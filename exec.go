package main

// `deter-guard exec -- <command>`: run a build with the egress proxy in front of it.
//
// The proxy listens on loopback, the CA is written where the child can read it, and the environment
// points every tool we know about at both. Then the command runs and its exit code is passed through
// — a wrapper that swallowed a build failure would be worse than no wrapper.
//
// What this does NOT do is make the proxy unavoidable. `HTTPS_PROXY` is a request, and a malicious
// postinstall can decline it. It is still the control that matters for the main threat, because it
// sits in the path where packages are FETCHED: a blocked package is never downloaded, so its install
// script never runs. Stopping code that is already running needs default-deny — see the README.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// proxyEnv returns the variables that point a child process at the proxy and its CA.
//
// Every ecosystem reads its own variable, and missing one shows up as an inscrutable certificate
// error deep in a build rather than as a configuration problem. The list is the whole point of this
// function existing.
func proxyEnv(proxyURL, caPath string) []string {
	noProxy := "localhost,127.0.0.1,::1"
	return []string{
		"HTTP_PROXY=" + proxyURL,
		"HTTPS_PROXY=" + proxyURL,
		// Lowercase too: curl and much of libc-land read these, some tools read only one case.
		"http_proxy=" + proxyURL,
		"https_proxy=" + proxyURL,
		"NO_PROXY=" + noProxy,
		"no_proxy=" + noProxy,

		// Trust stores, per ecosystem.
		"NODE_EXTRA_CA_CERTS=" + caPath, // node, npm, pnpm, yarn
		"REQUESTS_CA_BUNDLE=" + caPath,  // python requests
		"PIP_CERT=" + caPath,            // pip
		"CURL_CA_BUNDLE=" + caPath,      // curl
		"GIT_SSL_CAINFO=" + caPath,      // git
		"SSL_CERT_FILE=" + caPath,       // openssl, go, ruby, rust
		"CARGO_HTTP_CAINFO=" + caPath,   // cargo
		"DETER_GUARD_CA=" + caPath,      // for anything the build wants to wire up itself
	}
}

type execOpts struct {
	policy   *Policy
	reporter *reporter
	// Directory to write the CA into. Must be readable by the child.
	stateDir string
	verbose  bool
	argv     []string
}

// runExec starts the proxy, runs argv, and returns the child's exit code.
func runExec(o execOpts) (int, error) {
	if len(o.argv) == 0 {
		return exitUsage, errors.New("nothing to run: pass the command after --")
	}

	ca, err := newCertAuthority()
	if err != nil {
		return exitUsage, err
	}
	if o.stateDir == "" {
		o.stateDir = os.TempDir()
	}
	if err := os.MkdirAll(o.stateDir, 0o755); err != nil {
		return exitUsage, fmt.Errorf("creating %s: %w", o.stateDir, err)
	}
	caPath := filepath.Join(o.stateDir, "deter-guard-ca.pem")
	// 0644: the child may well run as a different user than the warden that wrote it.
	if err := os.WriteFile(caPath, ca.caPEM(), 0o644); err != nil {
		return exitUsage, fmt.Errorf("writing the CA to %s: %w", caPath, err)
	}
	defer os.Remove(caPath)

	// Port 0: let the kernel choose, so two jobs on one runner never collide.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return exitUsage, fmt.Errorf("opening the proxy port: %w", err)
	}
	proxyURL := "http://" + ln.Addr().String()

	px := newProxy(o.policy, ca, o.reporter, o.verbose)
	srv := &http.Server{Handler: px}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logf("proxy stopped: %s", err)
		}
	}()

	logf("egress proxy on %s · policy version %d · %d rule(s), %d block(s)",
		proxyURL, o.policy.Version, len(o.policy.Rules), len(o.policy.Blocked))

	code, runErr := runChild(o.argv, proxyEnv(proxyURL, caPath))

	// Shut the proxy first so nothing new is recorded, then flush what was.
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = srv.Shutdown(shutCtx)
	cancel()
	o.reporter.Close()

	return code, runErr
}

// runChild execs the command, wiring through stdio and forwarding signals, and returns its exit code.
func runChild(argv []string, extraEnv []string) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return exitUsage, fmt.Errorf("could not start %s: %w", argv[0], err)
	}

	// Forward the signals a CI runner sends when it cancels a job, so the build gets the chance to
	// clean up rather than being orphaned when we exit.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		for s := range sigs {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(s)
			}
		}
	}()

	err := cmd.Wait()
	if err == nil {
		return exitOK, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		// The build's own exit code, passed straight through.
		return ee.ExitCode(), nil
	}
	return exitUsage, err
}

// runExecCommand resolves a policy, then runs the build behind the proxy.
//
// A local --policy file needs no console and no credential, which makes the proxy testable and works
// on an air-gapped runner. It is also unsigned, so it says so: a policy whose provenance nobody
// checked should never look the same as one that verified.
func runExecCommand(o opts, argv []string) int {
	if len(argv) == 0 {
		errf("nothing to run — put the command after `--`, e.g. exec -- npm ci")
		return exitUsage
	}

	var pol *Policy
	var rep *reporter

	if o.policyFile != "" {
		p, err := loadPolicyFile(o.policyFile)
		if err != nil {
			errf("%s", err)
			return exitUsage
		}
		pol = p
		logf("policy from %s (UNSIGNED — no console, nothing verified)", o.policyFile)
	} else {
		if o.consoleURL == "" {
			errf("no console URL — pass --console, set DETER_CONSOLE_URL, or use --policy <file>")
			return exitUsage
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*httpTimeout)
		token, how, sessionKey, err := authenticate(ctx, o)
		if err != nil {
			cancel()
			errf("authentication failed: %s", err)
			return exitAuth
		}

		headers := map[string]string{}
		if o.project != "" {
			headers["X-Deter-Project"] = o.project
		}
		if o.run != "" {
			headers["X-Deter-Run"] = o.run
		}

		// Pin order matches `policy`: an explicitly pinned key wins, then the key the session
		// reported at exchange time. Falling back to the key the policy response carries would be
		// verifying a message against a key from the same message.
		pinned := o.pubkey
		if pinned == "" {
			pinned = sessionKey
		}

		p, served, verified, err := fetchRules(ctx, o.consoleURL, token, pinned, headers)
		cancel()
		if err != nil {
			errf("%s", err)
			var ae *apiError
			if errors.As(err, &ae) && ae.Status < 500 {
				return exitAuth
			}
			return exitUnverified
		}
		pol = p
		if verified {
			logf("policy version %d verified against pinned key %s (via %s)",
				p.Version, keyFingerprint(pinned), how)
		} else {
			logf("policy version %d verified against the key the CONSOLE SERVED (%s) — "+
				"pin --pubkey to make this a real check", p.Version, keyFingerprint(served))
		}

		rep = newReporter(baseURL(o.consoleURL)+"/api/report/attempts", token, headers)
	}

	if len(pol.Rules) == 0 {
		// A policy permitting nothing is valid and blocks everything. The only symptom is a build
		// that fails at its first fetch, which reads as "the proxy is broken".
		errf("this policy permits NO hosts — every request will be refused")
	}

	code, err := runExec(execOpts{
		policy:   pol,
		reporter: rep,
		stateDir: o.stateDir,
		verbose:  o.verbose,
		argv:     argv,
	})
	if err != nil {
		errf("%s", err)
	}
	return code
}
