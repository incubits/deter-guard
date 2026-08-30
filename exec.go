package main

// `deter-guard exec -- <command>`: run a build with the egress proxy in front of it.
//
// The proxy listens on loopback, the CA is written where the child can read it, and the environment
// points every tool we know about at both. Then the command runs and its exit code is passed through
// — a wrapper that swallowed a build failure would be worse than no wrapper.
//
// This is the CI shape: one command, an ephemeral port, and a CA that is deleted on the way out. For
// an image a customer already builds on — where the proxy has to outlive any one command and the
// address has to be something an ENV can name — see serve.go.
//
// What this does NOT do is make the proxy unavoidable. `HTTPS_PROXY` is a request, and a malicious
// postinstall can decline it. It is still the control that matters for the main threat, because it
// sits in the path where packages are FETCHED: a blocked package is never downloaded, so its install
// script never runs. Stopping code that is already running needs default-deny — see the README.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
)

// proxyEnv returns the variables that point a child process at the proxy and its CA.
//
// Every ecosystem reads its own variable, and missing one shows up as an inscrutable certificate
// error deep in a build rather than as a configuration problem. The list is the whole point of this
// function existing — and the reason `deter-guard env` exists rather than a README section telling
// integrators to copy fourteen lines into their own pipeline, where they would then go stale.
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
	mode     Mode
	verbose  bool
	argv     []string
}

// runExec starts the proxy, runs argv, and returns the child's exit code.
func runExec(o execOpts) (int, error) {
	if len(o.argv) == 0 {
		return exitUsage, errors.New("nothing to run: pass the command after --")
	}
	stateDir := o.stateDir
	if stateDir == "" {
		stateDir = os.TempDir()
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return exitUsage, fmt.Errorf("creating %s: %w", stateDir, err)
	}

	// Port 0: let the kernel choose, so two jobs on one runner never collide. The CA is ours to
	// delete afterwards — nobody outside this process was ever told where it is.
	g, err := startGuard(o.policy, o.reporter, o.mode, "127.0.0.1", 0,
		filepath.Join(stateDir, "deter-guard-ca.pem"), true, o.verbose)
	if err != nil {
		return exitUsage, err
	}
	// Shuts the proxy down first so nothing new is recorded, then flushes what was.
	defer g.stop()

	return runChild(o.argv, proxyEnv(g.proxyURL, g.caPath), nil)
}

// runChild execs the command, wiring through stdio and forwarding signals, and returns its exit code.
//
// cred, when set, is the identity to start the command as — see dropprivs.go. nil means "whoever we
// are", which is the right answer everywhere except transparent mode.
func runChild(argv []string, extraEnv []string, cred *dropCred) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	applyCredential(cmd, cred)

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

// resolvePolicy produces the policy the proxy will enforce, and the reporter to send refusals to.
//
// Shared by `exec` and `serve`, which must not differ on any of this. In particular the reporter is
// constructed in exactly one branch — the console one — so a local --policy file gets enforcement
// with no reporting, by construction rather than by omission. A policy nobody signed should not
// produce attributed telemetry.
//
// A local --policy file needs no console and no credential, which makes the proxy testable and works
// on an air-gapped runner. It is also unsigned, so it says so: a policy whose provenance nobody
// checked should never look the same as one that verified.
//
// The int is the exit code to use when err is non-nil, so callers do not have to re-derive whether a
// failure was configuration, authentication, or a signature that did not verify.
func resolvePolicy(o opts) (*Policy, *reporter, int, error) {
	if o.policyFile != "" {
		p, err := loadPolicyFile(o.policyFile)
		if err != nil {
			return nil, nil, exitUsage, err
		}
		logf("policy from %s (UNSIGNED — no console, nothing verified)", o.policyFile)
		warnIfPermitsNothing(p, o.mode)
		return p, nil, exitOK, nil
	}

	if o.consoleURL == "" {
		return nil, nil, exitUsage, errors.New(
			"no console URL — pass --console, set DETER_CONSOLE_URL, or use --policy <file>")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*httpTimeout)
	defer cancel()

	token, how, sessionKey, err := authenticate(ctx, o)
	if err != nil {
		return nil, nil, exitAuth, fmt.Errorf("authentication failed: %w", err)
	}

	headers := map[string]string{}
	if o.project != "" {
		headers["X-Deter-Project"] = o.project
	}
	if o.run != "" {
		headers["X-Deter-Run"] = o.run
	}

	// Pin order matches `policy`: an explicitly pinned key wins, then the key the session reported
	// at exchange time. Falling back to the key the policy response carries would be verifying a
	// message against a key from the same message.
	pinned := o.pubkey
	if pinned == "" {
		pinned = sessionKey
	}

	p, served, verified, err := fetchRules(ctx, o.consoleURL, token, pinned, headers)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.Status < 500 {
			return nil, nil, exitAuth, err
		}
		return nil, nil, exitUnverified, err
	}
	if verified {
		logf("policy version %d verified against pinned key %s (via %s)",
			p.Version, keyFingerprint(pinned), how)
	} else {
		logf("policy version %d verified against the key the CONSOLE SERVED (%s) — "+
			"pin --pubkey to make this a real check", p.Version, keyFingerprint(served))
	}

	warnIfPermitsNothing(p, o.mode)
	rep := newReporter(baseURL(o.consoleURL)+"/api/report/attempts", token, headers, o.mode)
	return p, rep, exitOK, nil
}

// warnIfPermitsNothing names the one policy that is valid, blocks everything, and looks like a bug.
//
// The only symptom otherwise is a build that fails at its first fetch, which reads as "the proxy is
// broken" rather than "the policy is empty".
func warnIfPermitsNothing(p *Policy, mode Mode) {
	if len(p.Rules) == 0 {
		if mode == ModeMonitor {
			errf("this policy permits NO hosts — every request would be refused under `--mode " +
				"enforce`. Nothing is blocked in monitor mode, so this run will list the lot")
			return
		}
		errf("this policy permits NO hosts — every request will be refused")
	}
}

// runExecCommand resolves a policy, then runs the build behind the proxy.
func runExecCommand(o opts, argv []string) int {
	if len(argv) == 0 {
		errf("nothing to run — put the command after `--`, e.g. exec -- npm ci")
		return exitUsage
	}

	pol, rep, code, err := resolvePolicy(o)
	if err != nil {
		errf("%s", err)
		return code
	}

	code, err = runExec(execOpts{
		policy:   pol,
		reporter: rep,
		stateDir: o.stateDir,
		mode:     o.mode,
		verbose:  o.verbose,
		argv:     argv,
	})
	if err != nil {
		errf("%s", err)
	}
	return code
}
