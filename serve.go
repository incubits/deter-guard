package main

// `deter-guard serve`: run the egress proxy as a process in its own right, rather than as something
// that exists only for the duration of one child command.
//
// `exec` was the whole product for a while, and it has a shape that stops working the moment a
// customer wants the guard in an image they already have. It couples three things that only need to
// be coupled in CI: the proxy's lifetime, one command's lifetime, and the delivery of the proxy's
// address to that command. An integrator who wants `pnpm install` and `pnpm build` guarded without
// writing `deter-guard exec --` in front of each, or who wants a container's shell session guarded,
// or who wants the guard as a sidecar, needs those three pulled apart.
//
// So serve does the same work and then stays up:
//
//	deter-guard serve                          block until SIGTERM; announce where to reach it
//	deter-guard serve --detach                 background it, wait until it is actually listening
//	deter-guard serve --wrap -- <command...>   run one command, but on a FIXED port and CA path
//
// --wrap looks redundant next to exec and is not. exec picks an ephemeral port and deletes its CA on
// exit, which is right for CI and wrong for an image: `docker exec` into a running container starts
// a process from the IMAGE's environment, not from PID 1's, so the only way to cover it is for the
// proxy's address and CA path to be values that could be baked into an ENV at build time. Fixed port
// and fixed CA path are exactly that. See the README's "Adding the guard to an image you already
// build" for the two-line result.
//
// What serve does NOT change is the honesty of the mechanism. HTTP(S)_PROXY is still a request the
// build may decline (see exec.go). Making it unavoidable needs the traffic redirected underneath the
// process rather than pointed at us by a variable, which is a different feature.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// The default proxy port. 3128 is the conventional forward-proxy port (Squid's), which makes it
// recognisable in a netstat and unlikely to collide with the application ports a build also uses —
// 8080 and 8000 collide constantly.
const defaultProxyPort = 3128

// detachedEnv marks the re-executed child of `--detach`, so it runs the server instead of forking
// again. An env var rather than a hidden flag: a hidden flag shows up in `ps` and invites being
// passed by hand.
const detachedEnv = "DETER_GUARD_DETACHED"

// stateFileName holds where the proxy is listening, so `deter-guard env` needs no arguments.
const stateFileName = "deter-guard.json"

// Ports the kernel redirects outbound 80 and 443 to in transparent mode. Two, because what arrives
// on 443 is a TLS record and what arrives on 80 is a request line.
const (
	defaultTransparentHTTPPort = 3129
	defaultTransparentTLSPort  = 3130
)

// ciControlPlaneHosts are permitted automatically in transparent mode.
//
// This is a deliberate hole in default-deny, and it buys the difference between a mistake you can
// read and one you cannot. Transparent mode intercepts EVERYTHING, including the CI runner's own
// traffic back to its control plane. A policy that does not list those hosts would not merely fail
// the build — it would stop the runner uploading logs, reporting status, or saying why. The job
// would die mute, and the guard would look like an outage rather than a policy.
//
// These are the runner's own channel, not the build's dependencies. They are logged at startup, so
// nobody has to read source to find out what was permitted on their behalf, and --no-ci-hosts turns
// them off for anyone who would rather have the failure.
func ciControlPlaneHosts() []string {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return []string{
			"github.com",
			"api.github.com",
			"*.actions.githubusercontent.com",
			"objects.githubusercontent.com",
			"*.blob.core.windows.net", // where Actions puts logs and artifacts
			"ghcr.io",
			"pkg-containers.githubusercontent.com",
		}
	}
	return nil
}

// guardState is what serve publishes and env reads back.
type guardState struct {
	ProxyURL string `json:"proxy_url"`
	CAPath   string `json:"ca_path"`
	PID      int    `json:"pid"`
}

// guardServer is a running proxy: the listener, the CA on disk, and the reporter that has to be
// flushed before the process goes away.
//
// exec and serve both drive this, so the two cannot drift apart on the details that matter —
// notably that the reporter is closed AFTER the proxy stops accepting, so a refusal in the last
// moment of a build is still reported.
type guardServer struct {
	proxyURL string
	caPath   string
	ca       *certAuthority
	px       *proxy
	srv      *http.Server
	reporter *reporter
	// removeCA is false when the operator named the path with --ca-out: a file they asked for is
	// theirs, and deleting it would break a container that mounted it.
	removeCA bool
	// cleanup is run in REVERSE on stop. Transparent mode installs a system CA and firewall rules,
	// and the order they come out in is not the order they went in: the redirect has to go before
	// the trust it depends on, or a build gets intercepted by a proxy it has stopped trusting.
	cleanup []func()
}

// startGuard generates a CA, writes it where the build can read it, and starts the proxy.
//
// addr of "" means loopback. port of 0 means "let the kernel choose", which is what exec wants and
// what makes two jobs on one runner safe.
func startGuard(pol *Policy, rep *reporter, addr string, port int, caPath string, removeCA, verbose bool) (*guardServer, error) {
	ca, err := newCertAuthority()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(caPath), 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", filepath.Dir(caPath), err)
	}
	// 0644: the build may well run as a different user than the guard that wrote it.
	if err := os.WriteFile(caPath, ca.caPEM(), 0o644); err != nil {
		return nil, fmt.Errorf("writing the CA to %s: %w", caPath, err)
	}

	if addr == "" {
		addr = "127.0.0.1"
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(addr, fmt.Sprint(port)))
	if err != nil {
		os.Remove(caPath)
		return nil, fmt.Errorf("opening the proxy port: %w", err)
	}

	// Binding anywhere but loopback publishes an intercepting proxy to the network. That is exactly
	// what the sidecar shape needs, and it is also an open relay for anyone who can reach the port:
	// there is no authentication on it, and it holds a CA the neighbours are being told to trust.
	// Allowed, because refusing it would rule out the only shape that actually contains a build —
	// but never silently.
	if !isLoopback(addr) {
		logf("WARNING: listening on %s, not loopback. Anything that can reach this port can use "+
			"this proxy and is covered by no authentication. Publish it to one container's network, "+
			"never to a shared one.", addr)
	}

	px := newProxy(pol, ca, rep, verbose)
	srv := &http.Server{Handler: px}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logf("proxy stopped: %s", err)
		}
	}()

	g := &guardServer{
		proxyURL: "http://" + net.JoinHostPort(addr, fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)),
		caPath:   caPath,
		ca:       ca,
		px:       px,
		srv:      srv,
		reporter: rep,
		removeCA: removeCA,
	}
	logf("egress proxy on %s · policy version %d · %d rule(s), %d block(s)",
		g.proxyURL, pol.Version, len(pol.Rules), len(pol.Blocked))
	return g, nil
}

// stop shuts the proxy down and flushes what it recorded.
//
// Order matters and is the reason this is not inlined at both call sites: stop accepting first so
// nothing new is recorded, then flush. A flush that raced new refusals would report a moving target.
func (g *guardServer) stop() {
	// Reverse order: whatever was installed last is removed first. In transparent mode that means
	// the firewall rules come out before the CA they made necessary — the other way round leaves a
	// window where traffic is still being intercepted by a proxy nothing trusts any more.
	for i := len(g.cleanup) - 1; i >= 0; i-- {
		g.cleanup[i]()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = g.srv.Shutdown(ctx)
	cancel()
	g.reporter.Close()
	if g.removeCA {
		os.Remove(g.caPath)
	}
}

// goTransparent puts the guard in front of traffic that was never told about it.
//
// Three things, and the order they are done in is the whole of the care required:
//
//  1. permit the CI control plane, so a mistake in steps 2 and 3 can still be reported;
//  2. install the CA, so intercepted TLS is trusted BEFORE anything is intercepted;
//  3. install the redirect, which is the step that actually starts intercepting.
//
// Reversed on the way out by g.cleanup.
func (g *guardServer) goTransparent(o opts, pol *Policy) error {
	if !transparentSupported() {
		return errNotLinux
	}

	if !o.noCIHosts {
		if hosts := ciControlPlaneHosts(); len(hosts) > 0 {
			for _, h := range hosts {
				pol.Rules = append(pol.Rules, Rule{Host: h, PathPrefixes: []string{"/"}})
			}
			logf("transparent mode also permits this runner's own control plane, so a policy "+
				"mistake cannot stop the job reporting one: %s", strings.Join(hosts, ", "))
			logf("(pass --no-ci-hosts to enforce the policy against those too)")
		}
	}

	httpPort, tlsPort := o.tHTTPPort, o.tTLSPort
	// REDIRECT rewrites the destination of locally generated packets to loopback, so that is where
	// the listeners belong. Binding wider would publish an intercepting proxy to the network.
	httpLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort))
	if err != nil {
		return fmt.Errorf("opening the transparent http port: %w", err)
	}
	tlsLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tlsPort))
	if err != nil {
		httpLn.Close()
		return fmt.Errorf("opening the transparent tls port: %w", err)
	}
	stopListeners := g.px.serveTransparent(tlsLn, httpLn)
	g.cleanup = append(g.cleanup, stopListeners)

	if o.installCA {
		undo, err := installSystemCA(g.ca.caPEM())
		if err != nil {
			return fmt.Errorf("installing the CA into the system trust store: %w", err)
		}
		g.cleanup = append(g.cleanup, undo)
	} else {
		logf("WARNING: --transparent without --install-ca. Anything that does not already trust %s "+
			"will fail its handshake rather than be filtered.", g.caPath)
	}

	if o.redirect {
		// Before installing the rules, not after: an unmarked upstream connection made in the
		// window between would be redirected into the guard itself.
		enableSocketMarking(g.px.upstream)
		var exempt []string
		if o.exempt != "" {
			exempt = strings.Split(o.exempt, ",")
		}
		if err := installRedirect(httpPort, tlsPort, exempt); err != nil {
			return fmt.Errorf("installing the redirect: %w", err)
		}
		g.cleanup = append(g.cleanup, func() {
			if err := removeRedirect(); err != nil {
				errf("could NOT remove the firewall rules — remove them by hand: %s", err)
			}
		})
	} else {
		logf("transparent listeners are up on :%d and :%d, but nothing is redirected to them. "+
			"Pass --redirect, or install the rules yourself.", httpPort, tlsPort)
	}

	return nil
}

func isLoopback(addr string) bool {
	if addr == "localhost" {
		return true
	}
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
}

// writeState publishes the address and CA path for `deter-guard env` to read.
func writeState(stateDir string, s guardState) (string, error) {
	path := filepath.Join(stateDir, stateFileName)
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

func readState(stateDir string) (guardState, error) {
	var s guardState
	b, err := os.ReadFile(filepath.Join(stateDir, stateFileName))
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

// runServeCommand resolves a policy and runs the proxy, in one of three shapes.
func runServeCommand(o opts, argv []string) int {
	if o.wrap && len(argv) == 0 {
		errf("--wrap needs a command — put it after `--`, e.g. serve --wrap -- bash")
		return exitUsage
	}
	if !o.wrap && len(argv) > 0 {
		errf("serve takes no command unless --wrap is given (got %q)", strings.Join(argv, " "))
		return exitUsage
	}
	if o.detach && o.wrap {
		errf("--detach and --wrap are mutually exclusive: one backgrounds the proxy, the other " +
			"keeps it in the foreground around a command")
		return exitUsage
	}

	stateDir := o.stateDir
	if stateDir == "" {
		stateDir = os.TempDir()
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		errf("creating %s: %s", stateDir, err)
		return exitUsage
	}

	if o.detach && os.Getenv(detachedEnv) == "" {
		return detach(o, stateDir)
	}

	caPath := o.caOut
	removeCA := false
	if caPath == "" {
		caPath = filepath.Join(stateDir, "deter-guard-ca.pem")
		// Only a path we invented is ours to delete. --wrap still cleans up after itself; a bare
		// serve leaves it, because whatever we handed the address to may still be running.
		removeCA = o.wrap
	}

	pol, rep, code, err := resolvePolicy(o)
	if err != nil {
		errf("%s", err)
		return code
	}

	g, err := startGuard(pol, rep, o.addr, o.port, caPath, removeCA, o.verbose)
	if err != nil {
		errf("%s", err)
		return exitUsage
	}

	if o.transparent {
		if err := g.goTransparent(o, pol); err != nil {
			// Everything installed so far comes back out. A half-configured interception is worse
			// than none: it is the state where traffic is redirected and nothing is filtering it.
			g.stop()
			errf("%s", err)
			return exitUsage
		}
	}

	statePath, err := writeState(stateDir, guardState{
		ProxyURL: g.proxyURL, CAPath: g.caPath, PID: os.Getpid(),
	})
	if err != nil {
		g.stop()
		errf("%s", err)
		return exitUsage
	}
	if !o.wrap {
		defer os.Remove(statePath)
	}

	// The CA is valid for 24 hours (ca.go). A CI job or a build never notices; a dev container left
	// running over a weekend would start failing handshakes with no obvious cause, so say when.
	logf("CA at %s, valid until %s", g.caPath, time.Now().Add(24*time.Hour).Format(time.RFC3339))

	if o.wrap {
		defer g.stop()
		code, err := runChild(argv, proxyEnv(g.proxyURL, g.caPath))
		if err != nil {
			errf("%s", err)
		}
		return code
	}

	if o.readyFile != "" {
		if err := os.WriteFile(o.readyFile, []byte(g.proxyURL+"\n"), 0o644); err != nil {
			g.stop()
			errf("writing the ready file %s: %s", o.readyFile, err)
			return exitUsage
		}
		defer os.Remove(o.readyFile)
	}

	logf("ready. Point a build at it with: eval \"$(deter-guard env --state-dir %s)\"", stateDir)

	// Wait for a signal, then shut down cleanly. This is the part the `exec -- sleep infinity`
	// workaround cannot do: killed without a handler, the reporter never flushes and the refusals
	// this proxy just recorded are lost — enforcement without the evidence for it.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigs
	logf("%s — shutting down", s)
	g.stop()
	return exitOK
}

// detach re-executes this binary as a background process and waits until it is actually listening.
//
// Returning before the proxy is up would be the whole bug this is meant to avoid: the next CI step
// exports HTTPS_PROXY and races a port that is not open yet. So the parent blocks on the state file
// the child writes, and fails loudly rather than leaving a half-configured job.
func detach(o opts, stateDir string) int {
	self, err := os.Executable()
	if err != nil {
		errf("finding this executable: %s", err)
		return exitUsage
	}

	logPath := filepath.Join(stateDir, "deter-guard.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		errf("opening %s: %s", logPath, err)
		return exitUsage
	}
	defer logFile.Close()

	// Drop --detach; keep everything else the caller passed.
	args := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		if a != "--detach" && a != "-detach" {
			args = append(args, a)
		}
	}

	cmd := exec.Command(self, args...)
	cmd.Env = append(os.Environ(), detachedEnv+"=1", "DETER_STATE_DIR="+stateDir)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Its own process group, so the shell that started it cannot take it down with a stray Ctrl-C
	// and, more to the point, so a CI step finishing does not reap it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		errf("starting the background guard: %s", err)
		return exitUsage
	}

	statePath := filepath.Join(stateDir, stateFileName)
	os.Remove(statePath)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := readState(stateDir); err == nil && st.ProxyURL != "" {
			logf("guard %d listening on %s (log: %s)", cmd.Process.Pid, st.ProxyURL, logPath)
			logf("point this shell at it with: eval \"$(deter-guard env --state-dir %s)\"", stateDir)
			// Do not Wait: the child outlives us on purpose.
			return exitOK
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	_ = cmd.Process.Kill()
	errf("the background guard did not come up within 30s; its log follows")
	if b, rerr := os.ReadFile(logPath); rerr == nil {
		fmt.Fprint(os.Stderr, string(b))
	}
	return exitUsage
}
