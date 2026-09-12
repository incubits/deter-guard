package main

import (
	"bytes"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------------------------
// Embedded roots
// ---------------------------------------------------------------------------------------------

func TestEmbeddedRootsAreARealBundle(t *testing.T) {
	// The whole point of roots.pem is that a guard copied into an image with no CA store can still
	// complete its own TLS. A truncated or empty embed would restore exactly the failure it exists
	// to prevent — and it would fail as a 502 from the proxy, which reads as a network problem
	// rather than a missing file. So assert it is populated, not merely present.
	n := countPEM(embeddedRootsPEM)
	if n < 100 {
		t.Fatalf("embedded root bundle holds %d certificates, want >= 100 — is roots.pem truncated?", n)
	}
}

func TestEveryRootModeProducesAUsablePool(t *testing.T) {
	// "system" may legitimately return nil: on macOS and Windows a nil pool means "ask the platform
	// verifier", which is right. The other modes must always produce a pool, because a nil there
	// would silently mean something different from what the operator asked for.
	for _, mode := range []string{rootsBoth, rootsEmbedded, "nonsense-falls-back-to-both"} {
		if pool := buildRootPool(mode); pool == nil {
			t.Fatalf("buildRootPool(%q) = nil, want a pool", mode)
		}
	}
	// Must not panic; the value is platform-dependent.
	_ = buildRootPool(rootsSystem)
}

func TestEmbeddedModeIgnoresTheHostStore(t *testing.T) {
	// `embedded` exists so an organization can get a reproducible trust set that does not vary with
	// whatever base image the guard was dropped into. If it silently unioned the host store it would
	// not be reproducible, and the flag would be a lie.
	embedded := buildRootPool(rootsEmbedded)
	fresh := x509NewPoolFrom(t, embeddedRootsPEM)
	if !embedded.Equal(fresh) {
		t.Fatal("DETER_GUARD_ROOTS=embedded produced a pool that is not exactly roots.pem")
	}
}

// ---------------------------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------------------------

func TestIsLoopback(t *testing.T) {
	// Drives whether the operator gets the "anyone who can reach this port can use this proxy"
	// warning. A false positive here silences it on a bind that genuinely publishes a MITM proxy.
	for _, addr := range []string{"127.0.0.1", "::1", "localhost", "127.9.9.9"} {
		if !isLoopback(addr) {
			t.Errorf("isLoopback(%q) = false, want true", addr)
		}
	}
	for _, addr := range []string{"0.0.0.0", "10.0.0.5", "::", "192.168.1.20", ""} {
		if isLoopback(addr) {
			t.Errorf("isLoopback(%q) = true, want false — this bind would NOT be warned about", addr)
		}
	}
}

func TestStateRoundTrips(t *testing.T) {
	// `deter-guard env` with no arguments reads this back. If the two ever disagree, a build gets
	// pointed at a port nothing is listening on, which looks like the network is down.
	dir := t.TempDir()
	want := guardState{ProxyURL: "http://127.0.0.1:3128", CAPath: "/tmp/ca.pem", PID: 4242}
	if _, err := writeState(dir, want); err != nil {
		t.Fatalf("writeState: %v", err)
	}
	got, err := readState(dir)
	if err != nil {
		t.Fatalf("readState: %v", err)
	}
	if got != want {
		t.Fatalf("state round-trip = %+v, want %+v", got, want)
	}
}

func TestReadStateFailsWhenNoGuardIsRunning(t *testing.T) {
	// Must be an error, not a zero value: an empty proxy URL would have `env` emit
	// HTTPS_PROXY= and quietly turn enforcement off for every step that follows.
	if _, err := readState(t.TempDir()); err == nil {
		t.Fatal("readState on an empty dir returned no error — `env` would emit an empty proxy URL")
	}
}

func TestGuardServerListensAndKeepsOrRemovesItsCA(t *testing.T) {
	pol := &Policy{Version: 1, Rules: []Rule{{Host: "allowed.example.com"}}}

	// removeCA=true is the exec shape: nobody outside the process was told where the CA is.
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	g, err := startGuard(pol, nil, nil, ModeEnforce, "127.0.0.1", 0, caPath, true, false)
	if err != nil {
		t.Fatalf("startGuard: %v", err)
	}
	if _, err := os.Stat(caPath); err != nil {
		t.Fatalf("CA was not written to %s: %v", caPath, err)
	}
	// Port 0 must have become a real port, or the URL handed to a build is useless.
	if strings.HasSuffix(g.proxyURL, ":0") {
		t.Fatalf("proxyURL %q still says port 0", g.proxyURL)
	}
	// It must actually be accepting; startGuard returning before that is the race --detach exists
	// to close.
	conn, err := net.Dial("tcp", strings.TrimPrefix(g.proxyURL, "http://"))
	if err != nil {
		t.Fatalf("proxy is not accepting on %s: %v", g.proxyURL, err)
	}
	conn.Close()
	g.stop()
	if _, err := os.Stat(caPath); !os.IsNotExist(err) {
		t.Fatal("stop() left the CA behind even though removeCA was set")
	}

	// removeCA=false is the serve shape: the operator named the path, possibly mounted it, and
	// deleting it would break a container that is still running.
	dir2 := t.TempDir()
	caPath2 := filepath.Join(dir2, "ca.pem")
	g2, err := startGuard(pol, nil, nil, ModeEnforce, "127.0.0.1", 0, caPath2, false, false)
	if err != nil {
		t.Fatalf("startGuard: %v", err)
	}
	g2.stop()
	if _, err := os.Stat(caPath2); err != nil {
		t.Fatalf("stop() deleted a CA the operator asked for with --ca-out: %v", err)
	}
}

func TestServeRefusesContradictoryFlags(t *testing.T) {
	// Each of these would otherwise "work" in a way that silently does not enforce what the operator
	// meant — the worst failure mode for a security control.
	cases := []struct {
		name string
		o    opts
		argv []string
	}{
		{"--wrap with no command", opts{wrap: true}, nil},
		{"a command without --wrap", opts{}, []string{"echo", "hi"}},
		{"--detach and --wrap together", opts{detach: true, wrap: true}, []string{"sh"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := runServeCommand(c.o, c.argv); got != exitUsage {
				t.Fatalf("exit = %d, want %d (usage)", got, exitUsage)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// env
// ---------------------------------------------------------------------------------------------

func TestEnvEmitsEveryVariableInEveryFormat(t *testing.T) {
	// The reason this command exists is that integrators were going to copy the list by hand and
	// then not notice when it grew. A format that drops one would reintroduce exactly that bug, so
	// every format is checked against proxyEnv itself rather than against a second hard-coded list.
	vars := proxyEnv("http://127.0.0.1:3128", "/etc/deter/ca.pem")
	for _, format := range []string{"sh", "github", "docker", "json"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			if err := emitEnv(&buf, vars, format, false); err != nil {
				t.Fatalf("emitEnv: %v", err)
			}
			out := buf.String()
			for _, kv := range vars {
				k, v := splitVar(kv)
				if !strings.Contains(out, k) {
					t.Errorf("%s output is missing %s", format, k)
				}
				if !strings.Contains(out, v) {
					t.Errorf("%s output is missing the value for %s", format, k)
				}
			}
			if lines := strings.Count(strings.TrimSpace(out), "\n") + 1; format != "json" && lines != len(vars) {
				t.Errorf("%s emitted %d lines for %d variables", format, lines, len(vars))
			}
		})
	}
}

func TestEnvUnsetClearsEverythingItCanSet(t *testing.T) {
	// Asymmetry here strands a shell half-guarded: some variables cleared, some still pointing at a
	// proxy that has since exited, which fails as a connection refused deep inside a build.
	vars := proxyEnv("http://127.0.0.1:3128", "/etc/deter/ca.pem")
	for _, format := range []string{"sh", "github"} {
		var buf bytes.Buffer
		if err := emitEnv(&buf, vars, format, true); err != nil {
			t.Fatalf("emitEnv(%s, unset): %v", format, err)
		}
		for _, kv := range vars {
			k, _ := splitVar(kv)
			if !strings.Contains(buf.String(), k) {
				t.Errorf("%s --unset does not clear %s", format, k)
			}
		}
		if strings.Contains(buf.String(), "127.0.0.1:3128") {
			t.Errorf("%s --unset still mentions the proxy URL", format)
		}
	}
}

func TestDockerFormatRefusesUnset(t *testing.T) {
	// An ENV layer cannot clear a variable for a build; emitting something that looked like it did
	// would be worse than refusing.
	if err := emitEnv(&bytes.Buffer{}, proxyEnv("http://x", "/ca"), "docker", true); err == nil {
		t.Fatal("--format docker --unset was accepted, want an error")
	}
}

func TestUnknownFormatIsRefused(t *testing.T) {
	if err := emitEnv(&bytes.Buffer{}, proxyEnv("http://x", "/ca"), "yaml", false); err == nil {
		t.Fatal("an unknown --format was accepted; a typo would silently emit nothing")
	}
}

func TestShQuoteSurvivesAQuoteInThePath(t *testing.T) {
	// The output is designed to be eval'd. A single quote in a path (legal on Linux) would end the
	// quoting early and hand the rest of the path to the shell as code.
	got := shQuote("/tmp/it's here/ca.pem")
	want := `'/tmp/it'\''s here/ca.pem'`
	if got != want {
		t.Fatalf("shQuote = %s, want %s", got, want)
	}
}

func TestEnvRefusesANewlineInAValue(t *testing.T) {
	// $GITHUB_ENV is parsed line by line and is a privilege boundary between steps: a value carrying
	// a newline could append arbitrary further variables. Nothing we generate contains one, which is
	// precisely why this must be enforced rather than assumed.
	bad := []string{"HTTPS_PROXY=http://127.0.0.1:3128\nPATH=/evil"}
	if err := emitEnv(&bytes.Buffer{}, bad, "github", false); err == nil {
		t.Fatal("a value containing a newline was emitted into $GITHUB_ENV format")
	}
}

func TestGithubFormatIsExactlyKeyEqualsValue(t *testing.T) {
	// Actions does not accept `export`, quotes, or leading spaces — it would set a variable whose
	// value literally begins with a quote. Pin the shape.
	var buf bytes.Buffer
	if err := emitEnv(&buf, []string{"HTTPS_PROXY=http://127.0.0.1:3128"}, "github", false); err != nil {
		t.Fatalf("emitEnv: %v", err)
	}
	if got := buf.String(); got != "HTTPS_PROXY=http://127.0.0.1:3128\n" {
		t.Fatalf("github format = %q", got)
	}
}

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

func x509NewPoolFrom(t *testing.T, pemBytes []byte) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pemBytes) {
		t.Fatal("roots.pem did not parse")
	}
	return p
}
