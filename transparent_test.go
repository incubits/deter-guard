package main

// Tests for interception without a CONNECT: the destination has to come out of the traffic itself.
//
// The firewall rules that put traffic here are Linux-only and not exercised on a laptop, but they
// are also the boring half — they move packets. Everything that DECIDES is in here and is portable,
// so it is tested properly rather than left to a runner.
//
// Upstream DNS is simulated by overriding the proxy's dialer: whatever host the policy allows, the
// connection lands on the test origin. That is exactly what a resolver would do, and it lets a test
// name a realistic host rather than one that happens to resolve.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// transparentFixture wires a proxy whose upstream always lands on `origin`, and returns the address
// of its transparent TLS listener.
func transparentFixture(t *testing.T, p *Policy, origin *httptest.Server, mode Mode) (tlsAddr, httpAddr string, px *proxy) {
	t.Helper()

	ca, err := newCertAuthority()
	if err != nil {
		t.Fatal(err)
	}
	px = newProxy(p, ca, nil, mode, false)

	originRoot := x509.NewCertPool()
	originRoot.AddCert(origin.Certificate())
	px.upstream.TLSClientConfig = &tls.Config{RootCAs: originRoot}
	originAddr := strings.TrimPrefix(origin.URL, "https://")
	// Stand in for DNS: every upstream dial reaches the test origin, whatever host was asked for.
	px.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, originAddr)
	}

	tlsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := px.serveTransparent([]net.Listener{tlsLn}, []net.Listener{httpLn})
	t.Cleanup(stop)

	return tlsLn.Addr().String(), httpLn.Addr().String(), px
}

// clientTo dials the transparent listener directly, exactly as a redirected connection would arrive,
// and presents `sni` as the server name.
func clientTo(t *testing.T, addr, sni string, trust *x509.CertPool) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{RootCAs: trust, ServerName: sni},
		},
	}
}

func TestTransparentAllowsAPermittedHostByItsSNI(t *testing.T) {
	// No CONNECT anywhere in this test. The only statement of intent the client makes is the SNI,
	// and that has to be enough to identify, decide, and forward.
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "upstream reached")
	}))
	defer origin.Close()

	// example.com is what httptest's certificate is issued for, so the upstream leg verifies for real
	// rather than being skipped.
	p := &Policy{Version: 5, Rules: []Rule{{Host: "example.com"}}}
	tlsAddr, _, px := transparentFixture(t, p, origin, ModeEnforce)

	trust := x509.NewCertPool()
	trust.AppendCertsFromPEM(px.ca.caPEM())

	res, err := clientTo(t, tlsAddr, "example.com", trust).Get("https://example.com/pkg.tgz")
	if err != nil {
		t.Fatalf("a permitted host must go through: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != "upstream reached" {
		t.Fatalf("got %d %q, want 200 \"upstream reached\"", res.StatusCode, body)
	}
}

func TestTransparentRefusesAnUnlistedHostWithA403(t *testing.T) {
	// Same shape as the proxy-mode refusal, and for the same reason: a handshake failure here would
	// be a transport error, and transport errors get retried.
	var reached int
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
	}))
	defer origin.Close()

	p := &Policy{Version: 5, Rules: []Rule{{Host: "example.com"}}}
	tlsAddr, _, px := transparentFixture(t, p, origin, ModeEnforce)

	trust := x509.NewCertPool()
	trust.AppendCertsFromPEM(px.ca.caPEM())

	res, err := clientTo(t, tlsAddr, "telemetry.invalid", trust).Get("https://telemetry.invalid/beacon")
	if err != nil {
		t.Fatalf("a refusal must arrive as a response, not a broken connection: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.StatusCode)
	}
	if reached != 0 {
		t.Fatalf("the refused host was contacted %d time(s)", reached)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "telemetry.invalid") {
		t.Fatalf("refusal does not name the host: %s", body)
	}
}

func TestTransparentRefusesAConnectionWithNoSNI(t *testing.T) {
	// Without SNI there is nothing to decide on. Default deny has to cover "I cannot tell what this
	// is" as well as "I know, and no" — otherwise omitting the SNI is the way around the policy.
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	p := &Policy{Version: 5, Rules: []Rule{{Host: "example.com"}}}
	tlsAddr, _, _ := transparentFixture(t, p, origin, ModeEnforce)

	conn, err := net.Dial("tcp", tlsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// InsecureSkipVerify here is the SUBJECT of the test, not a shortcut in it. Go requires either
	// a ServerName or InsecureSkipVerify, so an empty ServerName is only reachable with it — and an
	// empty ServerName is precisely how a client sends no SNI. This builds the hostile client, then
	// asserts the guard turns it away. Nothing outside this function skips verification.
	c := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- see above
	if err := c.Handshake(); err == nil {
		t.Fatal("a TLS connection with no SNI completed its handshake; it must be refused, or " +
			"omitting the SNI is the way around the policy")
	}
}

func TestTransparentHTTPUsesTheHostHeader(t *testing.T) {
	// Port 80 traffic arrives origin-form — `GET /path` plus a Host header — because the client
	// believes it reached the origin. Reading the host from the request line, as the proxy path
	// does, would find nothing there.
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	p := &Policy{Version: 5, Rules: []Rule{{Host: "example.com"}}}
	_, httpAddr, _ := transparentFixture(t, p, origin, ModeEnforce)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, httpAddr)
			},
		},
	}

	res, err := client.Get("http://blocked.invalid/whatever")
	if err != nil {
		t.Fatalf("refusal must be a response: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an unlisted host over plain HTTP", res.StatusCode)
	}
	if got := res.Header.Get("X-Deter-Host"); got != "blocked.invalid" {
		t.Fatalf("X-Deter-Host = %q — the Host header is what identifies a redirected request", got)
	}
}

func TestCIControlPlaneHostsOnlyApplyOnActions(t *testing.T) {
	// This is a deliberate hole in default-deny, so it must not open anywhere it was not reasoned
	// about. Off the runner, it is empty.
	t.Setenv("GITHUB_ACTIONS", "")
	if got := ciControlPlaneHosts(); len(got) != 0 {
		t.Fatalf("expected no automatic permits outside Actions, got %v", got)
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	got := ciControlPlaneHosts()
	if len(got) == 0 {
		t.Fatal("on Actions the runner's own control plane must be permitted, or a policy mistake " +
			"stops the job reporting it")
	}
	// The runner cannot report anything without these two in particular.
	want := map[string]bool{"github.com": false, "*.actions.githubusercontent.com": false}
	for _, h := range got {
		if _, ok := want[h]; ok {
			want[h] = true
		}
	}
	for h, found := range want {
		if !found {
			t.Errorf("%s is not automatically permitted; the runner would go mute on a bad policy", h)
		}
	}
}
