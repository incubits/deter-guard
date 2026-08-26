package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func active(b bool) *bool { return &b }

func npmPolicy() *Policy {
	return &Policy{
		Version: 3,
		Rules:   []Rule{{Host: "registry.npmjs.org"}},
		Blocked: []Block{{
			Host:      "registry.npmjs.org",
			PathGlobs: []string{"*/left-pad-1.3.0.tgz"},
			Reason:    "left-pad 1.3.0 is on your organization's blocklist",
		}},
	}
}

// The behaviour the whole product turns on: one package version is refused while the rest of the
// registry keeps working. A host allowlist cannot express this, which is why the decision has to see
// the path.
func TestBlocklistRefusesOneVersionNotTheHost(t *testing.T) {
	p := npmPolicy()

	if d := p.Check("registry.npmjs.org", "GET", "/left-pad"); !d.Allow {
		t.Fatalf("registry metadata must stay reachable, got %+v", d)
	}
	if d := p.Check("registry.npmjs.org", "GET", "/left-pad/-/left-pad-1.2.0.tgz"); !d.Allow {
		t.Fatalf("a different version must stay reachable, got %+v", d)
	}
	d := p.Check("registry.npmjs.org", "GET", "/left-pad/-/left-pad-1.3.0.tgz")
	if d.Allow {
		t.Fatal("the blocklisted version was allowed")
	}
	if d.Kind != "deny_blocklist" {
		t.Errorf("kind = %q, want deny_blocklist (it must be distinguishable from a policy miss)", d.Kind)
	}
	if !strings.Contains(d.Reason, "blocklist") {
		t.Errorf("reason %q does not tell the developer why their build failed", d.Reason)
	}
}

// A blocklist a permit could override would not be a blocklist.
func TestBlockBeatsAnExplicitPermit(t *testing.T) {
	p := &Policy{
		Rules:   []Rule{{Host: "evil.example.com", Active: active(true)}},
		Blocked: []Block{{Host: "evil.example.com"}},
	}
	if d := p.Check("evil.example.com", "GET", "/x"); d.Allow {
		t.Fatal("a block must win over a permit for the same host")
	}
	if d := p.CheckTunnel("evil.example.com"); d.Allow {
		t.Fatal("a whole-host block must refuse the tunnel, before any bytes flow")
	}
}

func TestDefaultDeny(t *testing.T) {
	p := &Policy{Rules: []Rule{{Host: "allowed.example.com"}}}
	if d := p.Check("other.example.com", "GET", "/"); d.Allow {
		t.Fatal("a host with no rule must be denied")
	}
	if d := (&Policy{}).Check("anything", "GET", "/"); d.Allow {
		t.Fatal("an empty policy must permit nothing")
	}
}

func TestHostWildcardDoesNotOpenTheApex(t *testing.T) {
	p := &Policy{Rules: []Rule{{Host: "*.example.com"}}}
	for _, h := range []string{"a.example.com", "a.b.example.com"} {
		if d := p.Check(h, "GET", "/"); !d.Allow {
			t.Errorf("%s should match *.example.com", h)
		}
	}
	// Widening surprises are the ones that matter: a subdomain rule must not also open the parent.
	if d := p.Check("example.com", "GET", "/"); d.Allow {
		t.Error("*.example.com must NOT match the bare apex example.com")
	}
	if d := p.Check("notexample.com", "GET", "/"); d.Allow {
		t.Error("*.example.com must not match a suffix that isn't a label boundary")
	}
}

func TestMethodAndPathNarrowing(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Host:         "api.example.com",
		Methods:      []string{"GET"},
		PathPrefixes: []string{"/v1/"},
	}}}
	if d := p.Check("api.example.com", "GET", "/v1/things"); !d.Allow {
		t.Error("in-scope request should be allowed")
	}
	if d := p.Check("api.example.com", "POST", "/v1/things"); d.Allow {
		t.Error("wrong method should be denied")
	}
	if d := p.Check("api.example.com", "GET", "/internal"); d.Allow {
		t.Error("out-of-scope path should be denied")
	}
	// The bug this design exists to avoid: a path-scoped rule must not deny the whole host at the
	// tunnel, because the tunnel has no path to judge yet.
	if d := p.CheckTunnel("api.example.com"); !d.Allow {
		t.Error("CONNECT must be allowed so the per-request check can do the real work")
	}
}

func TestInactiveRuleIsNotEnforcedButAbsentMeansActive(t *testing.T) {
	off := &Policy{Rules: []Rule{{Host: "h.example.com", Active: active(false)}}}
	if d := off.Check("h.example.com", "GET", "/"); d.Allow {
		t.Error("an inactive rule must not permit anything")
	}
	// A hand-written policy that omits `active` must still work, or it would permit nothing at all
	// while looking fine.
	absent := &Policy{Rules: []Rule{{Host: "h.example.com"}}}
	if d := absent.Check("h.example.com", "GET", "/"); !d.Allow {
		t.Error("an omitted `active` must mean active")
	}
}

func TestGlobCrossesSlashes(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		// The reason path.Match is not used: its `*` stops at `/`, and package paths have slashes.
		{"*/left-pad-1.3.0.tgz", "/left-pad/-/left-pad-1.3.0.tgz", true},
		{"*left-pad*", "/left-pad/-/left-pad-1.3.0.tgz", true},
		{"/a/*/c", "/a/b/c", true},
		{"/a/*/c", "/a/b/d", false},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		{"*", "anything", true},
		{"/pre*", "/prefix/thing", true},
		{"/pre*", "/nope", false},
	}
	for _, c := range cases {
		if got := globMatches(c.pattern, c.s); got != c.want {
			t.Errorf("globMatches(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

// --- the proxy, end to end -------------------------------------------------------------------

// proxyClient returns a client that goes through the proxy and trusts its CA, plus the running
// proxy's URL.
func startProxy(t *testing.T, p *Policy, originRoot *x509.CertPool) (*http.Client, func()) {
	t.Helper()
	ca, err := newCertAuthority()
	if err != nil {
		t.Fatal(err)
	}
	px := newProxy(p, ca, nil, false)
	if originRoot != nil {
		// The proxy verifies the ORIGIN against real roots in production; a test origin needs its
		// own. This is the only place that trust is relaxed, and only for the test's own server.
		px.upstream.TLSClientConfig = &tls.Config{RootCAs: originRoot}
	}
	srv := httptest.NewServer(px)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.caPEM()) {
		t.Fatal("the guard CA did not parse as PEM")
	}
	u, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	return client, srv.Close
}

func get(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	res, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	return res.StatusCode, string(b)
}

func TestProxyFiltersPlainHTTP(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("origin:" + r.URL.Path))
	}))
	defer origin.Close()
	host := strings.TrimPrefix(origin.URL, "http://")

	p := &Policy{
		Rules:   []Rule{{Host: mustHost(t, host)}},
		Blocked: []Block{{Host: mustHost(t, host), PathGlobs: []string{"*/blocked.tgz"}, Reason: "on the blocklist"}},
	}
	client, stop := startProxy(t, p, nil)
	defer stop()

	if code, body := get(t, client, origin.URL+"/fine"); code != 200 || !strings.Contains(body, "origin:/fine") {
		t.Errorf("allowed request: got %d %q", code, body)
	}
	code, body := get(t, client, origin.URL+"/pkg/blocked.tgz")
	if code != 403 {
		t.Errorf("blocked path: got %d, want 403", code)
	}
	if !strings.Contains(body, "on the blocklist") {
		t.Errorf("the 403 body must explain why, got %q", body)
	}
}

// The real test: HTTPS, so the path is only visible because the proxy terminates TLS.
func TestProxyBlocksOnePathOverHTTPS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tarball:" + r.URL.Path))
	}))
	defer origin.Close()

	originRoot := x509.NewCertPool()
	originRoot.AddCert(origin.Certificate())
	host := mustHost(t, strings.TrimPrefix(origin.URL, "https://"))

	p := &Policy{
		Rules: []Rule{{Host: host}},
		Blocked: []Block{{
			Host:      host,
			PathGlobs: []string{"*/left-pad-1.3.0.tgz"},
			Reason:    "left-pad 1.3.0 is on your organization's blocklist",
		}},
	}
	client, stop := startProxy(t, p, originRoot)
	defer stop()

	// Sibling version: allowed, and actually fetched through the intercepted tunnel.
	if code, body := get(t, client, origin.URL+"/left-pad/-/left-pad-1.2.0.tgz"); code != 200 ||
		!strings.Contains(body, "left-pad-1.2.0.tgz") {
		t.Errorf("1.2.0 should be fetched: got %d %q", code, body)
	}

	// Blocked version: refused inside the tunnel, with the reason.
	code, body := get(t, client, origin.URL+"/left-pad/-/left-pad-1.3.0.tgz")
	if code != 403 {
		t.Fatalf("1.3.0 should be refused: got %d %q", code, body)
	}
	if !strings.Contains(body, "blocklist") {
		t.Errorf("the refusal must say why, got %q", body)
	}
	if strings.Contains(body, "tarball:") {
		t.Error("the origin was reached anyway — the block did not stop the fetch")
	}
}

func TestProxyRefusesAnUnlistedHostWithARealStatus(t *testing.T) {
	// Two properties that pull in opposite directions, which is exactly why they are asserted
	// together. The refusal must arrive as an HTTP 403, because a client shown a broken tunnel
	// treats it as a transport failure and RETRIES a decision that can never change — eighteen
	// minutes of backoff against a host refused in the first millisecond. And the origin must never
	// be contacted, because answering politely must not mean connecting.
	var reached atomic.Int64
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.Write([]byte("should not be reachable"))
	}))
	defer origin.Close()
	originRoot := x509.NewCertPool()
	originRoot.AddCert(origin.Certificate())

	// Policy permits a different host entirely.
	p := &Policy{Version: 99, Rules: []Rule{{Host: "somewhere.else.example.com"}}}
	client, stop := startProxy(t, p, originRoot)
	defer stop()

	res, err := client.Get(origin.URL + "/anything")
	if err != nil {
		t.Fatalf("a refusal must be an HTTP response, not a transport error — package managers "+
			"retry transport errors and do not retry 4xx; got: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.StatusCode)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the refused origin was contacted %d time(s) — a refusal must not dial upstream", n)
	}

	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "egress_refused") {
		t.Fatalf("refusal body does not identify itself: %s", body)
	}
	// It must say which host and which policy, or the developer is guessing at exactly the moment
	// they need to act.
	if !strings.Contains(string(body), "127.0.0.1") {
		t.Fatalf("refusal body does not name the host: %s", body)
	}
	if got := res.Header.Get("X-Deter-Policy-Version"); got != "99" {
		t.Fatalf("X-Deter-Policy-Version = %q, want 99", got)
	}
	if got := res.Header.Get("X-Deter-Decision"); got != "deny_policy" {
		t.Fatalf("X-Deter-Decision = %q, want deny_policy", got)
	}
}

func TestARefusedHostIsReportedOncePerTunnelNotPerRetry(t *testing.T) {
	// The console shows blocked attempts. Now that a refused tunnel stays open and answers 403 to
	// whatever is asked, recording each of those answers would turn one client's retry loop into a
	// burst of distinct refusals — making a single misconfigured host look like an incident.
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	originRoot := x509.NewCertPool()
	originRoot.AddCert(origin.Certificate())

	ca, err := newCertAuthority()
	if err != nil {
		t.Fatal(err)
	}
	rep := &reporter{windows: map[windowKey]*window{}, stop: make(chan struct{}), done: make(chan struct{})}
	px := newProxy(&Policy{Version: 3, Rules: []Rule{{Host: "somewhere.else.example.com"}}}, ca, rep, false)
	px.upstream.TLSClientConfig = &tls.Config{RootCAs: originRoot}
	srv := httptest.NewServer(px)
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.caPEM())
	u, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{RootCAs: pool},
		// Force a fresh tunnel each time, which is the pessimistic case for double counting.
		DisableKeepAlives: true,
	}}

	for i := range 3 {
		res, err := client.Get(origin.URL + "/anything")
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		res.Body.Close()
	}

	rep.mu.Lock()
	defer rep.mu.Unlock()
	if len(rep.windows) != 1 {
		t.Fatalf("want one refusal window for one refused host, got %d", len(rep.windows))
	}
	for k, w := range rep.windows {
		if k.method != "CONNECT" {
			t.Errorf("recorded as %q, want CONNECT — the decision was made at the tunnel", k.method)
		}
		if w.count != 3 {
			t.Errorf("count = %d, want 3 collapsed into one window", w.count)
		}
	}
}

func TestReporterOnlySeesRefusals(t *testing.T) {
	r := &reporter{windows: map[windowKey]*window{}, stop: make(chan struct{}), done: make(chan struct{})}
	px := newProxy(&Policy{Rules: []Rule{{Host: "ok.example.com"}}}, nil, r, false)

	px.record(Decision{Allow: true, Kind: "allow"}, "ok.example.com", "GET", "/a")
	px.record(Decision{Kind: "deny_policy", Reason: "no"}, "bad.example.com", "GET", "/b")
	px.record(Decision{Kind: "deny_policy", Reason: "no"}, "bad.example.com", "GET", "/b")

	if len(r.windows) != 1 {
		t.Fatalf("want exactly one window (allows are never reported), got %d", len(r.windows))
	}
	for k, w := range r.windows {
		if k.host != "bad.example.com" {
			t.Errorf("reported the wrong host: %q", k.host)
		}
		if w.count != 2 {
			t.Errorf("two identical refusals must collapse to count=2, got %d", w.count)
		}
	}
}

func TestProxyEnvCoversEveryEcosystemTrustStore(t *testing.T) {
	env := proxyEnv("http://127.0.0.1:9999", "/tmp/ca.pem")
	joined := strings.Join(env, "\n")
	// Each of these is a real bug someone hits when it's missing: the build fails with a certificate
	// error from inside a package manager, which reads as a broken proxy rather than a missing var.
	for _, want := range []string{
		"HTTPS_PROXY=", "https_proxy=", "NO_PROXY=",
		"NODE_EXTRA_CA_CERTS=", "REQUESTS_CA_BUNDLE=", "PIP_CERT=",
		"CURL_CA_BUNDLE=", "GIT_SSL_CAINFO=", "SSL_CERT_FILE=", "CARGO_HTTP_CAINFO=",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("proxyEnv is missing %s", want)
		}
	}
	if !strings.Contains(joined, "NO_PROXY=localhost,127.0.0.1,::1") {
		t.Error("loopback must bypass the proxy, or the guard's own calls loop through itself")
	}
}
