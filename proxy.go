package main

// The egress proxy.
//
// Two decision points, and the split between them is the important part:
//
//   CONNECT host:port   gated on HOST only — a tunnel has no method or path yet
//   each request        gated on HOST + METHOD + PATH, after TLS is terminated
//
// Deciding only at the tunnel is what makes path rules unenforceable: `permit path /safe/*` has
// nothing to match at CONNECT time, so either the whole host is refused or the path rule does
// nothing. Both are wrong, and both are silent. So the tunnel opens when the host is plausibly
// reachable, and every request inside it is checked properly.
//
// The proxy is not the only thing between the build and the internet — see the README on default-deny.
// A proxy filters what is sent through it; it cannot filter what refuses to use it.

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Time allowed for one upstream request. Package downloads can be slow and large; a build that hangs
// forever is worse than one that fails, so there is a ceiling.
const upstreamTimeout = 10 * time.Minute

type proxy struct {
	policy *Policy
	// The SECOND artifact this proxy enforces, and nil is an ordinary value for it: no document
	// published, no console, or a pull that failed. Package blocking fails OPEN — see
	// supplychainpull.go for why it must, and why that is the opposite of the egress policy.
	supply   *supplyChain
	ca       *certAuthority
	reporter *reporter
	// Upstream client. Verifies origin certificates against real roots (see roots.go): intercepting
	// the build's TLS must not mean accepting anything on the way out, or the proxy would downgrade
	// the security it exists to enforce.
	upstream *http.Transport
	// What a refusal DOES — see mode.go. The decision above it is the same either way.
	mode    Mode
	verbose bool

	// The end-of-run tally, written from every connection the proxy is serving.
	mu             sync.Mutex
	refusals       map[refusalKey]*refusal
	order          []refusalKey
	allowed        int64
	observed       int64
	summaryDropped int64
}

func newProxy(p *Policy, sc *supplyChain, ca *certAuthority, r *reporter, mode Mode, verbose bool) *proxy {
	return &proxy{
		policy:   p,
		supply:   sc,
		ca:       ca,
		reporter: r,
		mode:     mode,
		refusals: map[refusalKey]*refusal{},
		upstream: &http.Transport{
			Proxy:                 nil, // never chain into another proxy by accident
			TLSClientConfig:       &tls.Config{RootCAs: rootCAs()},
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: upstreamTimeout,
			// HTTP/1.1 upstream, deliberately.
			//
			// Responses are relayed by writing them onto an HTTP/1.1 connection. An HTTP/2 response
			// has no HTTP/1.1 framing — no Content-Length, no chunked encoding, length is implied by
			// the stream — so relaying one produces a reply the client waits on forever. It shows up
			// as npm's "idle timeout reached", which reads like a network fault rather than a bug
			// here. A non-nil empty TLSNextProto is what actually disables h2; ForceAttemptHTTP2 on
			// its own does not.
			ForceAttemptHTTP2: false,
			TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
		verbose: verbose,
	}
}

// malformedHost is the refusal for an authority that is not a host — see canonical.go for why one
// is refused outright rather than cleaned up.
var malformedHost = Decision{
	Allow:     false,
	Kind:      "deny_policy",
	Reason:    "malformed host — not a hostname or IP address",
	Malformed: true,
}

// malformedPath is the refusal for a request target that cannot be decoded.
var malformedPath = Decision{
	Allow:     false,
	Kind:      "deny_policy",
	Reason:    "malformed request path — invalid percent-encoding",
	Malformed: true,
}

// record sends a refusal to the console and, when asked, prints it, then reports whether the
// request may PROCEED. Allowed requests are never reported — see the reporter.
//
// That return value is the whole of monitor mode at the call sites: each one refuses when this says
// no and continues when it says yes, so there is exactly one place where the two modes differ and no
// path can end up enforced in one mode and not the other by omission.
func (p *proxy) record(d Decision, host, method, path string) (proceed bool) {
	p.tally(d, host, method, path)
	if d.Allow {
		if p.verbose {
			logf("allow %s %s%s", method, host, path)
		}
		return true
	}
	// A request the guard could not identify is refused in BOTH modes. Monitor mode forwards what
	// enforce would have blocked, and there is no destination to forward this one to.
	observe := (p.mode == ModeMonitor || d.Observe) && !d.Malformed
	if observe {
		// A distinct word, because a build log full of DENY lines that denied nothing is how a
		// monitored job gets mistaken for a protected one. Which of the two reasons applies matters
		// to whoever reads it: one is how this RUN was invoked, the other is how the organization
		// configured that class of finding, and they are fixed in different places.
		why := "monitor mode: allowed through"
		if d.Observe && p.mode != ModeMonitor {
			why = "reported, not blocked"
		}
		logf("WOULD-DENY %s %s%s — %s (%s)", method, host, path, d.Reason, why)
	} else {
		logf("DENY  %s %s%s — %s", method, host, path, d.Reason)
	}
	if p.reporter != nil {
		p.reporter.note(d.Kind, host, method, path)
	}
	return observe
}

// checkSupply decides one request against the supply-chain blocklist, and reports whether it had
// anything to say at all.
//
// Placed AFTER the egress policy has permitted the request, which is the only order that makes
// sense: this asks "may this organization install this package", and a host it may not reach at all
// never gets that far. The broker makes the same call at the same point, for the additional reason
// that it injects credentials there — never into a request about to be denied.
//
// Only tarball fetches are decided. Metadata requests stay allowed or dependency resolution breaks
// before it ever reaches a blocked version, and a blocklist that also broke `npm view` is one an
// organization switches off by the end of the week.
func (p *proxy) checkSupply(host, path string) (Decision, bool) {
	if p.supply == nil {
		return Decision{}, false
	}
	if !p.supply.covers(host) {
		return Decision{}, false
	}
	// A blocklist the console stopped refreshing is a silently degraded control. Most organizations
	// keep last-known-good and accept that; one whose compliance posture cannot accept it sets
	// on_stale=block_registry, and then the registry closes rather than the blocklist rotting open.
	if p.supply.Posture.OnStale == scStaleBlock && p.supply.stale(time.Now()) {
		hit := &supplyHit{Reason: "stale", Block: true, BlocklistVersion: p.supply.Version,
			Detail: "the blocklist could not be refreshed and this organization refuses registry " +
				"access rather than install against a stale one"}
		return Decision{
			Allow: false, Kind: "deny_supply_chain", Supply: hit,
			Reason: "the supply-chain blocklist is stale — " + hit.Detail,
		}, true
	}
	pkg, ok := parseRegistryPath(path, p.supply.Posture.Prefixes)
	if !ok {
		return Decision{}, false
	}
	hit, ok := p.supply.decide(pkg)
	if !ok {
		return Decision{}, false
	}
	hit.BlocklistVersion = p.supply.Version
	kind := "monitor_supply_chain"
	if hit.Block {
		kind = "deny_supply_chain"
	}
	return Decision{
		Allow:   false,
		Kind:    kind,
		Reason:  hit.message(),
		Observe: !hit.Block,
		Supply:  &hit,
	}, true
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	// Absolute-form request: a plain HTTP proxy request.
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	host, port, ok := splitAuthority(authority)
	if !ok {
		p.record(malformedHost, authority, r.Method, r.URL.Path)
		p.writeRefusal(w, malformedHost, "")
		return
	}
	forward, match, ok := cleanPath(r.URL.EscapedPath())
	if !ok {
		p.record(malformedPath, host, r.Method, r.URL.EscapedPath())
		p.writeRefusal(w, malformedPath, host)
		return
	}
	d := p.policy.Check(host, r.Method, match)
	if !p.record(d, host, r.Method, match) {
		p.writeRefusal(w, d, host)
		return
	}
	if sd, ok := p.checkSupply(host, match); ok {
		if !p.record(sd, host, r.Method, match) {
			p.writeRefusal(w, sd, host)
			return
		}
	}
	p.forward(w, r, upstreamURL("http", host, port, forward, match, r.URL.RawQuery))
}

// A refusal has to arrive as an HTTP RESPONSE, not as a broken connection.
//
// This is the difference between a build that fails in one second and one that fails in eighteen
// minutes. Every package manager retries transport failures — that is what they are for — and none
// of them retry a 4xx. Refusing a CONNECT with 403 looks like a transport failure to the client:
// undici reports our refusal as
//
//	RequestAbortedError: Proxy response (403) !== 200 when HTTP Tunneling  (code UND_ERR_ABORTED)
//
// an abort, not a status. pnpm then backs off and retries a decision that was final before it was
// made, and the developer sees a hang rather than a policy. Consumers were working around this by
// turning retries off in their own pipelines, which is a defect of ours leaking into their config.
//
// So a refused host gets its tunnel accepted and its TLS terminated, and every request inside it is
// answered 403 — while nothing is ever sent upstream. The refusal is exactly as complete; only its
// shape changes, from "the connection broke" to "the server said no".
const refusalFix = "permit this host in the deter console, under your organization's egress policy"

func refusalJSON(d Decision, host string, version int64) []byte {
	if d.Supply != nil {
		return supplyRefusalJSON(d, host, version)
	}
	// Hand-built rather than encoding/json: this has to be writable onto a raw net.Conn in the
	// tunnel path, and the shape is fixed. Values are quoted through strconv so a hostile Host
	// header cannot break out of the document.
	return fmt.Appendf(nil, `{
  "error": "egress_refused",
  "decision": %s,
  "host": %s,
  "reason": %s,
  "policy_version": %d,
  "fix": %s
}
`, strconv.Quote(d.Kind), strconv.Quote(host), strconv.Quote(d.Reason), version, strconv.Quote(refusalFix))
}

// supplyRefusalJSON is the body for a package the blocklist refused, and it is the entire UX of that
// feature.
//
// This is what a developer reads in `npm install` output at the moment their build stops, so it has
// to answer all four questions at once: what was refused, why, on whose authority, and what to do
// next. A refusal that names none of those gets worked around — a pinned old version, a registry
// mirror, `--ignore-scripts`, an argument with the platform team — and the control is then off in
// practice while still reporting itself as on.
func supplyRefusalJSON(d Decision, host string, policyVersion int64) []byte {
	h := d.Supply
	fix := "ask an admin to add an exception under Supply chain in the deter console, if this package " +
		"is genuinely needed"
	if h.FixedIn != "" {
		fix = "upgrade to " + h.FixedIn + " — or, if that is not possible yet, ask an admin for an " +
			"exception under Supply chain in the deter console"
	}
	return fmt.Appendf(nil, `{
  "error": "package_blocked",
  "decision": %s,
  "host": %s,
  "reason": %s,
  "package": %s,
  "package_version": %s,
  "advisory": %s,
  "severity": %s,
  "fixed_in": %s,
  "kev": %t,
  "blocked_because": %s,
  "policy_version": %d,
  "blocklist_version": %d,
  "fix": %s
}
`, strconv.Quote(d.Kind), strconv.Quote(host), strconv.Quote(d.Reason),
		strconv.Quote(h.Package), strconv.Quote(h.Version), strconv.Quote(h.Advisory),
		strconv.Quote(h.Severity), strconv.Quote(h.FixedIn), h.KEV, strconv.Quote(h.Reason),
		policyVersion, h.BlocklistVersion, strconv.Quote(fix))
}

// refusalHeader carries the same facts as the body, for anything reading headers rather than parsing
// a body it did not expect.
func refusalHeader(d Decision, host string, version int64) http.Header {
	hdr := http.Header{
		"Content-Type":           []string{"application/json"},
		"X-Deter-Decision":       []string{d.Kind},
		"X-Deter-Host":           []string{host},
		"X-Deter-Policy-Version": []string{fmt.Sprint(version)},
		// Nothing here is worth caching, and a cached 403 would outlive the policy edit that fixes it.
		"Cache-Control": []string{"no-store"},
	}
	// The same facts as the body, for a package manager or a log scraper that reads headers rather
	// than parsing a body it did not expect to be JSON.
	if s := d.Supply; s != nil {
		if s.Package != "" {
			hdr.Set("X-Deter-Package", s.Package+"@"+s.Version)
		}
		if s.Advisory != "" {
			hdr.Set("X-Deter-Advisory", s.Advisory)
		}
		if s.FixedIn != "" {
			hdr.Set("X-Deter-Fixed-In", s.FixedIn)
		}
		hdr.Set("X-Deter-Blocklist-Version", fmt.Sprint(s.BlocklistVersion))
	}
	return hdr
}

// writeRefusal answers on a ResponseWriter — the plain-HTTP proxy path.
func (p *proxy) writeRefusal(w http.ResponseWriter, d Decision, host string) {
	body := refusalJSON(d, host, p.policy.Version)
	for k, v := range refusalHeader(d, host, p.policy.Version) {
		w.Header()[k] = v
	}
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(body)
}

// refusalResponse builds the same answer for the paths that write onto a raw connection, where there
// is no ResponseWriter.
func (p *proxy) refusalResponse(d Decision, host string) *http.Response {
	body := refusalJSON(d, host, p.policy.Version)
	return &http.Response{
		StatusCode:    http.StatusForbidden,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        refusalHeader(d, host, p.policy.Version),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		// Close after a refusal: a client that pipelines more requests onto a connection it was just
		// told no on is not a case worth being clever about.
		Close: true,
	}
}

// serveRefusals terminates TLS for a host the policy refused and answers 403 to whatever is asked.
//
// Nothing is dialled upstream from here — the connection to the refused host is never made. The only
// work done on its behalf is minting a certificate so the client can be told, in a language it
// already understands, that the answer is no.
func (p *proxy) serveRefusals(conn net.Conn, authority string, d Decision) {
	// A dead-end connection should not be able to occupy us indefinitely: a client that completes
	// the handshake and then says nothing gets dropped rather than parked.
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	host := authority
	if h, _, ok := splitAuthority(authority); ok {
		host = h
	}
	if req.Host != "" {
		if h, _, ok := splitAuthority(req.Host); ok {
			host = h
		}
	}
	// Deliberately not recorded again: handleConnect already logged and reported this refusal once,
	// at the tunnel. Counting it a second time per request would inflate every retry loop into the
	// console as if it were new information.
	_ = p.refusalResponse(d, host).Write(conn)
}

func (p *proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, valid := splitAuthority(r.Host)
	d := malformedHost
	if valid {
		d = p.policy.CheckTunnel(host)
	}
	proceed := d.Allow
	if !d.Allow {
		// Logged and reported HERE, once, while we still have the tunnel-level decision. What
		// follows serves 403s without recording them again, so a client's retry loop does not
		// arrive at the console as a stream of fresh refusals.
		//
		// In monitor mode this opens a tunnel to a host the policy does not permit, deliberately:
		// the requests inside it are then decided and reported one by one, so the run produces the
		// PATHS the policy will have to name rather than only the host. Enforce refuses at the
		// tunnel and never learns them, which is correct there and useless here.
		proceed = p.record(d, r.Host, "CONNECT", "")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy cannot hijack", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// A refused connection still gets a certificate, because the refusal has to be delivered as a
	// 403 inside the TLS session rather than as a broken pipe. An unparseable authority has no name
	// to put in one, so it borrows the CA's — the client is about to be told no regardless, and the
	// only thing that must not happen is minting a leaf for attacker-chosen bytes.
	certName := host
	if !valid {
		certName = "invalid.deter-guard"
	}
	leaf, err := p.ca.leafFor(certName)
	if err != nil {
		logf("could not mint a certificate for %s: %s", certName, err)
		return
	}
	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		// Advertise ONLY http/1.1. serveTunnel speaks HTTP/1.1 and nothing else, so a client that
		// negotiated h2 over ALPN would send frames into a parser expecting request lines, and the
		// connection would hang rather than fail.
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		// Almost always the client not trusting our CA. Say so plainly — this is the single most
		// common way a working setup looks broken.
		logf("TLS handshake with the build failed for %s (%s) — is the guard CA trusted?", certName, err)
		return
	}
	defer tlsConn.Close()

	// Refused hosts get a real 403 inside the TLS session and nothing is dialled upstream. Doing it
	// here rather than at the CONNECT is the whole point: see the comment on refusalJSON.
	if !proceed {
		p.serveRefusals(tlsConn, r.Host, d)
		return
	}

	// Host AND port travel separately from here: the policy decides on the hostname, but the request
	// has to be re-issued to the actual port. Losing it sends everything to :443, which is invisible
	// against a public registry and breaks any private one on another port.
	p.serveTunnel(tlsConn, host, port)
}

// serveTunnel reads requests off a terminated TLS connection and decides each one.
func (p *proxy) serveTunnel(conn net.Conn, tunnelHost, tunnelPort string) {
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return // client closed, or a malformed request; either way this connection is done
		}

		// A client's Host header wins when present — it is what the client believes it is talking
		// to, and it is re-checked against the policy below, so naming a different host is allowed
		// but never free. It is also entirely attacker-controlled, which is why it is PARSED rather
		// than pasted into a URL: this is the exact spot where `evil.com#.example.com` used to
		// satisfy a `*.example.com` rule and then resolve to evil.com.
		host, port := tunnelHost, tunnelPort
		if req.Host != "" {
			h, prt, ok := splitAuthority(req.Host)
			if !ok {
				p.record(malformedHost, req.Host, req.Method, req.URL.EscapedPath())
				_ = p.refusalResponse(malformedHost, "").Write(conn)
				return
			}
			host = h
			// A Host header carries no port in the ordinary case, and that must not silently move
			// the request to :443 — the tunnel was opened to a specific port and that is where it
			// goes unless the client says otherwise.
			if prt != "" {
				port = prt
			}
		}

		forward, match, ok := cleanPath(req.URL.EscapedPath())
		if !ok {
			p.record(malformedPath, host, req.Method, req.URL.EscapedPath())
			_ = p.refusalResponse(malformedPath, host).Write(conn)
			return
		}

		d := p.policy.Check(host, req.Method, match)
		if !p.record(d, host, req.Method, match) {
			// Written straight onto the connection, since there is no ResponseWriter in here.
			_ = p.refusalResponse(d, host).Write(conn)
			return
		}

		// This is the request the whole feature exists for: TLS is terminated, so the exact tarball
		// URL is visible, which is what lets `registry.npmjs.org` stay reachable while one
		// compromised release of one package does not.
		if sd, ok := p.checkSupply(host, match); ok {
			if !p.record(sd, host, req.Method, match) {
				_ = p.refusalResponse(sd, host).Write(conn)
				return
			}
		}

		res, err := p.roundTrip(req, upstreamURL("https", host, port, forward, match, req.URL.RawQuery))
		if err != nil {
			body := fmt.Sprintf("egress proxy could not reach %s: %s\n", host, err)
			res = &http.Response{
				StatusCode:    http.StatusBadGateway,
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
				Body:          io.NopCloser(strings.NewReader(body)),
				ContentLength: int64(len(body)),
				Close:         true,
			}
			_ = res.Write(conn)
			return
		}
		shouldClose := res.Close || req.Close
		// Response.Write emits the status line from these fields, so a response that arrived as
		// anything other than 1.1 must be relabelled before it goes onto a 1.1 connection.
		res.Proto, res.ProtoMajor, res.ProtoMinor = "HTTP/1.1", 1, 1
		if err := res.Write(conn); err != nil {
			res.Body.Close()
			return
		}
		res.Body.Close()
		if shouldClose {
			return
		}
	}
}

// roundTrip re-issues one request upstream. The inbound request cannot be reused directly: it
// carries an origin-form URL and hop-by-hop headers that must not be forwarded.
//
// Takes a built *url.URL rather than a string on purpose. A target assembled from validated parts
// cannot be re-read as a different address by the next parser to touch it, and there is no next
// parser here — the URL goes onto the request as-is.
func (p *proxy) roundTrip(req *http.Request, target *url.URL) (*http.Response, error) {
	out, err := http.NewRequest(req.Method, "", req.Body)
	if err != nil {
		return nil, err
	}
	out.URL = target
	out.Host = target.Host
	copyHeaders(out.Header, req.Header)
	out.Header.Del("Proxy-Connection")
	out.Header.Del("Proxy-Authorization")
	out.ContentLength = req.ContentLength
	return p.upstream.RoundTrip(out)
}

func (p *proxy) forward(w http.ResponseWriter, r *http.Request, target *url.URL) {
	res, err := p.roundTrip(r, target)
	if err != nil {
		http.Error(w, "egress proxy could not reach the origin: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	copyHeaders(w.Header(), res.Header)
	w.WriteHeader(res.StatusCode)
	_, _ = io.Copy(w, res.Body)
}

// hopByHop headers belong to one connection and must not be relayed (RFC 9110 §7.6.1).
var hopByHop = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHop[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
