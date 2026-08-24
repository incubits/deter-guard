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
	"strconv"
	"strings"
	"time"
)

// Time allowed for one upstream request. Package downloads can be slow and large; a build that hangs
// forever is worse than one that fails, so there is a ceiling.
const upstreamTimeout = 10 * time.Minute

type proxy struct {
	policy   *Policy
	ca       *certAuthority
	reporter *reporter
	// Upstream client. Verifies origin certificates against real roots (see roots.go): intercepting
	// the build's TLS must not mean accepting anything on the way out, or the proxy would downgrade
	// the security it exists to enforce.
	upstream *http.Transport
	verbose  bool
}

func newProxy(p *Policy, ca *certAuthority, r *reporter, verbose bool) *proxy {
	return &proxy{
		policy:   p,
		ca:       ca,
		reporter: r,
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

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// record sends a refusal to the console and, when asked, prints it. Allowed requests are never
// reported — see the reporter.
func (p *proxy) record(d Decision, host, method, path string) {
	if d.Allow {
		if p.verbose {
			logf("allow %s %s%s", method, host, path)
		}
		return
	}
	logf("DENY  %s %s%s — %s", method, host, path, d.Reason)
	if p.reporter != nil {
		p.reporter.note(d.Kind, host, method, path)
	}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	// Absolute-form request: a plain HTTP proxy request.
	host := hostOnly(r.Host)
	if host == "" {
		host = hostOnly(r.URL.Host)
	}
	d := p.policy.Check(host, r.Method, r.URL.Path)
	p.record(d, host, r.Method, r.URL.Path)
	if !d.Allow {
		p.writeRefusal(w, d, host)
		return
	}
	outURL := *r.URL
	outURL.Scheme = "http"
	if outURL.Host == "" {
		outURL.Host = r.Host
	}
	p.forward(w, r, outURL.String())
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

// refusalHeader carries the same facts as the body, for anything reading headers rather than parsing
// a body it did not expect.
func refusalHeader(d Decision, host string, version int64) http.Header {
	return http.Header{
		"Content-Type":           []string{"application/json"},
		"X-Deter-Decision":       []string{d.Kind},
		"X-Deter-Host":           []string{host},
		"X-Deter-Policy-Version": []string{fmt.Sprint(version)},
		// Nothing here is worth caching, and a cached 403 would outlive the policy edit that fixes it.
		"Cache-Control": []string{"no-store"},
	}
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
	host := hostOnly(authority)
	if req.Host != "" {
		host = hostOnly(req.Host)
	}
	// Deliberately not recorded again: handleConnect already logged and reported this refusal once,
	// at the tunnel. Counting it a second time per request would inflate every retry loop into the
	// console as if it were new information.
	_ = p.refusalResponse(d, host).Write(conn)
}

func (p *proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	d := p.policy.CheckTunnel(host)
	if !d.Allow {
		// Logged and reported HERE, once, while we still have the tunnel-level decision. What
		// follows serves 403s without recording them again, so a client's retry loop does not
		// arrive at the console as a stream of fresh refusals.
		p.record(d, host, "CONNECT", "")
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

	leaf, err := p.ca.leafFor(host)
	if err != nil {
		logf("could not mint a certificate for %s: %s", host, err)
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
		logf("TLS handshake with the build failed for %s (%s) — is the guard CA trusted?", host, err)
		return
	}
	defer tlsConn.Close()

	// Refused hosts get a real 403 inside the TLS session and nothing is dialled upstream. Doing it
	// here rather than at the CONNECT is the whole point: see the comment on refusalJSON.
	if !d.Allow {
		p.serveRefusals(tlsConn, r.Host, d)
		return
	}

	// The full authority, port included: the policy decides on the hostname, but the request has to
	// be re-issued to the actual port. Stripping it sends everything to :443, which is invisible
	// against a public registry and breaks any private one on another port.
	p.serveTunnel(tlsConn, r.Host)
}

// serveTunnel reads requests off a terminated TLS connection and decides each one.
func (p *proxy) serveTunnel(conn net.Conn, authority string) {
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return // client closed, or a malformed request; either way this connection is done
		}

		// A client's Host header wins when present — it is what the client believes it is talking to.
		target := authority
		if req.Host != "" {
			target = req.Host
		}
		reqHost := hostOnly(target)
		path := req.URL.Path
		d := p.policy.Check(reqHost, req.Method, path)
		p.record(d, reqHost, req.Method, path)

		if !d.Allow {
			// Written straight onto the connection, since there is no ResponseWriter in here.
			_ = p.refusalResponse(d, reqHost).Write(conn)
			return
		}

		res, err := p.roundTrip(req, "https://"+target+req.URL.RequestURI())
		if err != nil {
			body := fmt.Sprintf("egress proxy could not reach %s: %s\n", reqHost, err)
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
func (p *proxy) roundTrip(req *http.Request, target string) (*http.Response, error) {
	out, err := http.NewRequest(req.Method, target, req.Body)
	if err != nil {
		return nil, err
	}
	copyHeaders(out.Header, req.Header)
	out.Header.Del("Proxy-Connection")
	out.Header.Del("Proxy-Authorization")
	out.ContentLength = req.ContentLength
	return p.upstream.RoundTrip(out)
}

func (p *proxy) forward(w http.ResponseWriter, r *http.Request, target string) {
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
