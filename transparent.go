package main

// Transparent interception: filtering traffic that was never told about a proxy.
//
// Everything else in this program is pointed at by an environment variable, and an environment
// variable is a REQUEST. `HTTPS_PROXY` works because npm, pip, curl and git choose to honour it; a
// package's install script that opens its own socket simply does not, and neither does any runtime
// that has its own opinion — Node's built-in fetch ignores the proxy variables entirely unless
// NODE_USE_ENV_PROXY is set, which is how corepack was observed downloading a package manager from a
// host that was refused one second later.
//
// Each of those is a hole discovered in production, one ecosystem at a time. Transparent mode ends
// the category rather than the instances: the kernel redirects outbound 80 and 443 to us before
// anything gets a say, so there is no variable to ignore and nothing to opt out of.
//
// What arrives here is a connection with no CONNECT and no absolute-form URL — the client believes
// it is talking to the origin. So the destination has to be recovered from the traffic itself:
//
//	:443  the TLS ClientHello's SNI
//	:80   the Host header
//
// Note this is read from what the CLIENT SAYS, not from the packet's real destination. That is fine
// for policy — a client that lies about its SNI to reach a permitted host gets a certificate for the
// host it named and a TLS session it cannot use, since we then connect to the host it named too.
// It does mean a connection with no SNI cannot be identified at all, and is refused: default deny
// applies to "I cannot tell what this is" exactly as it applies to "I know and it is not allowed".

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"
)

// How long a client gets to complete a handshake before we stop holding the connection open. A
// redirected port is reachable by anything on the box, so an idle connection must not be free.
const transparentHandshakeTimeout = 30 * time.Second

// Defined here rather than in redirect_other.go because serve.go refers to it on every platform:
// the branch is dead on Linux, but dead code still has to compile.
var errNotLinux = errors.New("transparent mode needs Linux: it redirects packets with iptables and " +
	"marks its own sockets with SO_MARK, neither of which exists here. Use `serve` with the proxy " +
	"environment variables instead")

// serveTransparentTLS handles one connection redirected from port 443.
func (p *proxy) serveTransparentTLS(conn net.Conn) {
	defer conn.Close()

	// Captured by the callback below. GetCertificate is how the SNI reaches us: Go has already
	// parsed the ClientHello by the time it is called, so there is no hand-rolled wire parsing here
	// — which is the correct amount of hand-rolled wire parsing to have in a security control.
	var sni string
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Advertise only http/1.1: serveTunnel speaks HTTP/1.1 and nothing else, so a client that
		// negotiated h2 would send frames into a parser expecting request lines and hang.
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni = hello.ServerName
			if sni == "" {
				return nil, errors.New("no SNI: cannot tell which host this connection is for")
			}
			// A certificate is minted before the policy is consulted, deliberately. Refusing at the
			// handshake would give the client a TLS error — a transport failure, the exact shape
			// that makes package managers retry. The refusal is delivered as a 403 below instead.
			return p.ca.leafFor(sni)
		},
	}

	_ = conn.SetDeadline(time.Now().Add(transparentHandshakeTimeout))
	tlsConn := tls.Server(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		if sni == "" {
			logf("DENY  TLS connection with no SNI — cannot identify the host, so it is refused")
			p.record(Decision{Kind: "deny_policy", Reason: "no SNI"}, "<no SNI>", "CONNECT", "")
		} else {
			logf("TLS handshake with the build failed for %s (%s) — is the guard CA trusted?", sni, err)
		}
		return
	}
	// The handshake is done; the build's own request may legitimately take a long time.
	_ = tlsConn.SetDeadline(time.Time{})
	defer tlsConn.Close()

	if d := p.policy.CheckTunnel(sni); !d.Allow {
		p.record(d, sni, "CONNECT", "")
		p.serveRefusals(tlsConn, sni, d)
		return
	}

	// Port 443 by definition: this connection was redirected from it.
	p.serveTunnel(tlsConn, sni, "443")
}

// transparentHTTP handles requests redirected from port 80.
//
// Separate from ServeHTTP because the requests are a different shape. A proxied request carries an
// absolute-form URL (`GET http://host/path`); a redirected one is origin-form (`GET /path` plus a
// Host header) because the client thinks it reached the origin.
func (p *proxy) transparentHTTP() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "" {
			// Same reasoning as a missing SNI: unidentifiable is refused.
			d := Decision{Kind: "deny_policy", Reason: "no Host header"}
			p.record(d, "<no Host>", r.Method, r.URL.Path)
			p.writeRefusal(w, d, "")
			return
		}
		// Redirected traffic reaches us because the kernel sent it here, not because a client chose
		// to — so the Host header is the only thing naming the destination, and it is exactly as
		// attacker-controlled as it is in the tunnel. Same parse, same refusal.
		host, port, ok := splitAuthority(r.Host)
		if !ok {
			p.record(malformedHost, r.Host, r.Method, r.URL.Path)
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
		p.record(d, host, r.Method, match)
		if !d.Allow {
			p.writeRefusal(w, d, host)
			return
		}

		p.forward(w, r, upstreamURL("http", host, port, forward, match, r.URL.RawQuery))
	})
}

// serveTransparent runs the redirected listeners until the returned stop function is called.
//
// Two ports rather than one: what arrives on 443 is a TLS record and what arrives on 80 is a request
// line, and sniffing which is which per connection buys nothing when the kernel already knows.
//
// Several listeners per port, because one port has to be served on both loopback families. An
// IPv6 REDIRECT delivers to ::1 and an IPv4 one to 127.0.0.1; a guard listening on only the second
// would have the kernel handing it traffic it never accepts, which fails as a connection refused in
// the middle of a build rather than as anything resembling a policy decision.
func (p *proxy) serveTransparent(tlsLns, httpLns []net.Listener) (stop func()) {
	// A redirected port is reachable by anything on the box, so a client that opens a connection and
	// then says nothing must not be able to hold a goroutine indefinitely.
	httpSrv := &http.Server{
		Handler:           p.transparentHTTP(),
		ReadHeaderTimeout: transparentHandshakeTimeout,
	}
	for _, ln := range httpLns {
		go func(ln net.Listener) {
			if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logf("transparent http listener stopped: %s", err)
			}
		}(ln)
	}

	done := make(chan struct{})
	for _, ln := range tlsLns {
		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					select {
					case <-done:
					default:
						logf("transparent tls listener stopped: %s", err)
					}
					return
				}
				go p.serveTransparentTLS(conn)
			}
		}(ln)
	}

	return func() {
		close(done)
		for _, ln := range tlsLns {
			_ = ln.Close()
		}
		_ = httpSrv.Close()
	}
}
