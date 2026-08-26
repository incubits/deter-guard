package main

// Canonicalising a request before anything decides on it.
//
// Every rule in this package is a statement about a host and a path. That statement is only worth
// something if the host and path the POLICY sees are the ones the ORIGIN will resolve. Two bugs
// lived in exactly that gap, and both were reachable from a package's install script:
//
//   - The host. `hostMatches` was a suffix test over an unvalidated string, so a Host header of
//     `evil.com#.example.com` satisfied a `*.example.com` rule. The upstream URL was then built by
//     concatenation, `#` began a fragment, and the request went to evil.com. Any wildcard rule —
//     which is the ordinary shape, `*.npmjs.org` — was a general-purpose exfiltration channel.
//   - The path. Nothing resolved `//`, `/./` or `/../`, and the RAW request target went upstream,
//     so `/left-pad/-/./left-pad-1.3.0.tgz` matched no blocklist entry and still fetched the
//     blocked tarball. The origin normalises; the guard did not.
//
// So: DECIDE ON THE SAME THING YOU SEND. Matching one string and forwarding another is a single bug
// class rather than two bugs, which is why the fix is one file that both proxies go through.

import (
	"net"
	"net/url"
	"strings"
)

// canonicalHost puts a hostname in the one form everything else compares against: lower case, no
// surrounding brackets, no trailing root dot.
//
// The trailing dot matters beyond tidiness. `evil.com.` and `evil.com` are the same name to DNS, so
// a blocklist entry for one has to catch the other — otherwise a single keystroke walks past it.
func canonicalHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if len(h) > 1 && strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if len(h) > 1 && strings.HasSuffix(h, ".") {
		h = h[:len(h)-1]
	}
	return h
}

// validHostname reports whether a host is a plain DNS name or IP literal, and nothing else.
//
// This is the check that closes the wildcard bypass. `*.example.com` is matched with a suffix test,
// and a suffix test over arbitrary bytes is only safe if those bytes cannot also mean something to a
// URL parser. Underscores are allowed because internal registries really do use them and `_` is not
// a URL delimiter; `#`, `?`, `/`, `@`, `\` and `%` are not, because each one of them is a way to
// make the matched host and the resolved host differ.
func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// splitAuthority parses `host`, `host:port` or `[::1]:port` into a validated hostname and port.
//
// Refuses rather than repairs. A Host header carrying a URL delimiter is not a request with a typo
// in it — it is a request trying to be read two different ways by two different parsers, and the
// only safe reading is no reading at all.
func splitAuthority(authority string) (host, port string, ok bool) {
	a := strings.TrimSpace(authority)
	if a == "" {
		return "", "", false
	}
	if strings.ContainsAny(a, "/\\#?@%\"'<> \t\r\n") {
		return "", "", false
	}
	host = a
	if h, p, err := net.SplitHostPort(a); err == nil {
		host, port = h, p
	}
	if port != "" {
		if len(port) > 5 {
			return "", "", false
		}
		for i := 0; i < len(port); i++ {
			if port[i] < '0' || port[i] > '9' {
				return "", "", false
			}
		}
	}
	host = canonicalHost(host)
	if !validHostname(host) {
		return "", "", false
	}
	return host, port, true
}

// authorityOf renders a validated host and port back into what a URL wants.
//
// The brackets are not optional: `url.URL` will not add them for an IPv6 literal, and
// `https://::1/` is not a URL.
func authorityOf(host, port string) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

// cleanPath resolves a request path the way the origin will, and returns BOTH forms of it.
//
// `forward` is what goes upstream and keeps the caller's original percent-encoding byte for byte.
// That is not fussiness: a presigned S3 URL signs its own escaping, and npm addresses a scoped
// package as `@scope%2fpkg`, so re-encoding either one breaks a real build. `match` is the decoded
// form, which is what a rule's path prefix or a blocklist glob is written against — a block on
// `/left-pad/-/left-pad-1.3.0.tgz` should not be walked past by spelling one letter `%6c`.
//
// Only STRUCTURE changes. Empty segments collapse and `.`/`..` resolve, including their
// percent-encoded spellings, because an origin decodes before it normalises and so must we.
// Deliberately NOT touched: path parameters (`/pkg.tgz;x=1`). A handful of servers strip those and
// most treat them as literal filename bytes, so stripping them here would reopen this very bug in
// the other direction — matching `/pkg.tgz` while sending `/pkg.tgz;x=1`.
//
// ok is false for malformed percent-encoding. No package manager emits it, and a path that two
// parsers disagree about how to decode is the raw material for this whole class of bypass.
func cleanPath(escaped string) (forward, match string, ok bool) {
	if escaped == "" {
		return "/", "/", true
	}
	// A path ending in a separator, `.` or `..` addresses a directory, and that trailing slash is
	// load-bearing: a prefix rule for `/safe/` has to keep matching a request for `/safe/`.
	dir := strings.HasSuffix(escaped, "/") ||
		strings.HasSuffix(escaped, "/.") ||
		strings.HasSuffix(escaped, "/..")

	var raw, dec []string
	for _, seg := range strings.Split(escaped, "/") {
		d, err := url.PathUnescape(seg)
		if err != nil {
			return "", "", false
		}
		switch d {
		case "", ".":
			continue
		case "..":
			if n := len(raw); n > 0 {
				raw, dec = raw[:n-1], dec[:n-1]
			}
			continue
		}
		raw = append(raw, seg)
		dec = append(dec, d)
	}

	forward = "/" + strings.Join(raw, "/")
	match = "/" + strings.Join(dec, "/")
	if dir && len(raw) > 0 {
		forward += "/"
		match += "/"
	}
	return forward, match, true
}

// upstreamURL builds the request target structurally, from parts that have already been validated.
//
// Never by concatenating strings. `"https://" + host + path` is how a Host header of
// `evil.com#.example.com` became a request to evil.com; assembling a `url.URL` from a checked host
// and a checked path leaves nothing for a second parser to reinterpret.
//
// Path and RawPath are both set so that `EscapedPath` hands back the caller's own encoding: RawPath
// is used verbatim when it decodes to Path, which is exactly how cleanPath produced the pair.
func upstreamURL(scheme, host, port, forward, match, rawQuery string) *url.URL {
	// The scheme's own port is dropped rather than carried. It would otherwise ride along into the
	// Host header as `registry.npmjs.org:443`, which is legal, unlike anything a normal client
	// sends, and a thing some CDNs decline to serve.
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	return &url.URL{
		Scheme:   scheme,
		Host:     authorityOf(host, port),
		Path:     match,
		RawPath:  forward,
		RawQuery: rawQuery,
	}
}
