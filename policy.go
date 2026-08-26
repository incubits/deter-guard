package main

// The egress decision.
//
// This client does NOT evaluate Cedar. Cedar is the console's authoring language, and its evaluator
// lives there; what reaches a client is a compiled rule set — permits, plus a blocklist that
// overrides them. That split is deliberate:
//
//   - One implementation of policy SEMANTICS. A second evaluator out here would eventually disagree
//     with the console about what a rule means, and the failure mode is a rule that permits on a
//     laptop and denies in CI, discovered in production.
//   - The client stays small and dependency-free. Matching hostnames and path prefixes needs no
//     library, which is why this image can be a few megabytes with nothing to patch.
//
// Default deny. A request is allowed only if some active rule permits it AND no block matches.

import (
	"strings"
)

// Rule is one permit: a host, optionally narrowed to methods and path prefixes.
//
// Empty Methods means "any method"; empty PathPrefixes means "any path". That is what makes a plain
// host allowlist the common case it should be — `{Host: "registry.npmjs.org"}` and nothing else.
type Rule struct {
	Host         string   `json:"host"`
	Methods      []string `json:"methods"`
	PathPrefixes []string `json:"path_prefixes"`
	// Inactive rules travel with the policy so the console can show a disabled rule without
	// deleting it. They are never enforced.
	//
	// A POINTER so that "absent" and "false" are different things. The console always sends the
	// field, but a hand-written policy file usually omits it — and if absent meant inactive, such a
	// file would permit nothing and every request would be refused with no rule visibly disabled.
	Active *bool `json:"active"`
}

// enabled reports whether a rule is enforced. An omitted `active` means yes.
func (r Rule) enabled() bool { return r.Active == nil || *r.Active }

// Block denies a request even when a rule permits its host — the supply-chain blocklist.
//
// This is the whole point of the product: `registry.npmjs.org` has to stay reachable, while one
// specific compromised package version must not be. A blocklist that could only work at host
// granularity would mean turning off the registry to block one package.
type Block struct {
	Host string `json:"host"`
	// Glob patterns matched against the request path. `*` matches any run of characters.
	PathGlobs []string `json:"path_globs"`
	// Shown to whoever's build just failed. A refusal nobody can explain gets worked around.
	Reason string `json:"reason"`
}

// Policy is the compiled rule set as the console serves it.
type Policy struct {
	Version int64   `json:"version"`
	Rules   []Rule  `json:"rules"`
	Blocked []Block `json:"blocked"`
}

// Decision is why a request was allowed or refused. The reason is carried so the proxy can put it in
// the 403 body and in the report, rather than making everyone guess.
type Decision struct {
	Allow bool
	// "deny_policy" (no rule permits it) or "deny_blocklist" (explicitly blocked). Matches the Rust
	// broker's audit vocabulary so the two look the same in the console.
	Kind   string
	Reason string
}

// hostMatches supports an exact name and a leading-`*.` wildcard.
//
// The wildcard covers one or more leading labels, so `*.example.com` matches `a.example.com` and
// `a.b.example.com`. It deliberately does NOT match the bare apex `example.com`: a rule for
// subdomains that silently also opened the parent domain would be a surprise in the widening
// direction, which is the direction that matters.
func hostMatches(pattern, host string) bool {
	pattern = canonicalHost(pattern)
	host = canonicalHost(host)
	if pattern == "" || host == "" {
		return false
	}
	// A host that is not a plain name or address matches NOTHING — not a permit, and not a block.
	// The suffix test below is only sound over bytes that cannot also mean something to a URL
	// parser: `evil.com#.example.com` ends in `.example.com` and resolves to evil.com, which is how
	// a `*.example.com` rule became a way out to anywhere. See canonical.go.
	if !validHostname(host) {
		return false
	}
	if pattern == host {
		return true
	}
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return suffix != "" && strings.HasSuffix(host, "."+suffix)
	}
	return false
}

// globMatches implements `*`-only globbing, anchored at both ends.
//
// Written out rather than reaching for path.Match because path.Match's `*` stops at `/`, and every
// useful package pattern crosses slashes (`/left-pad/-/left-pad-1.3.0.tgz`). Splitting on `*` and
// walking the literal segments in order is the whole algorithm.
func globMatches(pattern, s string) bool {
	if pattern == "" {
		return false
	}
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	// A leading segment must sit at the start; a trailing one at the end.
	if first := parts[0]; first != "" {
		if !strings.HasPrefix(s, first) {
			return false
		}
		s = s[len(first):]
	}
	last := parts[len(parts)-1]
	middle := parts[1 : len(parts)-1]
	for _, m := range middle {
		if m == "" {
			continue
		}
		i := strings.Index(s, m)
		if i < 0 {
			return false
		}
		s = s[i+len(m):]
	}
	if last != "" {
		return strings.HasSuffix(s, last)
	}
	return true
}

// blocked reports the first matching block, if any. Checked BEFORE permits: a blocklist that a
// permit could override would not be a blocklist.
func (p *Policy) blocked(host, path string) (Block, bool) {
	for _, b := range p.Blocked {
		if !hostMatches(b.Host, host) {
			continue
		}
		// A block with no path globs blocks the whole host.
		if len(b.PathGlobs) == 0 {
			return b, true
		}
		for _, g := range b.PathGlobs {
			if globMatches(g, path) {
				return b, true
			}
		}
	}
	return Block{}, false
}

// permits reports whether any active rule allows this exact request.
func (p *Policy) permits(host, method, path string) bool {
	for _, r := range p.Rules {
		if !r.enabled() || !hostMatches(r.Host, host) {
			continue
		}
		if len(r.Methods) > 0 && !containsFold(r.Methods, method) {
			continue
		}
		if len(r.PathPrefixes) > 0 && !anyPrefix(r.PathPrefixes, path) {
			continue
		}
		return true
	}
	return false
}

func containsFold(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.EqualFold(strings.TrimSpace(h), needle) {
			return true
		}
	}
	return false
}

func anyPrefix(prefixes []string, path string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// Check decides one request.
func (p *Policy) Check(host, method, path string) Decision {
	if d, ok := refuseMalformedHost(host); ok {
		return d
	}
	if b, ok := p.blocked(host, path); ok {
		reason := b.Reason
		if reason == "" {
			reason = "blocked by the organization's blocklist"
		}
		return Decision{Allow: false, Kind: "deny_blocklist", Reason: reason}
	}
	if p.permits(host, method, path) {
		return Decision{Allow: true, Kind: "allow"}
	}
	return Decision{Allow: false, Kind: "deny_policy", Reason: "host not permitted by the egress policy"}
}

// CheckTunnel decides a CONNECT, which has a host but no method or path.
//
// A tunnel is opened if the host could be reachable at all — the per-request check inside the
// tunnel is what actually enforces method and path. Refusing the tunnel outright when a host is
// permitted only for some paths would make path-scoped rules deny the whole host, which is exactly
// the bug this design exists to avoid.
//
// A host on the blocklist with no path globs is refused here, before any bytes flow.
func (p *Policy) CheckTunnel(host string) Decision {
	if d, ok := refuseMalformedHost(host); ok {
		return d
	}
	if b, ok := p.blocked(host, ""); ok && len(b.PathGlobs) == 0 {
		reason := b.Reason
		if reason == "" {
			reason = "blocked by the organization's blocklist"
		}
		return Decision{Allow: false, Kind: "deny_blocklist", Reason: reason}
	}
	for _, r := range p.Rules {
		if r.enabled() && hostMatches(r.Host, host) {
			return Decision{Allow: true, Kind: "allow"}
		}
	}
	return Decision{Allow: false, Kind: "deny_policy", Reason: "host not permitted by the egress policy"}
}

// refuseMalformedHost is the belt to hostMatches' braces.
//
// hostMatches already refuses to match an unparseable host, which makes default-deny do the right
// thing on its own. This says so explicitly instead, because "no rule happened to match" and "this
// host is not a hostname" deserve different words in a build log — and because a future rule form
// that does not go through hostMatches should not silently inherit the hole.
func refuseMalformedHost(host string) (Decision, bool) {
	if validHostname(canonicalHost(host)) {
		return Decision{}, false
	}
	return Decision{
		Allow:  false,
		Kind:   "deny_policy",
		Reason: "malformed host — not a hostname or IP address",
	}, true
}
