package main

// What the transparent redirect installs, separated from the act of installing it.
//
// The rules are decided here and executed in redirect_linux.go. That split is not tidiness: the
// decisions are the part worth testing — which destinations are exempt, which order the rules go in,
// which address family each one belongs to — and none of it is testable on a machine that cannot run
// iptables. A developer's laptop can check the shape of the chain; only a Linux box can install it.

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// deterMark tags the guard's own outbound sockets. Arbitrary, but distinctive enough to recognise in
// somebody else's `iptables -L` output rather than looking like a stray bit.
const deterMark = 0xde7e

// chain keeps every rule we add in one place, so removal is exact rather than a best-effort scan of
// somebody else's NAT table.
const chain = "DETER_GUARD"

// family is one address family's worth of redirect: which binary installs it and what its loopback
// looks like. Both families get the same chain name, in their own separate tables.
type family struct {
	// bin is the iptables variant that owns this family.
	bin string
	// loopback is exempted wholesale — a build talking to its own service container is not egress.
	loopback string
}

var (
	familyV4 = family{bin: "iptables", loopback: "127.0.0.0/8"}
	familyV6 = family{bin: "ip6tables", loopback: "::1/128"}
)

// redirectRules is the chain, in order, for one address family.
//
// Order is the whole of the correctness here: every RETURN has to precede the REDIRECTs, or the
// exemption never runs. The OUTPUT hook goes last so the chain is never live while half-built.
//
// Note what is NOT exempt. Link-local — 169.254.0.0/16, and with it the cloud metadata service at
// 169.254.169.254 — used to be returned unfiltered, which made the single most valuable target on a
// CI runner the one destination the guard had no opinion about. Instance credentials are exactly
// what a supply-chain attack is after, and IMDS speaks plain HTTP on :80, so it is filtered like
// anything else: the policy decides, and default deny applies. A runner that genuinely needs it says
// so with `--exempt 169.254.169.254/32`.
func redirectRules(f family, exempt []string, httpPort, tlsPort int) [][]string {
	rule := func(args ...string) []string {
		return append([]string{"-t", "nat", "-A", chain}, args...)
	}

	rules := [][]string{
		// Our own traffic. Without this the guard proxies to itself, forever.
		rule("-m", "mark", "--mark", strconv.Itoa(deterMark), "-j", "RETURN"),
		rule("-d", f.loopback, "-j", "RETURN"),
	}
	for _, cidr := range exempt {
		rules = append(rules, rule("-d", cidr, "-j", "RETURN"))
	}
	return append(rules,
		rule("-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", strconv.Itoa(httpPort)),
		rule("-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", strconv.Itoa(tlsPort)),
		[]string{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", chain},
	)
}

// partitionExempt sorts operator-supplied CIDRs into the family each one belongs to.
//
// A v6 CIDR handed to iptables is an error, not a no-op, so guessing wrong would take the whole
// install down. Refuses anything it cannot parse rather than passing it through: a typo in an
// exemption silently becoming "exempt nothing" is a hole that looks like a working config.
func partitionExempt(cidrs []string) (v4, v6 []string, err error) {
	for _, raw := range cidrs {
		c := strings.TrimSpace(raw)
		if c == "" {
			continue
		}
		ip, _, perr := net.ParseCIDR(c)
		if perr != nil {
			// A bare address is a reasonable thing to type; treat it as a host route.
			if ip = net.ParseIP(c); ip == nil {
				return nil, nil, fmt.Errorf("--exempt %q is neither an IP address nor a CIDR", raw)
			}
		}
		if ip.To4() != nil {
			v4 = append(v4, c)
		} else {
			v6 = append(v6, c)
		}
	}
	return v4, v6, nil
}

// ipv6Routable reports whether this host has an IPv6 address that traffic could actually leave over.
//
// This is what decides whether a missing IPv6 redirect is survivable or fatal. Transparent mode's
// whole claim is that there is nothing to opt out of, and a build that prefers AAAA on a dual-stack
// runner opts out of an IPv4-only chain completely — without a warning, because from the guard's
// side nothing happened at all. So: cover both families, and if IPv6 is reachable and cannot be
// covered, refuse to run rather than enforce a policy with a silent hole in it.
//
// Unique local addresses count. fd00::/8 is routable within a site, which is enough to reach a
// registry mirror, and IsGlobalUnicast already reports true for them.
func ipv6Routable() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		// Cannot tell. Assume the dangerous answer: callers use this to decide whether to fail
		// closed, and guessing "no IPv6" here would be guessing in the direction of a silent bypass.
		return true
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() != nil {
			continue
		}
		if n.IP.IsGlobalUnicast() {
			return true
		}
	}
	return false
}
