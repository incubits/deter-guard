//go:build linux

package main

// Installing the kernel rules that make transparent mode transparent, and the one exemption that
// stops it eating itself.
//
// The loop to worry about: the guard's own connection to the upstream registry leaves this machine
// on port 443, so the redirect rule catches it and sends it straight back to the guard, which
// forwards it, which is caught again. The usual fix is to run the proxy as its own uid and exempt
// that uid — but on a CI runner the guard and the build are the SAME user, so uid tells them apart
// not at all.
//
// So the guard marks its own sockets instead (SO_MARK) and the rules exempt that mark. It is a
// property of the socket rather than of who opened it, which is exactly the distinction needed here.
// SO_MARK needs CAP_NET_ADMIN, which we already require in order to write firewall rules at all.
//
// iptables rather than nft directly: on modern distributions iptables is a front end for nftables
// anyway, and it is the one that exists on every runner image and in every troubleshooting guide a
// customer will find.
//
// BOTH families, always. An IPv4-only chain on a dual-stack runner is not a partial control, it is
// no control at all for any host with a AAAA record — the client simply prefers IPv6 and never
// touches a rule we wrote. What the rules should be lives in redirect.go; this file runs them.

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"syscall"
	"time"
)

func markSocket(c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, deterMark)
	}); err != nil {
		return err
	}
	return serr
}

// run executes one iptables or ip6tables command.
func (f family) run(args ...string) error {
	out, err := exec.Command(f.bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", f.bin, args, err, out)
	}
	return nil
}

// install builds this family's chain and hooks it up.
func (f family) install(exempt []string, httpPort, tlsPort int) error {
	if err := f.run("-t", "nat", "-N", chain); err != nil {
		return err
	}
	for _, r := range redirectRules(f, exempt, httpPort, tlsPort) {
		if err := f.run(r...); err != nil {
			// Leave nothing half-installed: a partial chain could redirect without exempting us.
			f.remove()
			return err
		}
	}
	return nil
}

// remove takes this family's rules out again. Safe when they were never installed.
func (f family) remove() {
	// Unhook first so nothing is redirected into a chain that is being emptied.
	for f.run("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", chain) == nil {
	}
	_ = f.run("-t", "nat", "-F", chain)
	_ = f.run("-t", "nat", "-X", chain)
}

// installRedirect points outbound 80/443 at the transparent listeners, on both address families.
//
// haveV6Listener says whether the guard actually managed to bind the transparent ports on ::1.
// Redirecting IPv6 traffic to a port nothing is listening on would break every build on the runner,
// so the v6 chain is only installed when there is something to redirect to.
//
// exempt holds CIDRs that must NOT be intercepted. At least one is mandatory in practice: the CI
// runner's own control-plane traffic. Intercepting that means a policy which omits the runner's
// control host does not merely fail the build — it stops the runner reporting the failure, so the
// job dies in a way that cannot explain itself. Refusing to enforce is recoverable; refusing to
// enforce invisibly is not.
func installRedirect(httpPort, tlsPort int, exempt []string, haveV6Listener bool) error {
	if err := removeRedirect(); err != nil {
		return err // a leftover chain from a previous run would double every rule
	}

	v4Exempt, v6Exempt, err := partitionExempt(exempt)
	if err != nil {
		return err
	}

	if err := familyV4.install(v4Exempt, httpPort, tlsPort); err != nil {
		return err
	}

	v6err := errNoV6Listener
	if haveV6Listener {
		v6err = familyV6.install(v6Exempt, httpPort, tlsPort)
	}
	if v6err != nil {
		// Fail closed. A build that prefers AAAA would walk straight past an IPv4-only chain, and
		// nothing about that looks like a failure from in here — which is precisely why it cannot be
		// allowed to pass as a warning.
		if ipv6Routable() {
			familyV4.remove()
			return fmt.Errorf("this host has routable IPv6 but the IPv6 redirect could not be "+
				"installed, so a build could reach any AAAA host unfiltered: %w\n"+
				"Install ip6tables, or disable IPv6 on this runner "+
				"(sysctl -w net.ipv6.conf.all.disable_ipv6=1), then try again", v6err)
		}
		logf("no IPv6 redirect installed (%s) — this host has no routable IPv6 address, "+
			"so there is nothing to intercept over it", v6err)
	}

	logf("transparent redirect installed: outbound :80 → :%d, :443 → :%d (IPv4%s)",
		httpPort, tlsPort, map[bool]string{true: " and IPv6", false: " only"}[v6err == nil])
	return nil
}

// errNoV6Listener is the reason string when the guard never got an ::1 socket to redirect to.
var errNoV6Listener = fmt.Errorf("the guard is not listening on ::1")

// removeRedirect takes the rules out again, both families. Safe to call when they were never
// installed, which is what makes it usable as the first step of installing them.
func removeRedirect() error {
	familyV4.remove()
	familyV6.remove()
	return nil
}

func transparentSupported() bool { return true }

// enableSocketMarking makes the proxy's own upstream connections carry deterMark, so the rules above
// let them out instead of feeding them straight back in.
//
// Applied ONLY when the redirect is installed. SO_MARK needs CAP_NET_ADMIN, so doing it
// unconditionally would break every ordinary unprivileged `serve` with a dial failure.
func enableSocketMarking(tr *http.Transport) {
	d := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   func(_, _ string, c syscall.RawConn) error { return markSocket(c) },
	}
	tr.DialContext = d.DialContext
}
