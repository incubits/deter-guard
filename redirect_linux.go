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

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// deterMark tags the guard's own outbound sockets. Arbitrary, but distinctive enough to recognise in
// somebody else's `iptables -L` output rather than looking like a stray bit.
const deterMark = 0xde7e

// chain keeps every rule we add in one place, so removal is exact rather than a best-effort scan of
// somebody else's NAT table.
const chain = "DETER_GUARD"

func markSocket(c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, deterMark)
	}); err != nil {
		return err
	}
	return serr
}

func iptables(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %v: %w: %s", args, err, out)
	}
	return nil
}

// installRedirect points outbound 80/443 at the transparent listeners.
//
// exempt holds CIDRs that must NOT be intercepted. At least one is mandatory in practice: the CI
// runner's own control-plane traffic. Intercepting that means a policy which omits the runner's
// control host does not merely fail the build — it stops the runner reporting the failure, so the
// job dies in a way that cannot explain itself. Refusing to enforce is recoverable; refusing to
// enforce invisibly is not.
func installRedirect(httpPort, tlsPort int, exempt []string) error {
	if err := removeRedirect(); err != nil {
		return err // a leftover chain from a previous run would double every rule
	}
	if err := iptables("-t", "nat", "-N", chain); err != nil {
		return err
	}

	// Order matters: every RETURN has to precede the REDIRECTs, or the exemption never runs.
	rules := [][]string{
		// Our own traffic. Without this the guard proxies to itself, forever.
		{"-t", "nat", "-A", chain, "-m", "mark", "--mark", strconv.Itoa(deterMark), "-j", "RETURN"},
		// Loopback, so a build talking to its own service container is untouched.
		{"-t", "nat", "-A", chain, "-d", "127.0.0.0/8", "-j", "RETURN"},
		{"-t", "nat", "-A", chain, "-d", "169.254.0.0/16", "-j", "RETURN"}, // link-local / cloud metadata
	}
	for _, cidr := range exempt {
		rules = append(rules, []string{"-t", "nat", "-A", chain, "-d", cidr, "-j", "RETURN"})
	}
	rules = append(rules,
		[]string{"-t", "nat", "-A", chain, "-p", "tcp", "--dport", "80", "-j", "REDIRECT",
			"--to-ports", strconv.Itoa(httpPort)},
		[]string{"-t", "nat", "-A", chain, "-p", "tcp", "--dport", "443", "-j", "REDIRECT",
			"--to-ports", strconv.Itoa(tlsPort)},
		// Hook it up last, so the chain is never live while half-built.
		[]string{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", chain},
	)

	for _, r := range rules {
		if err := iptables(r...); err != nil {
			// Leave nothing half-installed: a partial chain could redirect without exempting us.
			_ = removeRedirect()
			return err
		}
	}
	logf("transparent redirect installed: outbound :80 → :%d, :443 → :%d", httpPort, tlsPort)
	return nil
}

// removeRedirect takes the rules out again. Safe to call when they were never installed.
func removeRedirect() error {
	// Unhook first so nothing is redirected into a chain that is being emptied.
	for {
		if err := iptables("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", chain); err != nil {
			break // no more references
		}
	}
	_ = iptables("-t", "nat", "-F", chain)
	_ = iptables("-t", "nat", "-X", chain)
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
