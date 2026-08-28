package main

import (
	"os/user"
	"strconv"
	"strings"
	"testing"
)

// joined renders one rule for substring assertions, so a test reads like the command it checks.
func joined(rules [][]string) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, strings.Join(r, " "))
	}
	return out
}

func hasRuleContaining(rules [][]string, needle string) bool {
	for _, r := range joined(rules) {
		if strings.Contains(r, needle) {
			return true
		}
	}
	return false
}

// The regression this file exists for. 169.254.0.0/16 was returned unfiltered, which meant the cloud
// metadata service — instance credentials, the thing a supply-chain attack is actually after — was
// the one destination on the runner the policy had no opinion about.
func TestCloudMetadataIsNotExemptByDefault(t *testing.T) {
	rules := redirectRules(familyV4, nil, 3129, 3130)
	if hasRuleContaining(rules, "169.254") {
		t.Fatalf("link-local is exempt again, so metadata is unfiltered:\n%s",
			strings.Join(joined(rules), "\n"))
	}
	// It has to be reachable by the redirect instead, or it is not filtered, just unreachable.
	if !hasRuleContaining(rules, "--dport 80 -j REDIRECT") {
		t.Error("no :80 redirect, so metadata's plain-HTTP traffic is not intercepted at all")
	}
}

// The escape hatch has to actually work, or the answer to "our runner needs IMDS" is "stop using
// transparent mode".
func TestExemptRestoresCloudMetadata(t *testing.T) {
	rules := redirectRules(familyV4, []string{"169.254.169.254/32"}, 3129, 3130)
	if !hasRuleContaining(rules, "-d 169.254.169.254/32 -j RETURN") {
		t.Fatalf("--exempt did not produce a RETURN:\n%s", strings.Join(joined(rules), "\n"))
	}
}

// Order is the whole of the correctness: a RETURN after a REDIRECT never runs.
func TestEveryReturnPrecedesEveryRedirect(t *testing.T) {
	rules := joined(redirectRules(familyV4, []string{"10.0.0.0/8"}, 3129, 3130))
	firstRedirect := len(rules)
	for i, r := range rules {
		if strings.Contains(r, "-j REDIRECT") {
			firstRedirect = i
			break
		}
	}
	for i, r := range rules {
		if strings.Contains(r, "-j RETURN") && i > firstRedirect {
			t.Errorf("RETURN at %d comes after the first REDIRECT at %d: %q", i, firstRedirect, r)
		}
	}
}

// The OUTPUT hook goes last, so the chain is never live while it is still being built.
func TestTheOutputHookIsInstalledLast(t *testing.T) {
	rules := joined(redirectRules(familyV6, nil, 3129, 3130))
	if last := rules[len(rules)-1]; !strings.Contains(last, "-A OUTPUT") {
		t.Errorf("last rule is %q, expected the OUTPUT hook", last)
	}
	for _, r := range rules[:len(rules)-1] {
		if strings.Contains(r, "-A OUTPUT") {
			t.Errorf("OUTPUT hooked early: %q", r)
		}
	}
}

// An IPv4-only chain is not a partial control on a dual-stack host — it is no control at all for any
// host with a AAAA record, because the client simply prefers IPv6 and touches nothing we wrote.
func TestBothFamiliesGetTheirOwnLoopbackAndBinary(t *testing.T) {
	if familyV4.bin != "iptables" || familyV6.bin != "ip6tables" {
		t.Fatalf("families use the wrong binaries: %q and %q", familyV4.bin, familyV6.bin)
	}
	if !hasRuleContaining(redirectRules(familyV4, nil, 1, 2), "-d 127.0.0.0/8 -j RETURN") {
		t.Error("IPv4 chain does not exempt IPv4 loopback")
	}
	if !hasRuleContaining(redirectRules(familyV6, nil, 1, 2), "-d ::1/128 -j RETURN") {
		t.Error("IPv6 chain does not exempt IPv6 loopback")
	}
	// The guard's own marked sockets must be exempt in BOTH, or transparent mode feeds itself.
	for _, f := range []family{familyV4, familyV6} {
		if !hasRuleContaining(redirectRules(f, nil, 1, 2), "--mark "+strconv.Itoa(deterMark)) {
			t.Errorf("%s chain does not exempt the guard's own mark", f.bin)
		}
	}
}

func TestPartitionExemptSortsByFamily(t *testing.T) {
	v4, v6, err := partitionExempt([]string{"10.0.0.0/8", "fd00::/8", " 192.168.1.1 ", "2001:db8::1", ""})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if strings.Join(v4, ",") != "10.0.0.0/8,192.168.1.1" {
		t.Errorf("v4 = %v", v4)
	}
	if strings.Join(v6, ",") != "fd00::/8,2001:db8::1" {
		t.Errorf("v6 = %v", v6)
	}
}

// A typo silently becoming "exempt nothing" is a hole that looks like a working configuration.
func TestPartitionExemptRefusesNonsense(t *testing.T) {
	for _, bad := range []string{"registry.npmjs.org", "10.0.0.0/999", "not-an-ip"} {
		if _, _, err := partitionExempt([]string{bad}); err == nil {
			t.Errorf("%q was accepted as a CIDR", bad)
		}
	}
}

func TestResolveDropUserRefusesRoot(t *testing.T) {
	// The flag exists to remove a privilege. Resolving to uid 0 removes none, and silently doing
	// nothing is the one outcome a security flag must never have.
	for _, spec := range []string{"0", "0:0"} {
		if _, err := resolveDropUser(spec); err == nil {
			t.Errorf("--run-as %q was accepted", spec)
		}
	}
}

func TestResolveDropUserAcceptsBareNumbers(t *testing.T) {
	// A slim container often has no passwd entry at all, so a uid has to work without one.
	c, err := resolveDropUser("1001:2002")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if c.uid != 1001 || c.gid != 2002 {
		t.Errorf("uid/gid = %d/%d, want 1001/2002", c.uid, c.gid)
	}
}

func TestResolveDropUserFindsThisUserByName(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	if me.Uid == "0" {
		t.Skip("running as root; resolveDropUser correctly refuses uid 0")
	}
	c, err := resolveDropUser(me.Username)
	if err != nil {
		t.Fatalf("looking up %q: %s", me.Username, err)
	}
	if strconv.FormatUint(uint64(c.uid), 10) != me.Uid {
		t.Errorf("uid = %d, want %s", c.uid, me.Uid)
	}
}

func TestResolveDropUserRejectsMalformedSpecs(t *testing.T) {
	for _, bad := range []string{"", "   ", ":group", "user:"} {
		if _, err := resolveDropUser(bad); err == nil {
			t.Errorf("--run-as %q was accepted", bad)
		}
	}
}

// --run-as without --wrap has nothing to apply to. Accepting it would report a privilege drop that
// never happened.
func TestRunAsNeedsAWrappedCommand(t *testing.T) {
	if _, code := resolveRunAs(opts{runAs: "nobody"}); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if cred, code := resolveRunAs(opts{}); cred != nil || code != exitOK {
		t.Errorf("no --run-as should be a no-op, got cred=%v code=%d", cred, code)
	}
}
