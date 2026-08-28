package main

// Dropping the wrapped command's privileges.
//
// Transparent mode has to run as root: writing firewall rules and installing a CA into the system
// trust store are both privileged, and there is no way around that. But the BUILD does not need
// those privileges, and if it keeps them the interception is decorative — a process holding
// CAP_NET_ADMIN removes the redirect with one `iptables -t nat -F DETER_GUARD` and walks out.
//
// So `serve --wrap --run-as <user>` starts the guard as root and the command as somebody else. The
// child inherits the network namespace, so the rules apply to it; it does not inherit the capability,
// so it cannot remove them. THE PRIVILEGE DROP IS THE CONTROL — without it the redirect is a
// suggestion that happens to be enforced by the kernel until the build objects.
//
// This cannot be done for a detached `serve`, which never starts the build and has no say in how the
// build is started. There the guard says so at startup rather than implying a containment it is not
// providing.

import (
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"strings"
)

// dropCred is the identity a wrapped child is switched to. Kept as plain numbers rather than a
// syscall type so this file, and its tests, build everywhere.
type dropCred struct {
	name   string
	uid    uint32
	gid    uint32
	groups []uint32
}

func (c *dropCred) String() string {
	if c == nil {
		return "this process's own user"
	}
	return fmt.Sprintf("%s (uid %d, gid %d)", c.name, c.uid, c.gid)
}

// resolveDropUser parses `--run-as`, accepting a name or a number, with an optional group:
//
//	--run-as build          the user "build" and its primary group
//	--run-as 1001           uid 1001, and the primary group the passwd entry gives it
//	--run-as build:builders an explicit group
//	--run-as 1001:1001      neither has to exist in passwd at all
//
// Numbers are accepted without a passwd entry because a container frequently has none — refusing a
// uid that the kernel is perfectly willing to setuid to would make this unusable on exactly the slim
// images the guard is meant for.
func resolveDropUser(spec string) (*dropCred, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("--run-as needs a user name or uid")
	}
	userPart, groupPart, hasGroup := strings.Cut(spec, ":")
	userPart, groupPart = strings.TrimSpace(userPart), strings.TrimSpace(groupPart)
	if userPart == "" {
		return nil, fmt.Errorf("--run-as %q has no user part", spec)
	}
	if hasGroup && groupPart == "" {
		return nil, fmt.Errorf("--run-as %q has an empty group after the colon", spec)
	}

	c := &dropCred{name: userPart}
	u, lookupErr := lookupUser(userPart)
	switch {
	case lookupErr == nil:
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("user %q has a uid that is not a number (%q)", userPart, u.Uid)
		}
		gid, err := strconv.ParseUint(u.Gid, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("user %q has a gid that is not a number (%q)", userPart, u.Gid)
		}
		c.uid, c.gid = uint32(uid), uint32(gid)
		c.groups = supplementaryGroups(u)
	default:
		// No passwd entry. A bare number is still perfectly usable.
		uid, err := strconv.ParseUint(userPart, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("no such user %q, and it is not a uid either: %w", userPart, lookupErr)
		}
		c.uid, c.gid = uint32(uid), uint32(uid)
		c.name = userPart
	}

	if hasGroup {
		gid, err := resolveGroup(groupPart)
		if err != nil {
			return nil, err
		}
		c.gid = gid
		// An explicit group replaces the passwd-derived set rather than adding to it: the point of
		// naming one is to say exactly what the build may act as.
		c.groups = nil
	}

	if c.uid == 0 {
		return nil, errors.New("--run-as resolves to uid 0, which drops nothing at all")
	}
	return c, nil
}

// lookupUser finds a passwd entry by name or by uid.
func lookupUser(s string) (*user.User, error) {
	if u, err := user.Lookup(s); err == nil {
		return u, nil
	}
	return user.LookupId(s)
}

func resolveGroup(s string) (uint32, error) {
	if g, err := user.LookupGroup(s); err == nil {
		gid, perr := strconv.ParseUint(g.Gid, 10, 32)
		if perr != nil {
			return 0, fmt.Errorf("group %q has a gid that is not a number (%q)", s, g.Gid)
		}
		return uint32(gid), nil
	}
	gid, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("no such group %q, and it is not a gid either", s)
	}
	return uint32(gid), nil
}

// supplementaryGroups returns the user's other groups, best effort.
//
// Best effort on purpose: GroupIds needs to read /etc/group, which a minimal image may not have.
// Coming back with only the primary group is a strictly SMALLER set of privileges, so failing to
// read it is safe to ignore — the opposite direction would not be.
func supplementaryGroups(u *user.User) []uint32 {
	ids, err := u.GroupIds()
	if err != nil {
		return nil
	}
	var out []uint32
	for _, id := range ids {
		if n, perr := strconv.ParseUint(id, 10, 32); perr == nil {
			out = append(out, uint32(n))
		}
	}
	return out
}
