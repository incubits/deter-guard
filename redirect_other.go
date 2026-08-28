//go:build !linux

package main

// Transparent mode needs kernel packet redirection and SO_MARK, both of which are Linux.
//
// The stubs exist so the rest of the program — and its tests — still build and run on a developer's
// macOS laptop. The interception logic in transparent.go is fully portable and fully tested there,
// as is the rule-building in redirect.go; only the plumbing that puts traffic in front of it is not.

import (
	"net/http"
	"syscall"
)

func markSocket(syscall.RawConn) error { return nil }

func installRedirect(int, int, []string, bool) error { return errNotLinux }

func removeRedirect() error { return nil }

func transparentSupported() bool { return false }

func enableSocketMarking(*http.Transport) {}
