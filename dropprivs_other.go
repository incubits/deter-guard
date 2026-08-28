//go:build !unix

package main

// No setuid here. --run-as is refused rather than silently ignored: a flag whose whole purpose is to
// remove a privilege must never appear to have worked when it did nothing.

import "os/exec"

func credentialsSupported() bool { return false }

func applyCredential(*exec.Cmd, *dropCred) {}
