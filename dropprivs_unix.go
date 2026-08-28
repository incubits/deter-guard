//go:build unix

package main

// Applying a dropCred to a child process. Unix has setuid; the stub next door does not.

import (
	"os/exec"
	"syscall"
)

func credentialsSupported() bool { return true }

// applyCredential makes the child start as somebody else.
//
// Setting Credential is what the kernel acts on: exec.Cmd hands it to fork/exec, which setgid,
// setgroups and setuid in that order before the command ever runs. There is no window in which the
// child exists with our privileges.
func applyCredential(cmd *exec.Cmd, c *dropCred) {
	if c == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{
		Uid:    c.uid,
		Gid:    c.gid,
		Groups: c.groups,
	}
}
