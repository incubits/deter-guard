package main

// Putting the guard's CA into the system trust store.
//
// In proxy mode the CA travels by environment variable — NODE_EXTRA_CA_CERTS and its dozen cousins.
// That works only for tools that read those variables, which is the same limitation transparent mode
// exists to remove: intercepting a runtime that never asked about a proxy is pointless if it then
// rejects the certificate. So the trust has to live where every TLS library already looks.
//
// This is the most invasive thing the guard does, and it deserves to be said plainly rather than
// buried: for the lifetime of this job, anything on this machine will trust a CA we minted. That is
// acceptable because the CA is generated in memory per run, is valid for 24 hours, exists on disk
// only in the file we install, and is removed on the way out. It would not be acceptable on a
// long-lived shared machine, and the guard is not for one.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// trustStores are the layouts we know how to install into, most common first. Each is a directory of
// PEM files plus the command that rebuilds the bundle from it.
var trustStores = []struct {
	dir     string
	file    string
	refresh []string
}{
	// Debian, Ubuntu — the CI runner case.
	{"/usr/local/share/ca-certificates", "deter-guard.crt", []string{"update-ca-certificates"}},
	// RHEL, Fedora, Rocky, Alma.
	{"/etc/pki/ca-trust/source/anchors", "deter-guard.crt", []string{"update-ca-trust", "extract"}},
	// Alpine.
	{"/usr/local/share/ca-certificates", "deter-guard.crt", []string{"update-ca-certificates"}},
}

// installSystemCA writes the CA into the first trust store that exists and refreshes it. The undo
// function removes it again and is safe to call more than once.
func installSystemCA(caPEM []byte) (undo func(), err error) {
	for _, store := range trustStores {
		if _, statErr := os.Stat(store.dir); statErr != nil {
			continue
		}
		if _, lookErr := exec.LookPath(store.refresh[0]); lookErr != nil {
			continue
		}

		path := filepath.Join(store.dir, store.file)
		// 0644: every TLS library on the box has to be able to read it.
		if err := os.WriteFile(path, caPEM, 0o644); err != nil {
			return nil, fmt.Errorf("writing %s: %w (transparent mode needs root)", path, err)
		}
		if out, err := exec.Command(store.refresh[0], store.refresh[1:]...).CombinedOutput(); err != nil {
			os.Remove(path)
			return nil, fmt.Errorf("%s: %w: %s", store.refresh[0], err, out)
		}

		logf("CA installed into the system trust store (%s)", path)
		return func() {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				// Worth shouting about: a CA left behind outlives the job that justified it.
				errf("could NOT remove the guard CA from %s — remove it by hand: %s", path, err)
				return
			}
			// Rebuild without it. Failure here is the same problem as above.
			if out, err := exec.Command(store.refresh[0], store.refresh[1:]...).CombinedOutput(); err != nil {
				errf("could not refresh the system trust store after removing the guard CA: %s: %s", err, out)
			}
		}, nil
	}

	return nil, fmt.Errorf("no system trust store found: looked for %s and %s with their refresh tools",
		trustStores[0].dir, trustStores[1].dir)
}
