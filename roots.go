package main

// Root certificates for the guard's OWN outbound TLS — the console API, the OIDC exchange, and the
// upstream leg of the proxy. Nothing here affects what the guarded build trusts; that is the MITM CA
// in ca.go.
//
// The guard ships as one static binary and gets copied into whatever base image a customer already
// builds on. Two facts about that fight each other: Go's TLS stack needs a root store, and a slim
// image frequently has none. `node:*-slim` is the case that bit us in deter-console — Node bundles
// its own roots, so the image has no reason to carry the system bundle, and a Go binary dropped into
// it cannot complete a handshake it is perfectly willing to allow. It surfaces as `502 Bad Gateway`
// from the proxy, which reads as a network fault or a policy bug rather than a missing file. The fix
// was a second COPY line, and a second COPY line is a thing an integrator forgets.
//
// So the bundle travels inside the binary. roots.pem is Mozilla's set as published by the curl
// project — the same data a distro's ca-certificates package repackages. To refresh it:
//
//	curl -o roots.pem https://curl.se/ca/cacert.pem
//
// The embedded set is a UNION with the host's store by default, and the union is the part worth
// stating plainly rather than burying: a root the host has deliberately DISTRUSTED stays trusted
// here until the guard is rebuilt. That is the price of working in an image that has no store at
// all. An organization that manages its own trust and would rather have the failure can say so:
//
//	DETER_GUARD_ROOTS=system     host store only; fail honestly if it is empty
//	DETER_GUARD_ROOTS=embedded   ignore the host store; reproducible, ignores host revocations
//	DETER_GUARD_ROOTS=both       default
//
// Note this widens only what the GUARD will talk to. It cannot widen what the build may reach: that
// is the policy, checked before any connection is made.

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"net/http"
	"sync"
)

//go:embed roots.pem
var embeddedRootsPEM []byte

const (
	rootsBoth     = "both"
	rootsSystem   = "system"
	rootsEmbedded = "embedded"
)

var (
	rootsOnce sync.Once
	rootsPool *x509.CertPool
)

// countPEM reports how many certificates a PEM blob holds, for the log line. Cheap, and it is the
// only way to notice that roots.pem arrived empty or truncated.
func countPEM(b []byte) int {
	n := 0
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return n
		}
		if blk.Type == "CERTIFICATE" {
			n++
		}
	}
}

// rootCAs returns the pool for the guard's outbound TLS, built once.
//
// A nil pool is meaningful in Go: it means "use the platform verifier". That is what we want for the
// system-only mode on macOS and Windows, where SystemCertPool cannot be enumerated but the platform
// verifies perfectly well. So `system` mode deliberately returns nil rather than an empty pool —
// returning an empty pool would trust nothing at all.
func rootCAs() *x509.CertPool {
	rootsOnce.Do(func() { rootsPool = buildRootPool(env("DETER_GUARD_ROOTS", rootsBoth)) })
	return rootsPool
}

// buildRootPool is rootCAs without the caching, so a test can ask for each mode in one process.
func buildRootPool(mode string) *x509.CertPool {
	switch mode {
	case rootsSystem:
		pool, err := x509.SystemCertPool()
		if err != nil {
			// Do not fall back. The operator asked for the host's trust decisions specifically,
			// and quietly substituting ours would answer a different question than the one asked.
			errf("DETER_GUARD_ROOTS=system but the host root store could not be read: %s", err)
		}
		return pool

	case rootsEmbedded:
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(embeddedRootsPEM) {
			errf("the embedded root bundle did not parse — this binary is broken")
		}
		return pool

	default:
		if mode != rootsBoth {
			errf("unknown DETER_GUARD_ROOTS=%q — using %q", mode, rootsBoth)
		}
		// SystemCertPool returns a COPY, so appending to it cannot affect anything else in the
		// process. On macOS/Windows it comes back empty-but-usable; adding the embedded set there
		// is what makes `go test` on a laptop behave like the container.
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM(embeddedRootsPEM)
		return pool
	}
}

// installRoots points the shared http.DefaultClient at rootCAs().
//
// api.go, oidc.go and report.go all use http.DefaultClient, so this is the one place that has to
// change for every call the guard makes on its own behalf. Called from run() before any subcommand
// does I/O. It is a process-global mutation, which would be rude in a library and is right here: the
// whole process is one CLI invocation with one trust policy.
func installRoots() {
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// Cannot happen with the stdlib, but silently skipping would leave the guard using a
		// different trust store than it reports, which is worse than a loud line.
		errf("http.DefaultTransport is not *http.Transport — the embedded roots are NOT installed")
		return
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	tr.TLSClientConfig.RootCAs = rootCAs()
}
