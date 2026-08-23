package main

// The MITM certificate authority.
//
// Blocking one package version means reading the request path, and on HTTPS the path is inside the
// encrypted stream. So the proxy has to terminate TLS, which means minting certificates the build
// will trust. Host-level allowlisting alone would not need any of this — the hostname is in the SNI
// — but a host allowlist cannot tell `left-pad@1.2.0` from `left-pad@1.3.0`.
//
// The CA is generated fresh in memory at every start and never written anywhere but the file the
// child process is told to trust. It exists for the lifetime of one job. Nothing is shared between
// runs, so a leaked CA is worth nothing five minutes later — which is the property that makes
// intercepting a customer's own traffic acceptable at all.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// certAuthority mints per-host leaf certificates on demand.
type certAuthority struct {
	caCert *x509.Certificate
	caDER  []byte
	caKey  *ecdsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// P-256 rather than RSA: a few milliseconds to generate instead of a few hundred, which matters when
// the first `npm install` opens connections to a dozen hosts at once.
func newCertAuthority() (*certAuthority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "deter-guard egress CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-signing CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing CA: %w", err)
	}
	return &certAuthority{
		caCert: cert,
		caDER:  der,
		caKey:  key,
		cache:  map[string]*tls.Certificate{},
	}, nil
}

func randomSerial() (*big.Int, error) {
	// 128 bits, as the CA/Browser Forum requires and Go's own tooling uses.
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}
	return n, nil
}

// caPEM is what the child process is told to trust.
func (a *certAuthority) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.caDER})
}

// leafFor returns a certificate for one hostname, minting and caching on first use. A build that
// fetches two hundred tarballs from one host should pay for one certificate.
func (a *certAuthority) leafFor(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	if c, ok := a.cache[host]; ok {
		a.mu.Unlock()
		return c, nil
	}
	a.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// An IP literal has to go in IPAddresses, not DNSNames — a cert with an IP in DNSNames fails
	// verification, and builds do reach hosts by address (a private registry, a service container).
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, &key.PublicKey, a.caKey)
	if err != nil {
		return nil, fmt.Errorf("signing leaf for %s: %w", host, err)
	}
	out := &tls.Certificate{Certificate: [][]byte{der, a.caDER}, PrivateKey: key}

	a.mu.Lock()
	a.cache[host] = out
	a.mu.Unlock()
	return out, nil
}
