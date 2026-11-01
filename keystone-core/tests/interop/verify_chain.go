// Standalone verifier for Keystone's interoperability tests (FR-21 AC5).
//
// It checks a leaf certificate against roots and intermediates with Go's
// crypto/x509, which enforces name constraints. Standard library only; it reads
// only the files named on its command line and opens no network connection.
//
// Usage: go run verify_chain.go <roots.pem> <intermediates.pem> <leaf.pem>
// Prints "OK" and exits 0 when the chain verifies, otherwise prints
// "FAIL: <reason>" and exits 1. Exit code 2 means a usage or input error.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

func load(path string) []*x509.Certificate {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("ERROR: read", path, err)
		os.Exit(2)
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Println("ERROR: parse", path, err)
			os.Exit(2)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		fmt.Println("ERROR: no certificate in", path)
		os.Exit(2)
	}
	return certs
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("ERROR: usage: verify_chain <roots.pem> <intermediates.pem> <leaf.pem>")
		os.Exit(2)
	}
	roots := x509.NewCertPool()
	for _, cert := range load(os.Args[1]) {
		roots.AddCert(cert)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range load(os.Args[2]) {
		intermediates.AddCert(cert)
	}
	leaf := load(os.Args[3])[0]
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}
