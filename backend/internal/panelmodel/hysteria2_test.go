package panelmodel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
)

// TestHysteria2TrustBundle requires every uploaded block to be a usable public certificate, including after a valid certificate.
func TestHysteria2TrustBundle(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"", true}, {cert, true}, {cert + cert, true},
		{" ", false}, {cert + "garbage", false}, {"-----BEGIN CERTIFICATE-----\n" + cert, false},
		{cert + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("test")})), false},
	} {
		if validHysteriaCertificates(tc.value) != tc.valid {
			t.Fatalf("unexpected trust result for %d-byte input", len(tc.value))
		}
	}
}

// TestHysteria2HostContract excludes ambiguous numeric hosts while accepting DNS absolute names and bare IPv6.
func TestHysteria2HostContract(t *testing.T) {
	for host, valid := range map[string]bool{"vpn.example.": true, "203.0.113.2": true, "2001:db8::1": true, "::ffff:192.0.2.1": true, "192.0.2.999": false, "127.1": false, "192.00.2.1": false, "[::1]": false} {
		if validHysteriaHost(host) != valid {
			t.Errorf("unexpected validation for %q", host)
		}
	}
}
