package internal

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"testing"

	"github.com/globalsign/certlint/certdata"
)

func TestInternal(t *testing.T) {
	cd := &certdata.Data{
		Cert: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "localhost",
			},
			DNSNames:    []string{"localhost", "example.internal", "example.corp", "*.example.local", "*.server"},
			IPAddresses: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("172.16.1.1"), net.ParseIP("10.1.1.1")},
		},
		Type: "DV",
	}

	e := Check(cd)
	if len(e.List()) != 9 {
		for _, err := range e.List() {
			fmt.Println(err)
		}
		t.Errorf("Expected 9 errors, got %d", len(e.List()))
	}
}
