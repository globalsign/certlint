package publicsuffix

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"

	"github.com/globalsign/certlint/certdata"
)

func TestPublicSuffix(t *testing.T) {
	cd := &certdata.Data{
		Cert: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "*.com",
			},
			DNSNames: []string{"*.com", "com", "*.co.uk", "gov.uk", "*.eu.com"},
		},
		Type: "DV",
	}

	e := Check(cd)
	if len(e.List()) != 6 {
		for _, err := range e.List() {
			fmt.Println(err)
		}
		t.Errorf("Expected 6 errors, got %d", len(e.List()))
	}
}
