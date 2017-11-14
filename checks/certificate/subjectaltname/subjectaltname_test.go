package subjectaltname

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"

	"github.com/globalsign/certlint/certdata"
)

func TestSubjectAltNameDNSNames(t *testing.T) {
	cd := &certdata.Data{
		Cert: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "www.example .com",
			},
			DNSNames: []string{"www..example.com", "www .example.com",
				"www,example.com", "*.example.com", "www.example.com", "w_w.example.com",
				"グローバルサイン.com", "اختبارنطاق.شبكة", "-www.example.com",
				"www.ex_mple.com", "homoglyph.ехаmрlе.ϲоm"},
		},
		Type: "DV",
	}

	e := Check(cd)
	if len(e.List()) != 9 {
		t.Errorf("Expected 9 errors, got %d", len(e.List()))
	}
	for _, err := range e.List() {
		fmt.Println(err)
	}
}

// TODO: Set EmailAddresses in the Subject DN
func TestSubjectAltNameEmailAddresses(t *testing.T) {
	cd := &certdata.Data{
		Cert: &x509.Certificate{
			EmailAddresses: []string{"john.doe@example..com", "john.doe@example .com",
				"john.doe@example,com", "john.doe@example.com",
				"john.doe@グローバルサイン.com", "john.doe@اختبارنطاق.شبكة",
				"john.doe@-example.com", "john.doe@ex_mple.com", "homoglyph@ехаmрlе.ϲоm"},
		},
		Type: "PS",
	}

	e := Check(cd)
	if len(e.List()) != 6 {
		t.Errorf("Expected 6 errors, got %d", len(e.List()))
	}
	for _, err := range e.List() {
		fmt.Println(err)
	}
}
