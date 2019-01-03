package subject

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"

	"github.com/globalsign/certlint/certdata"
)

func TestSubject(t *testing.T) {
	n := &pkix.Name{
		Organization:       []string{"Organization Name that is exceeding the maximum length of 64 characters"},
		OrganizationalUnit: []string{"Organization Unit value exceeding the maximum length of 64 characters"},
		CommonName:         "just-a-really-really-really-really-loooooooooong-domain-exceeding-64chars.example.com",
	}

	rdns := n.ToRDNSequence()

	c := &x509.Certificate{}
	c.Subject.FillFromRDNSequence(&rdns)

	cd := &certdata.Data{
		Cert: c,
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
