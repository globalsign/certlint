package wildcard

import (
	"fmt"
	"strings"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
)

const checkName = "Wildcard(s) Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) []error {
	var errors []error

	switch d.Type {
	case "EV":
		if strings.LastIndex(d.Cert.Subject.CommonName, "*") > -1 {
			errors = append(errors, fmt.Errorf("Certificate should not contain a wildcard"))
		}
		for _, n := range d.Cert.DNSNames {
			if strings.LastIndex(n, "*") > -1 {
				errors = append(errors, fmt.Errorf("Certificate subjectAltName '%s' should not contain a wildcard", n))
			}
		}
	case "DV", "OV":
		if strings.LastIndex(d.Cert.Subject.CommonName, "*") > 0 {
			errors = append(errors, fmt.Errorf("Certificate wildcard is only allowed as prefix"))
		}
		for _, n := range d.Cert.DNSNames {
			if strings.LastIndex(n, "*") > 0 {
				errors = append(errors, fmt.Errorf("Certificate subjectAltName '%s' wildcard is only allowed as prefix", n))
			}
		}
	}

	return errors
}
