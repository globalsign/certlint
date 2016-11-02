package aiaissuers

import (
	"fmt"
	"net/url"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
)

const checkName = "Authority Info Access Issuers Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) []error {
	var errors []error
	if len(d.Cert.IssuingCertificateURL) == 0 {
		return []error{fmt.Errorf("Certificate contains no Authority Info Access Issuers")}
	}

	for _, icu := range d.Cert.IssuingCertificateURL {
		l, err := url.Parse(icu)
		if err != nil {
			errors = append(errors, fmt.Errorf("Certificate contains an invalid Authority Info Access Issuer URL (%s)", icu))
		}
		if l.Scheme != "http" {
			errors = append(errors, fmt.Errorf("Certificate contains a Authority Info Access Issuer with an non-preferred scheme (%s)", l.Scheme))
		}
	}

	return errors
}
