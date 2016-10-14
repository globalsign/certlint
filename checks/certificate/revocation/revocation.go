package revocation

import (
	"fmt"
	"net/url"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
)

const checkName = "Certificate Revocation Information Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
func Check(d *certdata.Data) []error {
	var errors []error
	if len(d.Cert.CRLDistributionPoints) == 0 && len(d.Cert.OCSPServer) == 0 {
		return []error{fmt.Errorf("Certificate contains no CRL or OCSP server")}
	}

	// Check CRL information
	for _, crl := range d.Cert.CRLDistributionPoints {
		l, err := url.Parse(crl)
		if err != nil {
			errors = append(errors, fmt.Errorf("Certificate contains an invalid CRL (%s)", crl))
		} else if l.Scheme != "http" {
			errors = append(errors, fmt.Errorf("Certificate contains a CRL with an non-preferred scheme (%s)", l.Scheme))
		}
	}

	// Check OCSP information
	for _, server := range d.Cert.OCSPServer {
		s, err := url.Parse(server)
		if err != nil {
			errors = append(errors, fmt.Errorf("Certificate contains an invalid OCSP server (%s)", s))
		} else if s.Scheme != "http" {
			errors = append(errors, fmt.Errorf("Certificate contains a OCSP server with an non-preferred scheme (%s)", s.Scheme))
		}
	}

	return errors
}
