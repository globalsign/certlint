package keyusage

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
)

const checkName = "Key Usage Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
// checkKeyUsageExtension verifies if the the required/allowed keyusages are set
//
// https://tools.ietf.org/html/rfc5280#section-4.2.1.3
//
// TODO: Check if we can or need to do something with dh.PublicKey
func Check(d *certdata.Data) []error {
	var errors []error
	var forbidden []x509.KeyUsage

	// Source
	// https://github.com/awslabs/certlint/blob/master/lib/certlint/extensions/keyusage.rb
	switch d.Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		forbidden = []x509.KeyUsage{
			x509.KeyUsageKeyAgreement,
			x509.KeyUsageEncipherOnly,
			x509.KeyUsageDecipherOnly,
		}
	case *ecdsa.PublicKey:
		forbidden = []x509.KeyUsage{
			x509.KeyUsageKeyEncipherment,
			x509.KeyUsageDataEncipherment,
		}
	case *dsa.PublicKey:
		forbidden = []x509.KeyUsage{
			x509.KeyUsageKeyEncipherment,
			x509.KeyUsageDataEncipherment,
			x509.KeyUsageKeyAgreement,
			x509.KeyUsageEncipherOnly,
			x509.KeyUsageDecipherOnly,
		}
		// case *dh.PublicKey:
		// forbidden = []x509.KeyUsage{
		//   x509.KeyUsageDigitalSignature,
		//   x509.KeyUsageContentCommitment,
		//   x509.KeyUsageKeyEncipherment,
		//   x509.KeyUsageDataEncipherment,
		//   x509.KeyUsageCertSign,
		//   x509.KeyUsageCRLSign,
		// }
	}

	// If we have not defined this certificate as a CA certificate, the following
	// key ussages would not be allowed
	if d.Type != "CA" {
		if d.Cert.KeyUsage == 0 {
			return []error{fmt.Errorf("Certificate has no key usage set")}
		}

		forbidden = append(forbidden, x509.KeyUsageCertSign)
		forbidden = append(forbidden, x509.KeyUsageCRLSign)
	}

	// Check if there are any forbidden key usages set
	for _, fku := range forbidden {
		if d.Cert.KeyUsage&fku != 0 {
			errors = append(errors, fmt.Errorf("Certificate has key usage %s set", keyUsageString(fku)))
		}
	}

	return errors
}
