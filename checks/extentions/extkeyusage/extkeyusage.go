package extkeyusage

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/globalsign/certlint/checks"
)

const checkName = "ExtKeyUsage Extention Check"

var extentionOid = asn1.ObjectIdentifier{2, 5, 29, 37}

func init() {
	checks.RegisterExtentionCheck(checkName, extentionOid, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
//
// https://tools.ietf.org/html/rfc5280#section-4.2.1.12
//
// This extension MAY, at the option of the certificate issuer, be either critical or non-critical.
//
func Check(e pkix.Extension, c *x509.Certificate) []error {
	var errors []error

	// RFC: In general, this extension will appear only in end entity certificates.
	if c.IsCA {
		errors = append(errors, fmt.Errorf("In general ExtKeyUsage will appear only in end entity certificates"))
	}

	// RFC: Conforming CAs	SHOULD NOT mark this extension as critical if the
	// anyExtendedKeyUsage KeyPurposeId is present.
	if e.Critical {
		for _, ku := range c.ExtKeyUsage {
			if ku == x509.ExtKeyUsageAny {
				errors = append(errors, fmt.Errorf("ExtKeyUsage extention SHOULD NOT be critical if anyExtendedKeyUsage is present"))
				break
			}
		}
	}

	return errors
}
