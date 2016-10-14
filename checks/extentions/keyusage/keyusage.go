package keyusage

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/globalsign/certlint/checks"
)

const checkName = "KeyUsage Extention Check"

var extentionOid = asn1.ObjectIdentifier{2, 5, 29, 15}

func init() {
	checks.RegisterExtentionCheck(checkName, extentionOid, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
//
// https://tools.ietf.org/html/rfc5280#section-4.2.1.3
//
func Check(e pkix.Extension, c *x509.Certificate) []error {
	var errors []error

	if !e.Critical {
		errors = append(errors, fmt.Errorf("KeyUsage extension SHOULD be marked as critical when present"))
	}

	return errors
}
