package crldistributionpoints

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/globalsign/certlint/checks"
)

const checkName = "CRLDistributionPoints Extention Check"

var extentionOid = asn1.ObjectIdentifier{2, 5, 29, 31}

func init() {
	checks.RegisterExtentionCheck(checkName, extentionOid, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
func Check(e pkix.Extension, c *x509.Certificate) []error {
	var errors []error

	if e.Critical {
		errors = append(errors, fmt.Errorf("CRLDistributionPoints extention set critical"))
	}

	return errors
}
