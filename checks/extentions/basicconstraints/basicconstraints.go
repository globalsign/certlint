package basicconstraints

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/globalsign/certlint/certdata"

	"github.com/globalsign/certlint/checks"
)

const checkName = "BasicConstraints Extention Check"

var extentionOid = asn1.ObjectIdentifier{2, 5, 29, 19}

func init() {
	checks.RegisterExtentionCheck(checkName, extentionOid, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
func Check(e pkix.Extension, d *certdata.Data) []error {
	var errors []error

	if e.Critical {
		errors = append(errors, fmt.Errorf("BasicConstraints extention set critical"))
	}

	return errors
}
