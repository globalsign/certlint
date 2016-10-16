package ct

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/globalsign/certlint/certdata"

	"github.com/globalsign/certlint/checks"
)

const checkName = "Certificate Transparency Extention Check"

var extentionOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

func init() {
	checks.RegisterExtentionCheck(checkName, extentionOid, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
//
// https://tools.ietf.org/html/rfc6962
//
// TODO: Check it's present in EV certificates issued after xxx
func Check(e pkix.Extension, d *certdata.Data) []error {
	var errors []error

	if e.Critical {
		errors = append(errors, fmt.Errorf("Certificate Transparency extention set critical"))
	}

	return errors
}
