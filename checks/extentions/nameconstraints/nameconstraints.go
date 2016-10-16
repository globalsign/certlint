package nameconstraints

import (
	"encoding/asn1"
	"fmt"

	"crypto/x509/pkix"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
)

const checkName = "NameConstraints Extention Check"

var extentionOid = asn1.ObjectIdentifier{2, 5, 29, 30}

func init() {
	checks.RegisterExtentionCheck(checkName, extentionOid, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
func Check(e pkix.Extension, d *certdata.Data) []error {
	var errors []error

	// NameConstraints do officially need to be set critical, often they are not
	// because many implementations still don't support Name Constraints.
	// TODO: Only show a warning message
	if !e.Critical {
		errors = append(errors, fmt.Errorf("NameConstraints extention set non-critical"))
	}

	// NameConstraints should only be included in CA or subordinate certificates
	if !d.Cert.IsCA {
		errors = append(errors, fmt.Errorf("End entity certificate should not contain a NameConstraints extention"))
	}

	return errors
}
