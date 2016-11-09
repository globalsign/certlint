package nameconstraints

import (
	"encoding/asn1"

	"crypto/x509/pkix"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "NameConstraints Extension Check"

var extensionOid = asn1.ObjectIdentifier{2, 5, 29, 30}

func init() {
	checks.RegisterExtensionCheck(checkName, extensionOid, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(ex pkix.Extension, d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	// NameConstraints do officially need to be set critical, often they are not
	// because many implementations still don't support Name Constraints.
	// TODO: Only show a warning message
	if !ex.Critical {
		e.Err("NameConstraints extension set non-critical")
	}

	// NameConstraints should only be included in CA or subordinate certificates
	if !d.Cert.IsCA {
		e.Err("End entity certificate should not contain a NameConstraints extension")
	}

	return e
}
