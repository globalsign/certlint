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
//
// https://tools.ietf.org/html/rfc5280#section-4.2.1.9
//
func Check(e pkix.Extension, d *certdata.Data) []error {
	var errors []error

	// This extension MAY appear as a critical or non-critical extension in end
	// entity certificates.
	if d.Cert.IsCA {

		// Conforming CAs MUST include this extension in all CA certificates
		// that contain public keys used to validate digital signatures on
		// certificates and MUST mark the extension as critical in such
		// certificates.  This extension MAY appear as a critical or non-
		// critical extension in CA certificates that contain public keys used
		// exclusively for purposes other than validating digital signatures on
		// certificates.  Such CA certificates include ones that contain public
		// keys used exclusively for validating digital signatures on CRLs and
		// ones that contain key management public keys used with certificate
		// enrollment protocols.
		//
		// TODO: Does it always need to be critical in CA certificates?
		if !e.Critical {
			errors = append(errors, fmt.Errorf("BasicConstraints extention must be critical in CA certificates"))
		}
	}

	return errors
}
