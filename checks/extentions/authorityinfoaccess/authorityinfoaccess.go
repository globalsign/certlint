package authorityinfoaccess

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/globalsign/certlint/checks"
)

const checkName = "AuthorityInfoAccess Extention Check"

var extentionOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}

func init() {
	checks.RegisterExtentionCheck(checkName, extentionOid, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
// TODO: Add more checks https://golang.org/src/crypto/x509/x509.go?s=15439:18344#L1157
func Check(e pkix.Extension, c *x509.Certificate) []error {
	var errors []error

	if e.Critical {
		errors = append(errors, fmt.Errorf("AuthorityInfoAccess extention set critical"))
	}

	return errors
}
