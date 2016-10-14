package version

import (
	"bytes"
	"fmt"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
)

const checkName = "Issuer DN Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
func Check(d *certdata.Data) []error {
	if d.Issuer != nil && !bytes.Equal(d.Cert.RawIssuer, d.Issuer.RawSubject) {
		return []error{fmt.Errorf("Certificate Issuer Distinguished Name field MUST match the Subject DN of the Issuing CA")}
	}
	return []error{}
}
