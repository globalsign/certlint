package version

import (
	"fmt"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
)

const checkName = "Certificate Version Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
func Check(d *certdata.Data) []error {
	if d.Cert.Version != 3 {
		return []error{fmt.Errorf("Certificate is not V3 (%d)", d.Cert.Version)}
	}
	return []error{}
}
