package basicconstraints

import (
	"fmt"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
)

const checkName = "Basic Constraints Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) []error {
	var errors []error

	switch d.Type {
	case "DV", "OV", "EV":
		if d.Cert.IsCA {
			errors = append(errors, fmt.Errorf("Certificate has set CA true"))
		}
		if d.Cert.MaxPathLen == 0 && d.Cert.MaxPathLenZero {
			//errors = append(errors, fmt.Errorf("Certificate has set CA true"))
		}
		if d.Cert.BasicConstraintsValid {
			//errors = append(errors, fmt.Errorf("Certificate has set CA true"))
		}
	}

	return errors
}
