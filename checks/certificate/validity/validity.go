package validity

import (
	"fmt"
	"time"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
)

const checkName = "Validity Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
func Check(d *certdata.Data) []error {
	switch d.Type {
	case "EV":
		if d.Cert.NotBefore.After(d.Cert.NotBefore.AddDate(0, 27, 0)) {
			return []error{fmt.Errorf("EV Certificate LifeTime exceeds 27 months")}
		}
	case "DV", "OV":
		if d.Cert.NotBefore.After(time.Date(2015, 4, 1, 0, 0, 0, 0, time.UTC)) {
			if d.Cert.NotBefore.After(d.Cert.NotBefore.AddDate(0, 39, 0)) {
				return []error{fmt.Errorf("Certificate LifeTime exceeds 39 months")}
			}
		} else {
			if d.Cert.NotBefore.After(d.Cert.NotBefore.AddDate(0, 60, 0)) {
				return []error{fmt.Errorf("Certificate LifeTime exceeds 60 months")}
			}
		}
	}
	return []error{}
}
