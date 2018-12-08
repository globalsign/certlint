package validity

import (
	"time"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "Validity Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	switch d.Type {
	case "EV":
		if d.Cert.NotBefore.After(time.Date(2017, 3, 17, 0, 0, 0, 0, time.UTC)) {
			if d.Cert.NotAfter.After(d.Cert.NotBefore.AddDate(0, 0, 825)) {
				e.Err("EV Certificate LifeTime exceeds 825 days")
				return e
			}
		} else {
			if d.Cert.NotAfter.After(d.Cert.NotBefore.AddDate(0, 27, 0)) {
				e.Err("EV Certificate LifeTime exceeds 27 months")
				return e
			}
		}
	case "DV", "OV":
		if d.Cert.NotBefore.After(time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC)) {
			if d.Cert.NotAfter.After(d.Cert.NotBefore.AddDate(0, 0, 825)) {
				e.Err("Certificate LifeTime exceeds 825 days")
				return e
			}
		} else if d.Cert.NotBefore.After(time.Date(2016, 7, 1, 0, 0, 0, 0, time.UTC)) {
			if d.Cert.NotAfter.After(d.Cert.NotBefore.AddDate(0, 39, 0)) {
				e.Err("Certificate LifeTime exceeds 39 months")
				return e
			}
		} else {
			if d.Cert.NotAfter.After(d.Cert.NotBefore.AddDate(0, 60, 0)) {
				e.Err("Certificate LifeTime exceeds 60 months")
				return e
			}
		}
	}
	return e
}
