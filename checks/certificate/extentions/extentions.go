package extentions

import (
	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
)

const checkName = "Extentions Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
func Check(d *certdata.Data) []error {
	var errors []error
	for _, ext := range d.Cert.Extensions {
		// Check for any imported extentions and run all matching
		errors = append(errors, checks.Extentions.Check(ext, d)...)
	}
	return errors
}
