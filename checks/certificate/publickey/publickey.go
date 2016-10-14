package publickey

import (
	"fmt"
	"strings"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/checks/certificate/publickey/goodkey"
)

const checkName = "Public Key Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
func Check(d *certdata.Data) []error {
	gkp := goodkey.NewKeyPolicy()
	err := gkp.GoodKey(d.Cert.PublicKey)
	if err != nil {
		return []error{fmt.Errorf("Certificate %s", strings.ToLower(err.Error()))}
	}
	return []error{}
}
