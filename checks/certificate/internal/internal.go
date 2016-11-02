package internal

import (
	"fmt"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
)

const checkName = "Internal Names and IP addresses Check"

func init() {
	filter := &checks.Filter{
		Type: []string{"DV", "OV", "IV", "EV"},
	}
	checks.RegisterCertificateCheck(checkName, filter, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
// TODO: Add more checks https://golang.org/src/crypto/x509/x509.go?s=15439:18344#L1157
func Check(d *certdata.Data) []error {
	var errors []error

	if checkInternalName(d.Cert.Subject.CommonName) {
		errors = append(errors, fmt.Errorf("Certificate contains an internal server name in the common name '%s'", d.Cert.Subject.CommonName))
	}
	for _, n := range d.Cert.DNSNames {
		if checkInternalName(n) {
			errors = append(errors, fmt.Errorf("Certificate subjectAltName '%s' contains an internal server name", n))
		}
	}

	// Check for internal IP addresses
	for _, ip := range d.Cert.IPAddresses {
		if !ip.IsGlobalUnicast() {
			errors = append(errors, fmt.Errorf("Certificate subjectAltName '%v' contains a non global unicast IP address", ip))
		}
		if checkInternalIP(ip) {
			errors = append(errors, fmt.Errorf("Certificate subjectAltName '%v' contains a private or local IP address", ip))
		}
	}

	return errors
}
