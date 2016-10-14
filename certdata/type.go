package certdata

import (
	"crypto/x509"
	"fmt"
	"strings"

	psl "golang.org/x/net/publicsuffix"
)

// setCertificateType set the base on how we check for other requirements of the
// certificate. It's important that we reliably identify the purpose to apply
// the right checks for that certificate type.
func (d *Data) setCertificateType() error {
	for _, ku := range d.Cert.ExtKeyUsage {
		switch ku {
		case x509.ExtKeyUsageServerAuth:
			// Try to determine certificate type via policy oid
			for _, poid := range d.Cert.PolicyIdentifiers {
				if val, ok := polOidType[poid.String()]; ok {
					d.Type = val
					break
				}
			}
		case x509.ExtKeyUsageEmailProtection:
			d.Type = "PS"
		case x509.ExtKeyUsageCodeSigning:
			d.Type = "CS"
		case x509.ExtKeyUsageTimeStamping:
			d.Type = "TS"
		case x509.ExtKeyUsageOCSPSigning:
			d.Type = "OCSP"
		}
	}

	// If we have no kown key usage, try the policy list again
	for _, poid := range d.Cert.PolicyIdentifiers {
		if val, ok := polOidType[poid.String()]; ok {
			d.Type = val
			break
		}
	}

	// When determined by Policy Identifier we can stop
	if d.Type != "" {
		return nil
	}

	// Check if the e-mailAddress is set in the DN
	for _, n := range d.Cert.Subject.Names {
		switch n.Type.String() {
		case "1.2.840.113549.1.9.1": // e-mailAddress
			d.Type = "PS"
			return nil
		}
	}

	// An @ sing in the common name is often used in PS.
	if strings.Contains(d.Cert.Subject.CommonName, "@") {
		d.Type = "PS"
		return nil
	} else if strings.Contains(d.Cert.Subject.CommonName, " ") {
		d.Type = "PS"
		return nil
	}

	// If it's a fqdn, it's a EV, OV or DV
	if suffix, _ := psl.PublicSuffix(strings.ToLower(d.Cert.Subject.CommonName)); len(suffix) > 0 {
		if len(d.Cert.Subject.Organization) > 0 {
			if len(d.Cert.Subject.SerialNumber) > 0 {
				d.Type = "EV"
				return nil
			} else {
				d.Type = "OV"
				return nil
			}
		} else {
			d.Type = "DV"
			return nil
		}
	}

	if d.Type == "" {
		fmt.Println(d.Cert.Subject)
		return fmt.Errorf("Could not determine certificate type")
	}
	return nil
}
