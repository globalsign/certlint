package subject

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "Subject Check"

func init() {
	filter := &checks.Filter{
		Type: []string{"DV", "OV", "IV", "EV"},
	}
	checks.RegisterCertificateCheck(checkName, filter, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) *errors.Errors {
	return checkDN(d.Type, d.Cert.Subject.Names)
}

// Subject Distinguished Name Fields
func checkDN(vetting string, dn []pkix.AttributeTypeAndValue) *errors.Errors {
	var e = errors.New(nil)

	// OV & EV requirements
	if vetting == "OV" || vetting == "EV" {
		if !inDN(dn, organizationName) {
			e.Err("organizationName is required for %s certificates", vetting)
		}
	}

	// EV specific requirements
	if vetting == "EV" {
		if !inDN(dn, localityName) {
			e.Err("localityName is required for %s certificates", vetting)
		}
		if !inDN(dn, businessCategory) {
			e.Err("businessCategory is required for %s certificates", vetting)
		}
		if !inDN(dn, jurisdictionCountryName) {
			e.Err("jurisdictionCountryName is required for %s certificates", vetting)
		}
		if !inDN(dn, serialNumber) {
			e.Err("serialNumber is required for %s certificates", vetting)
		}
	}

	// Field related requirements
	for _, n := range dn {
		switch {

		// commonName
		// If present, this field MUST contain a single IP address or Fully‐Qualified Domain Name
		case n.Type.Equal(commonName):
			// TODO: Enable once you can simply ignore warnings
			//e.Warning("commonName field is deprecated")

		// surname
		// A Certificate containing a givenName field or surname field MUST contain
		// the (2.23.140.1.2.3) Certificate Policy OID.
		case n.Type.Equal(surname):
			// Prohibited
			if !inDN(dn, givenName) {
				e.Err("surname may only set in combination with givenName")
			}
			// Require field if surname is set
			if !inDN(dn, localityName) && !inDN(dn, stateOrProvinceName) {
				e.Err("localityName or stateOrProvinceName is required if surname is set")
			}

		// countryName
		case n.Type.Equal(countryName):
			// TODO: Check against the values in ISO 3166‐1
			if len(n.Value.(string)) != 2 {
				e.Err("countryName MUST contain the two-letter ISO 3166-1 country code")
			}

			// jurisdictionCountryName
		case n.Type.Equal(jurisdictionCountryName):
			// TODO: Check against the values in ISO 3166‐1
			if len(n.Value.(string)) != 2 {
				e.Err("jurisdictionCountryName MUST contain the two-letter ISO 3166-1 country code")
			}

		// localityName
		case n.Type.Equal(localityName):
			// Prohibited
			if !inDN(dn, organizationName) && !(inDN(dn, givenName) && inDN(dn, surname)) {
				e.Err("localityName is not allowed without organizationName or givenName and surname")
			}

		// stateOrProvinceName
		case n.Type.Equal(stateOrProvinceName):
			// Prohibited
			if !inDN(dn, organizationName) && !(inDN(dn, givenName) && inDN(dn, surname)) {
				e.Err("stateOrProvinceName is not allowed without organizationName or givenName and surname")
			}

		// streetAddress
		case n.Type.Equal(streetAddress):
			// Prohibited
			if !inDN(dn, organizationName) && !(inDN(dn, givenName) && inDN(dn, surname)) {
				e.Err("streetAddress is not allowed without organizationName or givenName and surname")
			}

		// postalCode
		case n.Type.Equal(postalCode):
			// Prohibited
			if !inDN(dn, organizationName) && !(inDN(dn, givenName) && inDN(dn, surname)) {
				e.Err("postalCode is not allowed without organizationName or givenName and surname")
			}

		// organizationName
		case n.Type.Equal(organizationName):
			// Require field if organizationName is set
			if !inDN(dn, localityName) && !inDN(dn, stateOrProvinceName) {
				e.Err("localityName or stateOrProvinceName is required if organizationName is set")
			}
			if !inDN(dn, stateOrProvinceName) {
				e.Err("stateOrProvinceName is required if organizationName is set")
			}
			if !inDN(dn, countryName) {
				e.Err("countryName is required if organizationName is set")
			}

		// organizationalUnitName
		case n.Type.Equal(organizationalUnitName):

		// businessCategory
		case n.Type.Equal(businessCategory):
			bc := n.Value.(string)
			if bc != "Private Organization" && bc != "Government Entity" && bc != "Business Entity" && bc != "Non-Commercial Entity" {
				e.Err("businessCategory should contain 'Private Organization', 'Government Entity', 'Business Entity', or 'Non-Commercial Entity'")
			}

		// serialNumber
		case n.Type.Equal(serialNumber):

		// givenName
		case n.Type.Equal(givenName):
			// Prohibited
			if !inDN(dn, surname) {
				e.Err("givenName may only set in combination with surname")
			}
		}
	}

	return e
}

func inDN(dn []pkix.AttributeTypeAndValue, attr asn1.ObjectIdentifier) bool {
	for _, n := range dn {
		if n.Type.Equal(attr) {
			return true
		}
	}
	return false
}
