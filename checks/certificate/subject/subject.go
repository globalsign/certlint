package subject

import (
	"crypto/x509/pkix"

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

	// Using a map to check if attributes are set
	var attr = make(map[string]bool, len(dn))
	for _, n := range dn {
		attr[n.Type.String()] = true
	}

	// OV & EV requirements
	if vetting == "OV" || vetting == "EV" {
		if !inMap(attr, organizationName) {
			e.Err("organizationName is required for %s certificates", vetting)
		}
	}

	// EV specific requirements
	if vetting == "EV" {
		if !inMap(attr, localityName) {
			e.Err("localityName is required for %s certificates", vetting)
		}
		if !inMap(attr, businessCategory) {
			e.Err("businessCategory is required for %s certificates", vetting)
		}
		if !inMap(attr, jurisdictionCountryName) {
			e.Err("jurisdictionCountryName is required for %s certificates", vetting)
		}
		if !inMap(attr, serialNumber) {
			e.Err("serialNumber is required for %s certificates", vetting)
		}
	}

	// Field related requirements
	for _, n := range dn {
		switch n.Type.String() {

		// commonName
		// If present, this field MUST contain a single IP address or Fully‐Qualified Domain Name
		case commonName:
			// TODO: Apply a warning via a custom error package
			//e.Err("commonName field is deprecated")

		// surname
		// A Certificate containing a givenName field or surname field MUST contain
		// the (2.23.140.1.2.3) Certificate Policy OID.
		case surname:
			// Prohibited
			if !inMap(attr, givenName) {
				e.Err("surname may only set in combination with givenName")
			}
			// Require field if surname is set
			if !inMap(attr, localityName) && !inMap(attr, stateOrProvinceName) {
				e.Err("localityName or stateOrProvinceName is required if surname is set")
			}

		// countryName
		case countryName:
			// TODO: Check against the values in ISO 3166‐1
			if len(n.Value.(string)) != 2 {
				e.Err("countryName MUST contain the two-letter ISO 3166-1 country code")
			}

			// jurisdictionCountryName
		case jurisdictionCountryName:
			// TODO: Check against the values in ISO 3166‐1
			if len(n.Value.(string)) != 2 {
				e.Err("jurisdictionCountryName MUST contain the two-letter ISO 3166-1 country code")
			}

		// localityName
		case localityName:
			// Prohibited
			if !inMap(attr, organizationName) && !(inMap(attr, givenName) && inMap(attr, surname)) {
				e.Err("localityName is not allowed without organizationName or givenName and surname")
			}

		// stateOrProvinceName
		case stateOrProvinceName:
			// Prohibited
			if !inMap(attr, organizationName) && !(inMap(attr, givenName) && inMap(attr, surname)) {
				e.Err("stateOrProvinceName is not allowed without organizationName or givenName and surname")
			}

		// streetAddress
		case streetAddress:
			// Prohibited
			if !inMap(attr, organizationName) && !(inMap(attr, givenName) && inMap(attr, surname)) {
				e.Err("streetAddress is not allowed without organizationName or givenName and surname")
			}

		// postalCode
		case postalCode:
			// Prohibited
			if !inMap(attr, organizationName) && !(inMap(attr, givenName) && inMap(attr, surname)) {
				e.Err("postalCode is not allowed without organizationName or givenName and surname")
			}

		// organizationName
		case organizationName:
			// Require field if organizationName is set
			if !inMap(attr, localityName) && !inMap(attr, stateOrProvinceName) {
				e.Err("localityName or stateOrProvinceName is required if organizationName is set")
			}
			if !inMap(attr, stateOrProvinceName) {
				e.Err("stateOrProvinceName is required if organizationName is set")
			}
			if !inMap(attr, countryName) {
				e.Err("countryName is required if organizationName is set")
			}

		// organizationalUnitName
		case organizationalUnitName:

		// businessCategory
		case businessCategory:
			bc := n.Value.(string)
			if bc != "Private Organization" && bc != "Government Entity" && bc != "Business Entity" && bc != "Non-Commercial Entity" {
				e.Err("businessCategory should contain 'Private Organization', 'Government Entity', 'Business Entity', or 'Non-Commercial Entity'")
			}

		// serialNumber
		case serialNumber:

		// givenName
		case givenName:
			// Prohibited
			if !inMap(attr, surname) {
				e.Err("givenName may only set in combination with surname")
			}
		}
	}

	return e
}

func inMap(m map[string]bool, k string) bool {
	if _, ok := m[k]; ok {
		return true
	}
	return false
}
