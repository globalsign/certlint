package subject

import (
	"crypto/x509/pkix"
	"fmt"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
)

const checkName = "Subject Check"

func init() {
	filter := &checks.Filter{
		Type: []string{"DV", "OV", "IV", "EV"},
	}
	checks.RegisterCertificateCheck(checkName, filter, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
func Check(d *certdata.Data) []error {
	return checkDN(d.Type, d.Cert.Subject.Names)
}

// Subject Distinguished Name Fields
func checkDN(vetting string, dn []pkix.AttributeTypeAndValue) []error {
	var errors []error

	// Using a map to check if attributes are set
	var attr = make(map[string]bool, len(dn))
	for _, n := range dn {
		attr[n.Type.String()] = true
	}

	// OV & EV requirements
	if vetting == "OV" || vetting == "EV" {
		if !inMap(attr, organizationName) {
			errors = append(errors, fmt.Errorf("organizationName is required for %s certificates", vetting))
		}
	}

	// EV specific requirements
	if vetting == "EV" {
		if !inMap(attr, localityName) {
			errors = append(errors, fmt.Errorf("localityName is required for %s certificates", vetting))
		}
		if !inMap(attr, businessCategory) {
			errors = append(errors, fmt.Errorf("businessCategory is required for %s certificates", vetting))
		}
		if !inMap(attr, jurisdictionCountryName) {
			errors = append(errors, fmt.Errorf("jurisdictionCountryName is required for %s certificates", vetting))
		}
		if !inMap(attr, serialNumber) {
			errors = append(errors, fmt.Errorf("serialNumber is required for %s certificates", vetting))
		}
	}

	// Field related requirements
	for _, n := range dn {
		switch n.Type.String() {

		// commonName
		// If present, this field MUST contain a single IP address or Fully‐Qualified Domain Name
		case commonName:
			// TODO: Apply a warning via a custom error package
			//errors = append(errors, fmt.Errorf("commonName field is deprecated"))

		// surname
		// A Certificate containing a givenName field or surname field MUST contain
		// the (2.23.140.1.2.3) Certificate Policy OID.
		case surname:
			// Prohibited
			if !inMap(attr, givenName) {
				errors = append(errors, fmt.Errorf("surname may only set in combination with givenName"))
			}
			// Require field if surname is set
			if !inMap(attr, localityName) && !inMap(attr, stateOrProvinceName) {
				errors = append(errors, fmt.Errorf("localityName or stateOrProvinceName is required if surname is set"))
			}

		// countryName
		case countryName:
			// TODO: Check against the values in ISO 3166‐1
			if len(n.Value.(string)) != 2 {
				errors = append(errors, fmt.Errorf("countryName MUST contain the two-letter ISO 3166-1 country code"))
			}

			// jurisdictionCountryName
		case jurisdictionCountryName:
			// TODO: Check against the values in ISO 3166‐1
			if len(n.Value.(string)) != 2 {
				errors = append(errors, fmt.Errorf("jurisdictionCountryName MUST contain the two-letter ISO 3166-1 country code"))
			}

		// localityName
		case localityName:
			// Prohibited
			if !inMap(attr, organizationName) && !(inMap(attr, givenName) && inMap(attr, surname)) {
				errors = append(errors, fmt.Errorf("localityName is not allowed without organizationName or givenName and surname"))
			}

		// stateOrProvinceName
		case stateOrProvinceName:
			// Prohibited
			if !inMap(attr, organizationName) && !(inMap(attr, givenName) && inMap(attr, surname)) {
				errors = append(errors, fmt.Errorf("stateOrProvinceName is not allowed without organizationName or givenName and surname"))
			}

		// streetAddress
		case streetAddress:
			// Prohibited
			if !inMap(attr, organizationName) && !(inMap(attr, givenName) && inMap(attr, surname)) {
				errors = append(errors, fmt.Errorf("streetAddress is not allowed without organizationName or givenName and surname"))
			}

		// postalCode
		case postalCode:
			// Prohibited
			if !inMap(attr, organizationName) && !(inMap(attr, givenName) && inMap(attr, surname)) {
				errors = append(errors, fmt.Errorf("postalCode is not allowed without organizationName or givenName and surname"))
			}

		// organizationName
		case organizationName:
			// Require field if organizationName is set
			if !inMap(attr, localityName) && !inMap(attr, stateOrProvinceName) {
				errors = append(errors, fmt.Errorf("localityName or stateOrProvinceName is required if organizationName is set"))
			}
			if !inMap(attr, stateOrProvinceName) {
				errors = append(errors, fmt.Errorf("stateOrProvinceName is required if organizationName is set"))
			}
			if !inMap(attr, countryName) {
				errors = append(errors, fmt.Errorf("countryName is required if organizationName is set"))
			}

		// organizationalUnitName
		case organizationalUnitName:

		// businessCategory
		case businessCategory:
			bc := n.Value.(string)
			if bc != "Private Organization" && bc != "Government Entity" && bc != "Business Entity" && bc != "Non-Commercial Entity" {
				errors = append(errors, fmt.Errorf("businessCategory should contain 'Private Organization', 'Government Entity', 'Business Entity', or 'Non-Commercial Entity'"))
			}

		// serialNumber
		case serialNumber:

		// givenName
		case givenName:
			// Prohibited
			if !inMap(attr, surname) {
				errors = append(errors, fmt.Errorf("givenName may only set in combination with surname"))
			}
		}
	}

	return errors
}

func inMap(m map[string]bool, k string) bool {
	if _, ok := m[k]; ok {
		return true
	}
	return false
}
