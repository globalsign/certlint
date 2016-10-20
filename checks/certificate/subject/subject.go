package subject

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
)

const checkName = "Subject Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extention according to the standard(s)
func Check(d *certdata.Data) []error {
	return checkDN(d.Type, d.Cert.Subject.Names)
}

// Subject Distinguished Name Fields
func checkDN(vetting string, dn []pkix.AttributeTypeAndValue) []error {
	var errors []error

	// OV & EV requirements
	if vetting == "OV" || vetting == "EV" {
		if !inDN(dn, organizationName) {
			errors = append(errors, fmt.Errorf("organizationName is required for %s certificates", vetting))
		}
	}

	// EV specific requirements
	if vetting == "EV" {
		if !inDN(dn, localityName) {
			errors = append(errors, fmt.Errorf("localityName is required for %s certificates", vetting))
		}
		if !inDN(dn, businessCategory) {
			errors = append(errors, fmt.Errorf("businessCategory is required for %s certificates", vetting))
		}
		if !inDN(dn, jurisdictionCountryName) {
			errors = append(errors, fmt.Errorf("jurisdictionCountryName is required for %s certificates", vetting))
		}
		if !inDN(dn, serialNumber) {
			errors = append(errors, fmt.Errorf("serialNumber is required for %s certificates", vetting))
		}
	}

	// Field related requirements
	for _, n := range dn {
		// Check all values for '-', '.', etc,

		switch true {

		// commonName
		// If present, this field MUST contain a single IP address or Fully‐Qualified Domain Name
		case n.Type.Equal(commonName):
			// TODO: Apply a warning via a custom error package
			//errors = append(errors, fmt.Errorf("commonName field is deprecated"))

		// surname
		// A Certificate containing a givenName field or surname field MUST contain
		// the (2.23.140.1.2.3) Certificate Policy OID.
		case n.Type.Equal(surname):
			// Prohibited
			if !inDN(dn, givenName) {
				errors = append(errors, fmt.Errorf("surname may only set in combination with givenName"))
			}
			// Require field if surname is set
			if !inDN(dn, localityName) && !inDN(dn, stateOrProvinceName) {
				errors = append(errors, fmt.Errorf("localityName or stateOrProvinceName is required if surname is set"))
			}

		// countryName
		case n.Type.Equal(countryName):
			// TODO: Check against the values in ISO 3166‐1
			if len(n.Value.(string)) != 2 {
				errors = append(errors, fmt.Errorf("countryName MUST contain the two‐letter ISO 3166‐1 country code"))
			}

			// jurisdictionCountryName
		case n.Type.Equal(jurisdictionCountryName):
			// TODO: Check against the values in ISO 3166‐1
			if len(n.Value.(string)) != 2 {
				errors = append(errors, fmt.Errorf("jurisdictionCountryName MUST contain the two‐letter ISO 3166‐1 country code"))
			}

		// localityName
		case n.Type.Equal(localityName):
			// Prohibited
			if !inDN(dn, organizationName) && !(inDN(dn, givenName) && inDN(dn, surname)) {
				errors = append(errors, fmt.Errorf("localityName is not allowed without organizationName or givenName and surname"))
			}

		// stateOrProvinceName
		case n.Type.Equal(stateOrProvinceName):
			// Prohibited
			if !inDN(dn, organizationName) && !(inDN(dn, givenName) && inDN(dn, surname)) {
				errors = append(errors, fmt.Errorf("stateOrProvinceName is not allowed without organizationName or givenName and surname"))
			}

		// streetAddress
		case n.Type.Equal(streetAddress):
			// Prohibited
			if !inDN(dn, organizationName) && !(inDN(dn, givenName) && inDN(dn, surname)) {
				errors = append(errors, fmt.Errorf("streetAddress is not allowed without organizationName or givenName and surname"))
			}

		// postalCode
		case n.Type.Equal(postalCode):
			// Prohibited
			if !inDN(dn, organizationName) && !(inDN(dn, givenName) && inDN(dn, surname)) {
				errors = append(errors, fmt.Errorf("postalCode is not allowed without organizationName or givenName and surname"))
			}

		// organizationName
		case n.Type.Equal(organizationName):
			// Require field if organizationName is set
			if !inDN(dn, localityName) && !inDN(dn, stateOrProvinceName) {
				errors = append(errors, fmt.Errorf("localityName or stateOrProvinceName is required if organizationName is set"))
			}
			if !inDN(dn, stateOrProvinceName) {
				errors = append(errors, fmt.Errorf("stateOrProvinceName is required if organizationName is set"))
			}
			if !inDN(dn, countryName) {
				errors = append(errors, fmt.Errorf("countryName is required if organizationName is set"))
			}

		// organizationalUnitName
		case n.Type.Equal(organizationalUnitName):

		// businessCategory
		case n.Type.Equal(businessCategory):
			bc := n.Value.(string)
			if bc != "Private Organization" && bc != "Government Entity" && bc != "Business Entity" && bc != "Non-Commercial Entity" {
				errors = append(errors, fmt.Errorf("businessCategory should contain 'Private Organization', 'Government Entity', 'Business Entity', or 'Non-Commercial Entity'"))
			}

		// serialNumber
		case n.Type.Equal(serialNumber):

		// givenName
		case n.Type.Equal(givenName):
			// Prohibited
			if !inDN(dn, surname) {
				errors = append(errors, fmt.Errorf("givenName may only set in combination with surname"))
			}
		}
	}

	return errors
}

// inDN check if a specific oid is included in the given DN
func inDN(dn []pkix.AttributeTypeAndValue, oid asn1.ObjectIdentifier) bool {
	for _, n := range dn {
		if n.Type.Equal(oid) {
			return true
		}
	}
	return false
}
