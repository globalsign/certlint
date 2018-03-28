package ocspmuststaple

import (
	"crypto/x509/pkix"
	"testing"

	"github.com/globalsign/certlint/certdata"
)

// TestCheck tests the OCSP Must Staple extension Check() behaves as expected
// with valid/invalid testcases.
func TestCheck(t *testing.T) {
	// Valid OCSP Must Staple Extension.
	validExtension := pkix.Extension{
		Id:       extensionOid,
		Value:    expectedExtensionValue,
		Critical: false,
	}
	// Invalid OCSP Must Staple Extension: Critical field set to `true`.
	criticalExtension := pkix.Extension{
		Id:       extensionOid,
		Value:    expectedExtensionValue,
		Critical: true,
	}
	// Invalid OCSP Must Staple Extension: Wrong value.
	wrongValueExtension := pkix.Extension{
		Id:       extensionOid,
		Value:    []uint8{0xC0, 0xFF, 0xEE},
		Critical: false,
	}
	// Invalid OCSP Must Staple Extension: Wrong value, Critical field set to
	// `true`
	wrongValueExtensionCritical := pkix.Extension{
		Id:       extensionOid,
		Value:    []uint8{0xC0, 0xFF, 0xEE},
		Critical: true,
	}

	testCases := []struct {
		Name           string
		InputEx        pkix.Extension
		CertType       string
		ExpectedErrors []string
	}{
		{
			Name:           "Valid: DV cert type",
			InputEx:        validExtension,
			CertType:       "DV",
			ExpectedErrors: []string{},
		},
		{
			Name:           "Valid: OV cert type",
			InputEx:        validExtension,
			CertType:       "DV",
			ExpectedErrors: []string{},
		},
		{
			Name:           "Valid: EV cert type",
			InputEx:        validExtension,
			CertType:       "DV",
			ExpectedErrors: []string{},
		},
		{
			Name:           "Valid: CA cert type",
			InputEx:        validExtension,
			CertType:       "CA",
			ExpectedErrors: []string{},
		},
		{
			Name:     "Invalid: OCSP cert type",
			InputEx:  validExtension,
			CertType: "OCSP",
			ExpectedErrors: []string{
				certTypeErr,
			},
		},
		{
			Name:           "Invalid: critical extension",
			InputEx:        criticalExtension,
			CertType:       "DV",
			ExpectedErrors: []string{critExtErr},
		},
		{
			Name:     "Invalid: critical extension, OCSP cert type",
			InputEx:  criticalExtension,
			CertType: "OCSP",
			ExpectedErrors: []string{
				certTypeErr, critExtErr,
			},
		},
		{
			Name:     "Invalid: wrong extension value",
			InputEx:  wrongValueExtension,
			CertType: "DV",
			ExpectedErrors: []string{
				extValueErr,
			},
		},
		{
			Name:     "Invalid: wrong extension value, critical extension, OCSP cert type",
			InputEx:  wrongValueExtensionCritical,
			CertType: "OCSP",
			ExpectedErrors: []string{
				certTypeErr, critExtErr, extValueErr,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			certData := &certdata.Data{
				Type: tc.CertType,
			}
			// Run the OCSP Must Staple check on the test data
			errors := Check(tc.InputEx, certData)
			// Collect the returned errors into a list
			errList := errors.List()
			// Verify the expected number of errors are in the list
			if len(tc.ExpectedErrors) != len(errList) {
				t.Errorf("wrong number of Check errors: expected %d, got %d\n",
					len(tc.ExpectedErrors), len(errList))
			} else {
				// Match the error list to the expected error list
				for i, err := range errList {
					if errMsg := err.Error(); errMsg != tc.ExpectedErrors[i] {
						t.Errorf("expected error %q at index %d, got %q",
							tc.ExpectedErrors[i], i, errMsg)
					}
				}
			}
		})
	}
}
