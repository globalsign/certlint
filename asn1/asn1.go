package asn1

import (
	"encoding/asn1"
	"fmt"
)

// CheckStruct returns a list of errors based on strict checks on the raw ASN1
// encoding of the input der.
func CheckStruct(der []byte) []error {
	return walk(der, "")
}

// walk is a recursive call that walks over the ASN1 structured data until no
// remaining bytes are left. For each non compound is will call the ASN1 format
// checker.
func walk(der []byte, path string) []error {
	var err error
	var errors []error
	var sequence int

	for len(der) > 0 {
		sequence++
		d := asn1.RawValue{}
		der, err = asn1.Unmarshal(der, &d)
		if err != nil {
			// Errors should be included in the report, but allow format checking when
			// data has been decoded.
			errors = append(errors, err)
			if len(d.Bytes) == 0 {
				return errors
			}
		}

		// A compound is an ASN.1 container that contains other structs.
		if d.IsCompound {
			errors = append(errors, walk(d.Bytes, fmt.Sprintf("%s.%d", path, sequence))...)
		} else {
			errors = append(errors, CheckFormat(d)...)
		}
	}

	return errors
}
