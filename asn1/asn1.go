package asn1

import (
	"encoding/asn1"
	"fmt"

	"github.com/globalsign/certlint/errors"
)

// CheckStruct returns a list of errors based on strict checks on the raw ASN1
// encoding of the input der.
func CheckStruct(der []byte) *errors.Errors {
	return walk(der, "")
}

// walk is a recursive call that walks over the ASN1 structured data until no
// remaining bytes are left. For each non compound is will call the ASN1 format
// checker.
func walk(der []byte, path string) *errors.Errors {
	var e = errors.New(nil)
	var err error
	var sequence int

	for len(der) > 0 {
		sequence++
		d := asn1.RawValue{}
		der, err = asn1.Unmarshal(der, &d)
		if err != nil {
			// Errors should be included in the report, but allow format checking when
			// data has been decoded.
			e.Err(err.Error())
			if len(d.Bytes) == 0 {
				return e
			}
		}

		// A compound is an ASN.1 container that contains other structs.
		if d.IsCompound {
			e.Append(walk(d.Bytes, fmt.Sprintf("%s.%d", path, sequence)))
		} else {
			e.Append(CheckFormat(d))
		}
	}

	return e
}
