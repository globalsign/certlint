package asn1

import (
	"bytes"
	"encoding/asn1"
	"regexp"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/globalsign/certlint/errors"
)

// RFC 5280 4.1.2.5.1: UTCTime MUST include seconds, even when 00
var formatUTCTime = regexp.MustCompile("^([0-9]{2})([01][0-9])([0-3][0-9])([012][0-9])([0-5][0-9]){2}Z$")
var formatGeneralizedTime = regexp.MustCompile("^([0-9]{4})([01][0-9])([0-3][0-9])([012][0-9])([0-5][0-9]){2}Z$")

// CheckFormat returns a list of formatting errors based on the expected ASN1
// encoding according to the class and tag of the raw value.
// TODO: Create checks for remaining class 0 tags
// TODO: Should we create extensions for other classes, even include class 0?
func CheckFormat(d asn1.RawValue) *errors.Errors {
	var e = errors.New(nil)

	if d.Class == 0 {
		switch d.Tag {
		case 0: // "reserved for BER"
		case 1: // "BOOLEAN"
		case 2: // "INTEGER"
		case 3: // "BIT STRING"
		case 4: // "OCTET STRING"
		case 5: // "NULL"
		case 6: // "OBJECT IDENTIFIER"
		case 7: // "ObjectDescriptor"
		case 8: // "INSTANCE OF, EXTERNAL"
		case 9: // "REAL"
		case 10: // "ENUMERATED"
		case 11: // "EMBEDDED PDV"
		case 12: // "UTF8String"
			if !utf8.Valid(d.Bytes) {
				e.Err("Invalid UTF8 encoding in UTF8String")
			}
			if isForbiddenString(d.Bytes) {
				e.Err("Forbidden value in UTF8String '%s'", string(d.Bytes))
			}
			if isControlCharacter(d.Bytes) {
				e.Err("Control character in UTF8String '%s'", string(d.Bytes))
			}
		case 13: // "RELATIVE-OID"
		case 16: // "SEQUENCE, SEQUENCE OF"
		case 17: // "SET, SET OF"
		case 18: // "NumericString"
			if !isNumericString(d.Bytes) {
				e.Err("Invalid character in NumericString '%s'", string(d.Bytes))
			}
		case 19: // "PrintableString"
			for _, b := range d.Bytes {
				if !isPrintable(b) {
					e.Err("Invalid character in PrintableString '%s'", string(d.Bytes))
				}
			}
			if isForbiddenString(d.Bytes) {
				e.Err("Forbidden value in PrintableString '%s'", string(d.Bytes))
			}
		case 20: // "TeletexString, T61String"
			e.Warning("Using depricated TeletexString for '%s'", string(d.Bytes))
			if isForbiddenString(d.Bytes) {
				e.Err("Forbidden value in TeletexString '%s'", string(d.Bytes))
			}
			if isControlCharacter(d.Bytes) {
				e.Err("Control character in TeletexString '%s'", string(d.Bytes))
			}
		case 21: // "VideotexString"
			e.Warning("Using depricated VideotexString for '%s'", string(d.Bytes))
			if isForbiddenString(d.Bytes) {
				e.Err("Forbidden value in VideotexString '%s'", string(d.Bytes))
			}
			if isControlCharacter(d.Bytes) {
				e.Err("Control character in VideotexString '%s'", string(d.Bytes))
			}
		case 22: // "IA5String"
			if !isIA5String(d.Bytes) {
				e.Err("Invalid character in IA5String '%s'", string(d.Bytes))
			}
			if isForbiddenString(d.Bytes) {
				e.Err("Forbidden value in IA5String '%s'", string(d.Bytes))
			}

		case 23: // "UTCTime"
			// RFC 5280 4.1.2.5: times must be in Z (GMT)
			if !bytes.HasSuffix(d.Bytes, []byte{90}) {
				e.Err("UTCTime not in Zulu/GMT")
			}
			if !formatUTCTime.Match(d.Bytes) {
				e.Err("Invalid UTCTime")
			}
		case 24: // "GeneralizedTime"
			var v time.Time
			_, err := asn1.Unmarshal(d.FullBytes, &v)
			if err != nil {
				e.Err("Failed to parse Generalized Time: %s", err.Error())
			}

			// RFC 5280 4.1.2.5: times must be in Z (GMT)
			if !bytes.HasSuffix(d.Bytes, []byte{90}) {
				e.Err("Generalized Time not in Zulu/GMT")
			}
			// TODO: Can we use binary.BigEndian.Varint(d.Bytes[0:3]), for better performance?
			if v.Year() < 2050 {
				e.Err("Generalized Time before 2050")
			}

			if !formatGeneralizedTime.Match(d.Bytes) {
				e.Err("Invalid Generalized Time")
			}

		case 25: // "GraphicString"
			e.Warning("Using depricated GraphicString for '%s'", string(d.Bytes))
			if isForbiddenString(d.Bytes) {
				e.Err("Forbidden value in GraphicString '%s'", string(d.Bytes))
			}
			if isControlCharacter(d.Bytes) {
				e.Err("Control character in GraphicString '%s'", string(d.Bytes))
			}
		case 26: // "VisibleString, ISO646String"
		case 27: // "GeneralString"
			e.Warning("Using depricated GeneralString for '%s'", string(d.Bytes))
			if isForbiddenString(d.Bytes) {
				e.Err("Forbidden value in GeneralString '%s'", string(d.Bytes))
			}
			if isControlCharacter(d.Bytes) {
				e.Err("Control character in GeneralString '%s'", string(d.Bytes))
			}
		case 28: // "UniversalString"
			e.Warning("Using depricated UniversalString for '%s'", string(d.Bytes))
			if isForbiddenString(d.Bytes) {
				e.Err("Forbidden value in UniversalString '%s'", string(d.Bytes))
			}
			if isControlCharacter(d.Bytes) {
				e.Err("Control character in UniversalString '%s'", string(d.Bytes))
			}
		case 29: // "CHARACTER STRING"
		case 30: // "BMPString"
			e.Warning("Using depricated BMPString for '%s'", string(d.Bytes))
			if isForbiddenString(d.Bytes) {
				e.Err("Forbidden value in BMPString '%s'", string(d.Bytes))
			}
			if isControlCharacter(d.Bytes) {
				e.Err("Control character in BMPString '%s'", string(d.Bytes))
			}
		}
	}

	return e
}

// Version of isPrintable without allowing a *
// Source: https://golang.org/src/encoding/asn1/asn1.go
func isPrintable(b byte) bool {
	return 'a' <= b && b <= 'z' ||
		'A' <= b && b <= 'Z' ||
		'0' <= b && b <= '9' ||
		'\'' <= b && b <= ')' ||
		'+' <= b && b <= '/' ||
		b == ' ' ||
		b == ':' ||
		b == '=' ||
		b == '?'
}

// Range from: http://www.zytrax.com/tech/ia5.html
func isIA5String(b []byte) bool {
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r < 0 || r > 127 {
			return false
		}
		b = b[size:]
	}
	return true
}

// 	1, 2, 3, 4, 5, 6, 7, 8, 9, 0, and SPACE
func isNumericString(b []byte) bool {
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if !unicode.IsNumber(r) && !unicode.IsSpace(r) {
			return false
		}
		b = b[size:]
	}
	return true
}

// The BR state that attributes MUST NOT contain metadata such as '.', '-', ' ',
// this check implements a structure wide validation for values that indication
// that the field is absent, incomplete, or not applicable.
func isForbiddenString(b []byte) bool {
	if len(b) != 1 {
		return false
	}
	if b[0] == '.' || b[0] == '-' || b[0] == ' ' || b[0] == '_' {
		return true
	}
	return false
}

// isControlCharacter checks if Control characters are included in the given bytes
func isControlCharacter(b []byte) bool {
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if unicode.IsControl(r) || unicode.Is(unicode.C, r) {
			return true
		}
		b = b[size:]
	}
	return false
}
