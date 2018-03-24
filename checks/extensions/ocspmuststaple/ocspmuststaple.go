package ocspmuststaple

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "OCSP Must Staple Extension Check"

// See RFC 7633
var extensionOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

func init() {
	checks.RegisterExtensionCheck(checkName, extensionOid, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(ex pkix.Extension, d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	// RFC 7633 only defines this extension for PKIX end-entity certificates,
	// certificate signing requests, and certificate signing certificates (CAs)
	if d.Type == "OCSP" {
		e.Err("OCSP Must Staple extension set in non end-entity/issuer certificate")
	}

	// Per RFC 7633 "The TLS feature extension SHOULD NOT be marked critical"
	if ex.Critical {
		e.Err("OCSP Must Staple extension set critical")
	}

	return e
}
