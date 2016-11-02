package checks

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
	"sync"

	"github.com/globalsign/certlint/certdata"
)

var extMutex = &sync.Mutex{}

type extentions []extentionCheck

type extentionCheck struct {
	name   string
	oid    asn1.ObjectIdentifier
	filter *Filter
	f      func(pkix.Extension, *certdata.Data) []error
}

// Extentions contains all imported extention checks
var Extentions extentions

// RegisterExtentionCheck adds a new check to Extentions
func RegisterExtentionCheck(name string, oid asn1.ObjectIdentifier, filter *Filter, f func(pkix.Extension, *certdata.Data) []error) {
	extMutex.Lock()
	Extentions = append(Extentions, extentionCheck{name, oid, filter, f})
	extMutex.Unlock()
}

// Check lookups the registered extention checks and runs all checks with the
// same Object Identifier.
func (e extentions) Check(ext pkix.Extension, d *certdata.Data) []error {
	var errors []error
	var found bool

	for _, ec := range e {
		if ec.oid.Equal(ext.Id) {
			found = true
			if ec.filter != nil && ec.filter.Check(d) {
				continue
			}
			errors = append(errors, ec.f(ext, d)...)
		}
	}

	if !found {
		// Don't report private enterprise extensions as unknown, registered private
		// extentions have still been checked above.
		if !strings.HasPrefix(ext.Id.String(), "1.3.6.1.4.1.") {
			errors = append(errors, fmt.Errorf("Certificate contains unknown extension (%s)", ext.Id.String()))
		}
	}

	return errors
}
