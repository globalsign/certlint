package checks

import (
	"sync"

	"github.com/globalsign/certlint/certdata"
)

var certMutex = &sync.Mutex{}

type certificate []certificateCheck

type certificateCheck struct {
	name   string
	filter *Filter
	f      func(*certdata.Data) []error
}

// Certificate contains all imported certificate checks
var Certificate certificate

// RegisterCertificateCheck adds a new check to Cerificates
func RegisterCertificateCheck(name string, filter *Filter, f func(*certdata.Data) []error) {
	certMutex.Lock()
	Certificate = append(Certificate, certificateCheck{name, filter, f})
	certMutex.Unlock()
}

// Check runs all the registered certificate checks
func (c certificate) Check(d *certdata.Data) []error {
	var errors []error

	for _, cc := range c {
		if cc.filter != nil && cc.filter.Check(d) {
			continue
		}
		errors = append(errors, cc.f(d)...)
	}

	return errors
}
