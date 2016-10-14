// A command line utility that uses the certlint library to validate one or more
// certificates.
//
// See the examples directory for other use cases.

package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/globalsign/certlint/asn1"
	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"

	// Import all availible checks
	_ "github.com/globalsign/certlint/checks/certificate/all"
	_ "github.com/globalsign/certlint/checks/extentions/all"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
)

type testResult struct {
	Type   string
	Cert   *x509.Certificate
	Pem    string
	Errors []error
}

var jobs = make(chan []byte, 100)
var results = make(chan testResult, 100)
var count int64

func main() {
	var cert = flag.String("cert", "", "Certificate file")
	var bulk = flag.String("bulk", "", "Bulk certificates file")
	var issuer = flag.String("issuer", "", "Certificate file")
	var expired = flag.Bool("expired", false, "Test expired certificates")
	var report = flag.String("report", "report.csv", "Report filename")
	var include = flag.Bool("include", false, "Include certificates in report")
	var help = flag.Bool("help", false, "Show this help")

	flag.Parse()

	if *help || (len(*cert) < 1 && len(*bulk) < 1) {
		flag.PrintDefaults()
		return
	}

	// Prevent CloudFlare informational log messages
	log.Level = log.LevelError

	// Start the bulk checking logic to parse a pem file with more certificates and
	// save the results to a csv file.
	if len(*bulk) > 0 {
		for i := 1; i <= 5; i++ {
			go runBulk(*expired)
		}
		go saveResults(*report, *include)
		doBulk(*bulk)
		return
	}

	// Check one certificate and print results on screen
	der := getCertificate(*cert)
	result := do(der, issuer, *expired, true)

	if len(result.Errors) > 0 {
		fmt.Println("Certificate Type:", result.Type)
		for _, err := range result.Errors {
			fmt.Println(err)
		}
	}
}

// do performs the checks on the der encoding and the actual certificate, if exp
// is set true it will also check expired certificates.
func do(der []byte, issuer *string, exp, rtrn bool) testResult {
	var result testResult

	// Include pem in results for debugging
	result.Pem = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}))

	// This causes that we check every certificate, even expired certificates
	structErrors := asn1.CheckStruct(der)
	if len(structErrors) > 0 {
		result.Errors = append(result.Errors, structErrors...)
	}

	// Load certificate
	d, err := certdata.Load(der)
	if err != nil {
		result.Errors = append(result.Errors, err)
	} else {
		result.Cert = d.Cert
		result.Type = d.Type

		// Indication to not check this type of certificate
		if d.Type == "-" {
			return result
		}

		// Check if we need to skip expied certificates
		if !exp && d.Cert.NotAfter.Before(time.Now()) {
			return result
		}

		// If we have the issuer certificate verify the raw issuer struct and signatures
		if issuer != nil && len(*issuer) > 0 {
			d.SetIssuer(getCertificate(*issuer))
		}

		// Check against errors
		testErrors := checks.Certificate.Check(d)
		if len(testErrors) > 0 {
			result.Errors = append(result.Errors, testErrors...)
		}
	}

	// In batch mode we want to queue results
	if !rtrn && len(result.Errors) > 0 {
		results <- result
	}

	return result
}

func doBulk(bulk string) {
	var pemCert []byte

	f, err := os.Open(bulk)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Unfortunatly pem.Decode can't use a io.Reader but exspects a byte array
	// the files we want to support are to big to load in memory.
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()

		// "-BEGIN CERTIFICATE-"
		if bytes.Contains(line, []byte{0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d}) {
			pemCert = []byte{}
		}

		pemCert = append(pemCert, []byte{0xa}...)
		pemCert = append(pemCert, line...)

		// Check last line for "-END CERTIFICATE-"
		if bytes.Contains(line, []byte{0x2d, 0x45, 0x4e, 0x44, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d}) {
			block, _ := pem.Decode(pemCert)
			if block != nil {
				count++
				jobs <- block.Bytes
			} else {
				results <- testResult{
					Cert:   nil,
					Pem:    string(pemCert),
					Errors: []error{err},
				}
			}
		}
	}

	fmt.Printf("Checked %d certificates\n", count)
	close(jobs)
}

func runBulk(exp bool) {
	for {
		der, more := <-jobs
		if more {
			do(der, nil, exp, false)
		} else {
			break
		}
	}
}

func saveResults(filename string, include bool) error {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	writer.UseCRLF = true
	writer.Write([]string{"Issuer", "CN", "O", "Serial", "Type", "Error", "Revoked", "Cert"})
	writer.Flush()

	for {
		r, more := <-results
		if more {
			for _, e := range r.Errors {
				if e == nil {
					continue
				}
				var columns []string
				if r.Cert != nil {
					columns = []string{
						fmt.Sprintf("%s, %s", r.Cert.Issuer.CommonName, r.Cert.Issuer.Organization),
						r.Cert.Subject.CommonName,
						strings.Join(r.Cert.Subject.Organization, ", "),
						fmt.Sprintf("%x", r.Cert.SerialNumber),
						r.Type,
						e.Error(),
					}

					// Is this certificate revoked?
					if revoked, ok := revoke.VerifyCertificate(r.Cert); ok {
						columns = append(columns, fmt.Sprintf("%t", revoked))
					} else {
						columns = append(columns, "failed")
					}

					// Do we need to include the certificate
					if include {
						columns = append(columns, r.Pem)
					} else {
						columns = append(columns, "")
					}

				} else {
					columns = []string{"", "", "", "", "", e.Error(), "", r.Pem}
				}

				err := writer.Write(columns)
				if err != nil {
					fmt.Println(err)
					continue
				}

				writer.Flush()
			}
		} else {
			break
		}
	}
	return nil
}

// getCertificate reads a single certificate from disk
func getCertificate(file string) []byte {
	derBytes, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	// decode pem
	block, _ := pem.Decode(derBytes)
	if block != nil {
		derBytes = block.Bytes
	}
	return derBytes
}
