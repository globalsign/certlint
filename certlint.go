// A command line utility that uses the certlint library to validate one or more
// certificates.
//
// See the examples directory for other use cases.

package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/globalsign/certlint/asn1"
	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"

	// Import all available checks
	_ "github.com/globalsign/certlint/checks/certificate/all"
	_ "github.com/globalsign/certlint/checks/extensions/all"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/golang/groupcache/lru"

	"github.com/pkg/profile"
)

type testResult struct {
	Type    string
	Trusted bool
	Cert    *x509.Certificate
	Pem     string
	Der     []byte
	Errors  *errors.Errors
}

var jobs = make(chan []byte, 100)
var results = make(chan testResult, 100)
var count int64
var saved int64
var wgSave sync.WaitGroup
var wgBulk sync.WaitGroup
var intPool *x509.CertPool
var trusted bool

func main() {
	var cert = flag.String("cert", "", "Certificate file")
	var bulk = flag.String("bulk", "", "Bulk certificates file")
	var issuer = flag.String("issuer", "", "Pem file with one or more issuers")
	var expired = flag.Bool("expired", false, "Test expired certificates")
	var report = flag.String("report", "report.csv", "Report filename")
	var include = flag.Bool("include", false, "Include certificates in report")
	var revoked = flag.Bool("revoked", false, "Check if certificates are revoked")
	trusted = *flag.Bool("trusted", false, "Only check trusted certificates")
	var pprof = flag.String("pprof", "", "Generate pprof profile (cpu,mem,trace)")
	var help = flag.Bool("help", false, "Show this help")

	flag.Parse()

	if *help || (len(*cert) < 1 && len(*bulk) < 1) {
		flag.PrintDefaults()
		return
	}

	// Is any profiling requested?
	switch *pprof {
	case "cpu":
		defer profile.Start(profile.CPUProfile).Stop()
	case "mem":
		defer profile.Start(profile.MemProfile).Stop()
	case "trace":
		defer profile.Start(profile.TraceProfile).Stop()
	default:
		// pprof disabled
	}

	// Prevent CloudFlare informational log messages
	log.Level = log.LevelError

	// Load intermediates
	if len(*issuer) > 0 {
		data, err := ioutil.ReadFile(*issuer)
		if err != nil {
			log.Fatal("Failed to load intermediates:", err)
		}
		intPool = x509.NewCertPool()
		intPool.AppendCertsFromPEM(data)
	}

	// Start the bulk checking logic to parse a pem file with more certificates and
	// save the results to a csv file.
	if len(*bulk) > 0 {
		wgSave.Add(1)
		go saveResults(*report, *include, *revoked)

		for i := 1; i <= runtime.NumCPU(); i++ {
			wgBulk.Add(1)
			go runBulk(*expired)
		}

		doBulk(*bulk)

		fmt.Println("Finshed reading bulk file, waiting for processing to finish")
		wgBulk.Wait()

		close(results)

		fmt.Println("Processing finished, waiting till all results are saved")
		wgSave.Wait()

		return
	}

	// Check one certificate and print results on screen
	der := getCertificate(*cert)
	result := do(nil, der, *expired, true)

	fmt.Println("Processed Certificate Type:", result.Type)
	if result.Errors != nil {
		fmt.Printf("Certificate Errors: %v\n", len(result.Errors.List()))
		for _, err := range result.Errors.List() {
			fmt.Printf("  Priority: %s, Message: %v\n", err.Priority(), err)
		}
		if result.Errors.Priority() > errors.Warning {
			os.Exit(1)
		}
	}
}

// do performs the checks on the der encoding and the actual certificate, if exp
// is set true it will also check expired certificates.
func do(icaCache *lru.Cache, der []byte, exp, rtrn bool) testResult {
	// use a local cache to prevent that we need to wait on a local
	var result testResult
	result.Errors = errors.New(nil)

	// Include der in results for debugging
	result.Der = der

	// This causes that we check every certificate, even expired certificates
	al := new(asn1.Linter)
	result.Errors.Append(al.CheckStruct(der))

	// Load certificate
	d, err := certdata.Load(der)
	if err != nil {
		result.Errors.Err(err.Error())
	} else {
		result.Trusted = true
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

		// Check if this is a publicly trusted certificate
		opts := x509.VerifyOptions{
			CurrentTime:   d.Cert.NotBefore,
			Intermediates: intPool,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		chain, err := d.Cert.Verify(opts)
		if err == nil && len(chain) > 0 && len(chain[0]) > 1 {
			d.Issuer = chain[0][1]

		} else {
			// Issuer not in default pool, use issuer from AIA cache, download if
			// not in cache and when certificate has not expired.
			pool := intPool
			type issuerCache struct {
				Trusted bool
				Issuer  *x509.Certificate
				Pool    *x509.CertPool
			}

			var key string

			// Create a unique ID to cache the chain of this issuer
			if len(d.Cert.IssuingCertificateURL) > 0 {
				// Same issuer can have multiple issuing URL's (cross certificates), we
				// want to test with the provided information
				key = fmt.Sprintf("%x", sha1.Sum([]byte(fmt.Sprint(d.Cert.IssuingCertificateURL))))

			} else if len(d.Cert.AuthorityKeyId) > 0 {
				// If no issuer is given we use the AuthorityKeyId to identify the chain
				key = fmt.Sprintf("%x", d.Cert.AuthorityKeyId)

			} else {
				// If we also have no AKI the only thing left is the raw DN of the issuer
				key = fmt.Sprintf("%x", sha1.Sum(d.Cert.RawIssuer))
			}

			// try to get from lru cache
			var cache interface{}
			var ok bool

			if icaCache != nil {
				cache, ok = icaCache.Get(key)
			}
			if ok {
				ic := cache.(issuerCache)
				result.Trusted = ic.Trusted
				d.Issuer = ic.Issuer
				pool = ic.Pool

			} else {
				var e = errors.New(nil)
				d.Issuer, pool, e = getIssuerPool(d.Cert)
				result.Errors.Append(e)

				// Check if this is a publicly trusted certificate
				opts := x509.VerifyOptions{
					CurrentTime:   d.Cert.NotBefore,
					Intermediates: pool,
					KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
				}
				if chain, err = d.Cert.Verify(opts); err != nil {
					result.Trusted = false
				}

				// Save pool in cache
				if pool != nil && icaCache != nil {
					icaCache.Add(key, issuerCache{result.Trusted, d.Issuer, pool})
				}
			}
		}

		if trusted && !result.Trusted {
			fmt.Printf("Failed to verify chain for %s\n", d.Cert.Issuer.CommonName)
			result.Errors.Err("Failed to verify chain for %s\n", d.Cert.Issuer.CommonName)
			return result
		}

		if d.Issuer == nil {
			fmt.Printf("Incomplete chain for %s %s %x %v\n", d.Cert.Issuer.CommonName, d.Cert.Subject.CommonName, d.Cert.SerialNumber, result.Errors)
		}

		// Check against errors
		result.Errors.Append(checks.Certificate.Check(d))
	}

	// In batch mode we want to queue results
	if !rtrn && result.Errors.IsError() {
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

	// Unfortunately pem.Decode can't use a io.Reader but exspects a byte array
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
				fmt.Println(string(pemCert))
				var e = errors.New(nil)
				if err != nil {
					e.Err(err.Error())
				}

				results <- testResult{
					Cert:   nil,
					Pem:    string(pemCert),
					Errors: e,
				}
			}
		}
	}

	fmt.Printf("Checked %d certificates\n", count)
	close(jobs)
}

func runBulk(exp bool) {
	defer wgBulk.Done()
	var icaCache = lru.New(200)

	for {
		der, more := <-jobs
		if more {
			do(icaCache, der, exp, false)
		} else {
			break
		}
	}
}

func saveResults(filename string, include, revoked bool) error {
	defer wgSave.Done()

	file, err := os.Create(filename)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	writer.UseCRLF = true
	writer.Write([]string{"Issuer", "CN", "O", "Serial", "NotBefore", "NotAfter", "Type", "Priority", "Error", "Revoked", "Cert", "Fingerprint"})
	writer.Flush()

	for {
		r, more := <-results
		if !more {
			break
		}

		// Don't report anything less than warning (info, debug, notice)
		if r.Errors.Priority() < errors.Warning {
			continue
		}

		// Add all errors to file
		for _, e := range r.Errors.List() {
			var columns []string
			if r.Cert != nil {
				columns = []string{
					fmt.Sprintf("%s, %s", r.Cert.Issuer.CommonName, r.Cert.Issuer.Organization),
					r.Cert.Subject.CommonName,
					strings.Join(r.Cert.Subject.Organization, ", "),
					hex.EncodeToString(r.Cert.SerialNumber.Bytes()),
					r.Cert.NotBefore.Format("2006-01-02"),
					r.Cert.NotAfter.Format("2006-01-02"),
					r.Type,
					e.Priority().String(),
					e.Error(),
				}

				// Check if certificate is revoked when idicated and not expired
				if revoked {
					if r.Cert.NotAfter.Before(time.Now()) {
						// Expired certs are often purged of the revocation list/status
						columns = append(columns, "expired")
					} else if isRevoked, ok := revoke.VerifyCertificate(r.Cert); ok {
						columns = append(columns, fmt.Sprintf("%t", isRevoked))
					} else {
						columns = append(columns, "failed")
					}
				} else {
					columns = append(columns, "")
				}

				// Do we need to include the certificate
				if include {
					columns = append(columns, string(pem.EncodeToMemory(&pem.Block{
						Type:  "CERTIFICATE",
						Bytes: r.Der,
					})))
				} else {
					columns = append(columns, "")
				}

				// Certificate Fingerprint
				fingerprint := sha256.Sum256(r.Der)
				columns = append(columns, hex.EncodeToString(fingerprint[:]))

			} else {
				columns = []string{"", "", "", "", "", "", "", e.Priority().String(), e.Error(), "", r.Pem}
			}

			err := writer.Write(columns)
			if err != nil {
				fmt.Println(err)
				continue
			}

			saved++
		}
	}

	writer.Flush()

	fmt.Printf("Saved %d findings\n", saved)
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

func getIssuerPool(cert *x509.Certificate) (*x509.Certificate, *x509.CertPool, *errors.Errors) {
	var e = errors.New(nil)
	var issuer *x509.Certificate

	pool := x509.NewCertPool()
	var i int
	for len(cert.IssuingCertificateURL) > 0 {
		ic, err := getIssuer(cert)
		e.Append(err)
		if ic == nil {
			break
		}

		// add certificate to pool
		pool.AddCert(ic)

		// issuer of end-entity certificate
		if i == 0 {
			issuer = ic
		}

		// download the issuer of the issuer certificate
		cert = ic
		i++
	}

	return issuer, pool, e
}

func getIssuer(cert *x509.Certificate) (*x509.Certificate, *errors.Errors) {
	var e = errors.New(nil)
	var issuer *x509.Certificate
	for _, url := range cert.IssuingCertificateURL {
		// download if not in cache
		var err error
		issuer, err = downloadCert(url)
		if err != nil {
			e.Err("Failed to download issuer certificate from '%s': %s", url, err.Error())
		}
		if issuer != nil {
			break
		}
	}

	// check if the signature on this certificate can be verified with the downloaded issuer certificate
	if issuer != nil {
		err := cert.CheckSignatureFrom(issuer)
		if err != nil {
			e.Err("Signature not from downloaded issuer: %s", err.Error())
		}
	}

	return issuer, e
}

func downloadCert(url string) (*x509.Certificate, error) {
	// download file
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode > 399 {
		return nil, fmt.Errorf("Unexpected response '%s'", resp.Status)
	}

	// read response body
	derBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	// decode pem, if pem
	block, _ := pem.Decode(derBytes)
	if block != nil {
		derBytes = block.Bytes
	}

	issuer, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return issuer, nil
}
