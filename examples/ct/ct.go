package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/globalsign/certlint/asn1"
	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"

	_ "github.com/globalsign/certlint/checks/certificate/all"
	_ "github.com/globalsign/certlint/checks/extensions/all"

	ct "github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
	"github.com/google/certificate-transparency/go/jsonclient"
)

func main() {
	var logServer = flag.String("server", "https://ct.googleapis.com/aviator", "CT log server")
	var start = flag.Int64("start", 0, "CT log start index")
	flag.Parse()

	logClient := client.New(*logServer, nil, jsonclient.Options{})
	sth, err := logClient.GetSTH()
	if err != nil {
		fmt.Printf("Failed to get tree head: %s\n", err.Error())
		return
	}

	var startIndex = *start
	for {
		entries, err := logClient.GetEntries(startIndex, startIndex+1000)
		if err != nil {
			fmt.Printf("Failed to get entries: %s\n", err.Error())
			break
		}

		for _, entry := range entries {
			startIndex++
			ctEntry(entry)
		}

		if !(startIndex < int64(sth.TreeSize)) {
			break
		}
	}
}

func ctEntry(entry ct.LogEntry) {
	switch entry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		leaf, err := entry.Leaf.X509Certificate()
		if err != nil {
			fmt.Printf("Failed to get leaf certificate in entry %d: %s\n", entry.Index, err.Error())
			return
		}
		check(leaf.Raw)
		return

	case ct.PrecertLogEntryType:
		check(entry.Chain[0])
		return

	default:
		fmt.Printf("Failed to parse unknown entry type: %s", entry.Leaf.TimestampedEntry.EntryType)
		return
	}
}

func check(der []byte) {
	var e = errors.New(nil)

	// Check the ASN1 structure for common formatting errros
	e.Append(asn1.CheckStruct(der))

	// Load and parse certificate
	d, err := certdata.Load(der)
	if err == nil {
		// Don't check expired certificates
		if d.Cert.NotAfter.Before(time.Now()) {
			return
		}

		// Perform all and only the imported checks
		e.Append(checks.Certificate.Check(d))
	}

	// List all errors
	if len(e.List()) > 0 {
		fmt.Printf("'%s' issued by '%s'\n", d.Cert.Subject.CommonName, d.Cert.Issuer.CommonName)
		for _, err := range e.List() {
			fmt.Printf("\t- %s (%s)\n", err.Error(), d.Type)
		}
		fmt.Println()
	}
}
