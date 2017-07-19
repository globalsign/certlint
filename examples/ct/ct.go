package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/globalsign/certlint/asn1"
	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"

	_ "github.com/globalsign/certlint/checks/certificate/all"
	_ "github.com/globalsign/certlint/checks/extensions/all"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

func main() {
	var logServer = flag.String("server", "https://ct.googleapis.com/aviator", "CT log server")
	var start = flag.Int64("start", 0, "CT log start index")
	flag.Parse()

	logClient, err := client.New(*logServer, nil, jsonclient.Options{})
	if err != nil {
		fmt.Printf("Failed to create log client: %s\n", err.Error())
		return
	}
	sth, err := logClient.GetSTH(context.Background())
	if err != nil {
		fmt.Printf("Failed to get tree head: %s\n", err.Error())
		return
	}

	var startIndex = *start
	for {
		entries, err := logClient.GetEntries(context.Background(), startIndex, startIndex+1000)
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
		if leaf != nil {
			check(leaf.Raw)
		}
		return

	case ct.PrecertLogEntryType:
		check(entry.Chain[0].Data)
		return

	default:
		fmt.Printf("Failed to parse unknown entry type: %s", entry.Leaf.TimestampedEntry.EntryType)
		return
	}
}

func check(der []byte) {
	var e = errors.New(nil)

	// Check the ASN1 structure for common formatting errros
	al := new(asn1.Linter)
	e.Append(al.CheckStruct(der))

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
	if d == nil {
		e.Err("Failed to load certificate")
	}

	// List all errors
	if e != nil {
		if d != nil {
			fmt.Printf("'%s' issued by '%s' (%s)\n", d.Cert.Subject.CommonName, d.Cert.Issuer.CommonName, d.Type)
		}
		for _, err := range e.List() {
			fmt.Printf("\t- %s\n", err.Error())
		}
		fmt.Println()
	}
}
