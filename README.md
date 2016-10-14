# certlint
X.509 certificate linter written in Go

#### General
This package is a work in progress.

Please keep in mind that:
- This is an early release and may contain bugs or false reports
- Not all checks have been fully implemented or verified against the standard
- CLI flag, APIs and CSV export are subject to change

Code contributions and tests are highly welcome!

#### Installation

To install from source, just run:
```bash
go get -u github.com/globalsign/certlint
go install github.com/globalsign/certlint
```

#### CLI: Usage
```
Usage of ./certlinter:
  -bulk string
        Bulk certificates file
  -cert string
        Certificate file
  -expired
        Test expired certificates
  -help
        Show this help
  -include
        Include certificates in report
  -issuer string
        Certificate file
  -report string
        Report filename (default "report.csv")
```

##### CLI: One certificate
```bash
$ certlinter -cert certificate.pem
```

##### CLI: A series of PEM encoded certificates
```bash
$ certlinter -bulk largestore.pem
```

##### CLI: Testing expired certificates
```bash
$ certlinter -expired -bulk largestore.pem
```

##### API: Usage
Import one or all of these packages:

```go
import "github.com/globalsign/certlint/asn1"
import "github.com/globalsign/certlint/certdata"
import "github.com/globalsign/certlint/checks"
```

You can import all available checks:
```go
_ "github.com/globalsign/certlint/checks/extentions/all"
_ "github.com/globalsign/certlint/checks/certificate/all"
```

Or you can just import a restricted set:
```go
// Check for certificate (ext) KeyUsage extention
_ "github.com/globalsign/certlint/checks/extentions/extkeyusage"
_ "github.com/globalsign/certlint/checks/extentions/keyusage"

// Also check the parsed certificate (ext) keyusage content
_ "github.com/globalsign/certlint/checks/certificate/extkeyusage"
_ "github.com/globalsign/certlint/checks/certificate/keyusage"
```

##### API: Check ASN.1 value formatting
```go
errors := asn1.CheckStruct(der)
if len(errors) > 0 {
  for _, err := range errors {
    fmt.Println(err)
  }
}
```

##### API: Check certificate details
```go
d, err := certdata.Load(der)
if err == nil {
  errors := checks.Certificate.Check(d)
  if len(errors) > 0 {
    for _, err := range errors {
      fmt.Println(err)
    }
  }
}
```
