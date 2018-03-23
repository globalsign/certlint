package main

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/globalsign/certlint/asn1"
	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/golang/groupcache/lru"
)

var certBench = `-----BEGIN CERTIFICATE-----
MIIFqTCCBJGgAwIBAgIMLle3b82wYk2pKYzMMA0GCSqGSIb3DQEBCwUAMGIxCzAJ
BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTgwNgYDVQQDEy9H
bG9iYWxTaWduIEV4dGVuZGVkIFZhbGlkYXRpb24gQ0EgLSBTSEEyNTYgLSBHMjAe
Fw0xNTA3MDMwNTU2MDNaFw0xNzA3MDMwNTU2MDNaMIHSMR0wGwYDVQQPDBRQcml2
YXRlIE9yZ2FuaXphdGlvbjEXMBUGA1UEBRMOMDExMC0wMS0wNDAxODExEzARBgsr
BgEEAYI3PAIBAxMCSlAxCzAJBgNVBAYTAkpQMQ4wDAYDVQQIEwVUb2t5bzEQMA4G
A1UEBxMHU2hpYnV5YTEZMBcGA1UECRMQMjYtMSBTYWt1cmFnYW9rYTEcMBoGA1UE
ChMTR01PIEdsb2JhbFNpZ24gSy5LLjEbMBkGA1UEAxMSd3d3Lmdsb2JhbHNpZ24u
bmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnG0zOWZS5Jw4FtOB
k3wsBfQP5Htu9Ki4yNDc72r6Z3F/Xbp/Gg+l62CgI00ODw+YsuXl87KdQrj6f0WO
HdpHYn9GmTo9WTtwKlYGgk/l71EcbCtuQ4oPqB6QAs02Ag5cSZFjnjFkXK7fMUoq
4Ds0uoHUdb69l2LFIkK7hpXE53bIA4nnHP/z7Hu/nlUOBMs1Xs7YUbemWFgbY+vy
zHuq02h4hAyWeEkRyLpgpRJ4KsDnrAsy1Me0/HpURS/HljFE1adCc0s5j167OYxt
ikKARpSbs3sGHREHC3MCJBu6zm6OrDJaWR48lWFkCDzuVuLcM8UKKK/Jay9PH/kh
bAgZqwIDAQABo4IB7DCCAegwDgYDVR0PAQH/BAQDAgWgMIGUBggrBgEFBQcBAQSB
hzCBhDBHBggrBgEFBQcwAoY7aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9j
YWNlcnQvZ3NleHRlbmR2YWxzaGEyZzJyMi5jcnQwOQYIKwYBBQUHMAGGLWh0dHA6
Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2V4dGVuZHZhbHNoYTJnMjBMBgNVHSAE
RTBDMEEGCSsGAQQBoDIBATA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAJBgNVHRMEAjAAMEMGA1UdHwQ8MDowOKA2
oDSGMmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3NleHRlbmR2YWxzaGEy
ZzIuY3JsMC0GA1UdEQQmMCSCEnd3dy5nbG9iYWxzaWduLm5ldIIOZ2xvYmFsc2ln
bi5uZXQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBRU
nGc1F8xta8n/GEilz7cINJcjizAfBgNVHSMEGDAWgBTaQHdDZRz4/qfj9GSCPk1D
EyIxAjATBgorBgEEAdZ5AgQDAQH/BAIFADANBgkqhkiG9w0BAQsFAAOCAQEAOk2S
YH/vvsrHp4FtUWXuOq+jQ8uUuUMjV9Q7xSyHkLdIba7M4Sq00jA4E8YjruwlNSxp
tfy6WBz8/93RDvNodNhlokJOibmZ8X3xvXMqAPFbeX6YLjWsl4z30ZnMUi2g+SQa
4JCKbYZvTnVRY3SSIqfPYcGMNG5ErFcKfq9YdcKdmw9ZuPgJUBj2aJvnnXb91MoV
2YlSqan5qI9N6K6mkf2VuXUbw2Z6H6/A7qTLj0CGzWGscqgwUXXC4aGUPFSm78AB
accZ5e1iOtNIBTVUEaQ0YxNwhZqnQO4rgBFCnEpNH6TB62hXUD6u/oP/WB48Wmek
KPgaoWHMo5sOFQnw5A==
-----END CERTIFICATE-----`

func TestMain(m *testing.M) {
	build := exec.Command("go", "build")
	berr := build.Run()
	if berr != nil {
		fmt.Printf("could not build before tests: %v", berr)
		os.Exit(1)
	}

	retcode := m.Run()

	clean := exec.Command("go", "clean", "-x")
	cerr := clean.Run()
	if cerr != nil {
		fmt.Printf("could not cleanup after tests: %v", cerr)
		os.Exit(1)
	}

	os.Exit(retcode)
}

func TestTestData(t *testing.T) {
	var icaCache = lru.New(200)

	// TODO: Check for specific errors per certificate to be sure we don't miss one
	files, _ := filepath.Glob("./testdata/*.pem")
	for _, f := range files {
		fname := path.Base(f)
		fmt.Printf("---- %s ----\n", fname)

		der := getCertificate("./testdata/" + fname)
		if len(der) > 0 {
			result := do(icaCache, der, true, true)
			if len(result.Errors.List()) == 0 {
				t.Errorf("Expected some errors, got %d in %s", len(result.Errors.List()), fname)
				continue
			}
			for _, err := range result.Errors.List() {
				fmt.Printf("Priority: %s, Message: %s (%s)\n", err.Priority(), err.Error(), result.Type)
			}
		}
	}
}

func TestCLITestData(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	testdata := path.Join(dir, "testdata")
	files, _ := filepath.Glob("./testdata/*.pem")
	for _, f := range files {
		fname := path.Base(f)
		t.Run(fname, func(t *testing.T) {
			fmt.Printf("---- CLI %s ----\n", fname)

			golden := path.Join(testdata, fname+".golden")
			crt := path.Join(testdata, fname)
			bin := path.Join(dir, "certlint")

			// raise errlevel to Alert because non-zero return causes the test to fail
			cli_args := []string{"-expired", "-errlevel", "alert", "-cert", crt}
			cmd := exec.Command(bin, cli_args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatal(err)
			}

			// TODO: allow for programatic refresh of golden files as a test argument
			//if *update {
			//	ioutil.WriteFile(golden, output, 0640)
			//}

			actual := string(output)

			expected, err := ioutil.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(actual, string(expected)) {
				t.Fatalf("actual = %T:%s\nexpected = %T:%s\n", actual, actual, expected, expected)
			}
		})
	}
}

func TestCLIReturn(t *testing.T) {
	tests := []struct {
		name string
		args []string
		retv string
	}{
		{
			"Error Level Info",
			[]string{
				"-expired", "-errlevel", "info", "-cert", "testdata/invalid_encoding2.pem",
			},
			"exit status 1",
		},
		{
			"Error Level Warning",
			[]string{
				"-expired", "-errlevel", "warning", "-cert", "testdata/invalid_encoding2.pem",
			},
			"exit status 1",
		},
		{
			"Error Level Critical",
			[]string{
				"-expired", "-errlevel", "critical", "-cert", "testdata/invalid_encoding2.pem",
			},
			"exit status 0",
		},
		{
			"Error Level Unspecified (default is Error)",
			[]string{"-expired", "-cert", "testdata/invalid_encoding2.pem"},
			"exit status 1",
		},
		{
			"Supplied Error Level Invalid",
			[]string{"-expired", "-errlevel", "garbage", "-cert", "testdata/invalid_encoding2.pem"},
			"exit status 1",
		},
	}

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Printf("---- CLI %s ----\n", tt.name)

			bin := path.Join(dir, "certlint")
			cmd := exec.Command(bin, tt.args...)
			_, err = cmd.CombinedOutput()
			if err != nil {
				actual := err.Error()
				expected := tt.retv

				if !reflect.DeepEqual(actual, expected) {
					t.Fatalf("actual = %T:%s, expected = %T:%s", actual, actual, expected, expected)
				}
			}

		})
	}
}

func BenchmarkTestData(b *testing.B) {
	var icaCache = lru.New(200)

	// TODO: Check for specific errors per certificate to be sure we don't miss one
	files, _ := filepath.Glob("./testdata/*.pem")
	for _, f := range files {
		fname := path.Base(f)
		der := getCertificate("./testdata/" + fname)
		if len(der) > 0 {
			b.Run(fname, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					do(icaCache, der, true, true)
				}
			})
		}
	}
}

func BenchmarkASN1Good(b *testing.B) {
	block, _ := pem.Decode([]byte(certBench))

	// run asn1 formatting checks b.N times
	for n := 0; n < b.N; n++ {
		al := new(asn1.Linter)
		al.CheckStruct(block.Bytes)
	}
}

func BenchmarkCertGood(b *testing.B) {
	block, _ := pem.Decode([]byte(certBench))
	d, _ := certdata.Load(block.Bytes)

	// run certificate checks b.N times
	for n := 0; n < b.N; n++ {
		checks.Certificate.Check(d)
	}
}
