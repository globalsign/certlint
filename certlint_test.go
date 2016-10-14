package main

import (
	"fmt"
	"io/ioutil"
	"testing"
)

func TestTestData(t *testing.T) {
	// TODO: Check for specific errors per certificate to be sure we don't miss one
	files, _ := ioutil.ReadDir("./testdata")
	for _, f := range files {
		fmt.Printf("---- %s ----\n", f.Name())

		der := getCertificate("./testdata/" + f.Name())
		if len(der) > 0 {
			result := do(der, nil, true, true)
			if len(result.Errors) == 0 {
				t.Errorf("Exspected some errors, got %d in %s", len(result.Errors), f.Name())
				continue
			}
			for _, err := range result.Errors {
				fmt.Printf("%s (%s)\n", err.Error(), result.Type)
			}
		}
	}
}
