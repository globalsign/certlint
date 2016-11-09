package main

import (
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/golang/groupcache/lru"
)

func TestTestData(t *testing.T) {
	var icaCache = lru.New(200)

	// TODO: Check for specific errors per certificate to be sure we don't miss one
	files, _ := ioutil.ReadDir("./testdata")
	for _, f := range files {
		fmt.Printf("---- %s ----\n", f.Name())

		der := getCertificate("./testdata/" + f.Name())
		if len(der) > 0 {
			result := do(icaCache, der, nil, true, true)
			if len(result.Errors.List()) == 0 {
				t.Errorf("Expected some errors, got %d in %s", len(result.Errors.List()), f.Name())
				continue
			}
			for _, err := range result.Errors.List() {
				fmt.Printf("%s (%s)\n", err.Error(), result.Type)
			}
		}
	}
}
