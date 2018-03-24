package asn1

import (
	"testing"
)

func TestIsForbiddenString(t *testing.T) {
	// Some forbidden characters to test
	forbidden := []string{"-", "--", "_", "__", "-_", "- -", "?", "n/a", "N/A", ".", "+"}

	for _, v := range forbidden {
		if !isForbiddenString([]byte(v)) {
			t.Errorf("Forbidden string passed check: %q", v)
		}
	}

	// These could be accepted values
	accepted := []string{"OK+", "-OK"}

	for _, v := range accepted {
		if isForbiddenString([]byte(v)) {
			t.Errorf("Accepted string did not pass check: %q", v)
		}
	}
}
