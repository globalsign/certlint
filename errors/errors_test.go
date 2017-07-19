package errors

import (
	"testing"
)

func TestErrros(t *testing.T) {
	e := new(Errors)
	e.Warning("Warning")
	if e.Priority() != Warning {
		t.Errorf("Unexspected priority got %d, want %d", e.Priority(), Warning)
	}
	e.Err("Error")
	if e.Priority() != Error {
		t.Errorf("Unexspected priority got %d, want %d", e.Priority(), Error)
	}

	e2 := new(Errors)
	e.Crit("Critical")
	if e.Priority() != Critical {
		t.Errorf("Unexspected priority got %d, want %d", e.Priority(), Critical)
	}

	e.Append(e2)
	if e.Priority() != Critical {
		t.Errorf("Unexspected priority got %d, want %d", e.Priority(), Critical)
	}

	if len(e.List()) != 3 {
		t.Errorf("Unexspected lenght got %d, want %d", len(e.List()), 3)
	}
}
