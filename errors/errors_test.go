package errors

import "testing"

func TestList(t *testing.T) {
	var e = New(nil)

	e.Emerg("Emergency message")
	e.Alert("Alert message")
	e.Crit("Critical message")
	e.Err("Error message")
	e.Warning("Warning message")
	e.Notice("Notice message")
	e.Info("Info message")
	e.Debug("Debug message")

	if len(e.List()) != 8 {
		t.Errorf("Expected 8 errors, got %d", len(e.List()))
	}

	var priorities = []Priority{Emergency, Alert, Critical, Error, Warning, Notice, Info, Debug}
	for _, p := range priorities {
		if len(e.List(p)) != 1 {
			t.Errorf("Expected 1 error with priority %d, got %d", p, len(e.List(p)))
		}
	}
}

func TestAppend(t *testing.T) {
	var e1 = New(nil)
	e1.Emerg("Emergency message")
	e1.Alert("Alert message")
	e1.Crit("Critical message")
	e1.Err("Error message")

	var e2 = New(nil)
	e2.Warning("Warning message")
	e2.Notice("Notice message")
	e2.Info("Info message")
	e2.Debug("Debug message")

	e1.Append(e2)

	if len(e1.List()) != 8 {
		t.Errorf("Expected 8 errors, got %d", len(e1.List()))
	}

	var priorities = []Priority{Emergency, Alert, Critical, Error, Warning, Notice, Info, Debug}
	for _, p := range priorities {
		if len(e1.List(p)) != 1 {
			t.Errorf("Expected 1 error with priority %d, got %d", p, len(e1.List(p)))
		}
	}
}
