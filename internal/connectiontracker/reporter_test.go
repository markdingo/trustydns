package connectiontracker

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestReporterName(t *testing.T) {
	trk := New("Fido")
	if trk.Name() != "Conn Track" {
		t.Error("New not storing name correctly", trk.Name())
	}
	rep := trk.Report(false)
	if !strings.Contains(rep, "Fido") {
		t.Error("New not reporting name correctly", rep)
	}
}

const (
	zero = "curr=0 pk=0 sess=0 errs=0 (0/0/0/0/0/0) connFor=0.0s activeFor=0.0s Filo"
	one  = "curr=1 pk=1 sess=0 errs=0 (0/0/0/0/0/0) connFor=0.0s activeFor=0.0s Filo"
)

func TestReporterReport(t *testing.T) {
	trk := New("Filo")
	rep := trk.Report(false)
	if rep != zero {
		t.Error("Expected zero report", zero, "got", rep)
	}
	trk.ConnState("one", time.Now(), http.StateNew)
	rep = trk.Report(false)
	if rep != one {
		t.Error("Expected one report", one, "got", rep)
	}
	trk.ConnState("one", time.Now(), http.StateClosed)
	trk.Report(true)        // Cause reset
	rep = trk.Report(false) // Get report *after* reset
	if rep != zero {
		t.Error("resetCounters did not produce zero report. Got", rep)
	}
}
