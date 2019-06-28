package concurrencytracker

import (
	"testing"
)

func TestAll(t *testing.T) {
	var cct Counter
	peak := cct.Peak(false)
	if peak != 0 {
		t.Error("Peak should start life at zero, not", peak)
	}
	cct.Add() // Should be: current=1, peak=1
	peak = cct.Peak(false)
	if peak != 1 {
		t.Error("Peak should reflect Add->1, not", peak)
	}
	cct.Add() // Should be: current=2, peak=2
	peak = cct.Peak(false)
	if peak != 2 {
		t.Error("Peak should reflect Add->2, not", peak)
	}

	cct.Done()            // Should be: current=1, peak=2
	peak = cct.Peak(true) // true means peak=current. Should be: current=1, peak=1
	if peak != 2 {
		t.Error("Peak should not decrement until reset. Expect 2, not", peak)
	}
	peak = cct.Peak(false) // Should be: current=1, peak=1
	if peak != 1 {
		t.Error("Peak should have been reset down to current peak. Expect 1, not", peak)
	}

	cct.Done()            // Should be: current=0, peak=1
	peak = cct.Peak(true) // Should be reset to: current=0, peak=0
	if peak != 1 {
		t.Error("Peak should have been reset down to current peak. Expect 1, not", peak)
	}
	peak = cct.Peak(false)
	if peak != 0 {
		t.Error("Peak should have been reset down to zero, not", peak)
	}
}

// Check that Add returns true when it increases peak
func TestAddTrue(t *testing.T) {
	var cct Counter
	if !cct.Add() { // curr=1, peak=1
		t.Error("Expected first add to set new peak")
	}
	if !cct.Add() { // curr=2, peak=2
		t.Error("Expected second add to set new peak")
	}
	cct.Done()              // curr=1, peak=2
	peak := cct.Peak(false) // Returns peak=2, After call curr=1, peak=2
	if cct.Add() {
		t.Error("Expected third add to not set new peak", peak, cct.Peak(false))
	}
}

func TestPanic(t *testing.T) {
	gotPanic := false
	panicFunc(&gotPanic)
	if !gotPanic {
		t.Error("Expected a panic/recover sequence, but nadda")
	}
}

func panicFunc(gotPanic *bool) {
	var cct Counter
	cct.Add()
	cct.Done()
	defer func() {
		if x := recover(); x != nil {
			*gotPanic = true
		}
	}()
	cct.Done() // Should cause panic and set the gotPanic flag
}
