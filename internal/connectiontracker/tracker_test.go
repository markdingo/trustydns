package connectiontracker

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Test that unique connection IDs are tracked separately
func TestUniqueConns(t *testing.T) {
	trk := New("Unique")
	var now time.Time
	res := trk.ConnState("1.2.3.4:5", now, http.StateNew)
	if !res {
		t.Error("Unexpected complaint from first StateNew")
	}

	res = trk.ConnState("1.2.3.5:5", now, http.StateNew)
	if !res {
		t.Error("Unexpected complaint from second StateNew")
	}

	rep := trk.Report(false) // Use reporter to check conn count
	if !strings.Contains(rep, "curr=2") {
		t.Error("Expected curr=2, got", rep)
	}

	res = trk.ConnState("1.2.3.4:5", now, http.StateClosed)
	if !res {
		t.Error("Unexpected complaint from first StateClosed")
	}

	res = trk.ConnState("1.2.3.5:5", now, http.StateClosed)
	if !res {
		t.Error("Unexpected complaint from second StateClosed")
	}

	rep = trk.Report(false) // Use reporter to check conn count
	if !strings.Contains(rep, "curr=0") {
		t.Error("Expected curr=0, got", rep)
	}
}

const (
	exp = "curr=0 pk=2 sess=0 errs=0 (0/0/0/0/0/0) connFor=1260.0s activeFor=420.0s Active"
)

// Check that the active times are accumlated correctly
func TestDurations(t *testing.T) {
	trk := New("Active")
	var now time.Time
	now = now.Add(time.Hour * 12)
	trk.ConnState("one", now, http.StateNew) // Clock: 12:00
	trk.ConnState("two", now, http.StateNew) // Clock: 12:00

	now = now.Add(time.Minute)
	trk.ConnState("one", now, http.StateActive) // Clock: 12:01
	now = now.Add(time.Minute)
	trk.ConnState("two", now, http.StateActive) // Clock: 12:02

	now = now.Add(time.Minute * 2)
	trk.ConnState("one", now, http.StateIdle) // Clock: 12:04
	now = now.Add(time.Minute)
	trk.ConnState("two", now, http.StateIdle) // Clock: 12:05

	now = now.Add(time.Minute)
	trk.ConnState("two", now, http.StateActive) // Clock: 12:06
	now = now.Add(time.Minute)
	trk.ConnState("two", now, http.StateIdle) // Clock: 12:07

	now = now.Add(time.Minute * 3)
	trk.ConnState("one", now, http.StateClosed) // Clock: 12:10
	now = now.Add(time.Minute)
	trk.ConnState("two", now, http.StateHijacked) // Clock: 12:11

	// Elapse is 12:00-12:11 = 660s.
	// one exists for 12:00-12:10 = 600s. Active for 12:01-12:04 = 180s
	// two exists for 12:00-12:11 = 660s. Active for 12:02-12:05, 12:06-12:07 = 240s
	// Current should be zero, peak should be two.
	// connFor = 600+660=1260. activeFor=180+240=420.

	rep := trk.Report(false) // Use reporter to check results rather than peaking at struct
	if !strings.Contains(rep, exp) {
		t.Error("Expected", exp, "got", rep)
	}
}

const (
	peakSession = "curr=0 pk=1 sess=2 errs=0 (0/0/0/0/0/0) connFor=0.0s activeFor=0.0s Sessions"
)

func TestSessions(t *testing.T) {
	trk := New("Sessions")
	trk.ConnState("one", time.Now(), http.StateNew)
	trk.ConnState("one", time.Now(), http.StateActive)
	res := trk.SessionAdd("one")
	if res != true {
		t.Error("Unexpected false return from SessionAdd")
	}
	trk.SessionAdd("one")
	res = trk.SessionDone("one")
	if res != true {
		t.Error("Unexpected false return from SessionAdd")
	}
	trk.SessionDone("one")
	trk.ConnState("one", time.Now(), http.StateClosed)
	rep := trk.Report(false)
	if rep != peakSession {
		t.Error("Expected peak session", peakSession, "got", rep)
	}
}

// Exercise all the error paths when the supplied state doesn't match the internal state.
func TestStateErrors(t *testing.T) {
	trk := New("State Errors")

	// Test creating a new key that needs to discard a dangling connection.

	trk.ConnState("one", time.Now(), http.StateNew)
	res := trk.ConnState("one", time.Now(), http.StateNew) // Dangling "one"
	if res {
		t.Error("Should not have got a true when replacing a dangling connection", trk)
	}

	rep := trk.Report(true)
	if !strings.Contains(rep, "curr=1") { // Should only have one Connection
		t.Error("Report should only have one connection, not", rep)
	}

	// Test referring to a key that doesn't exist, but should.

	res = trk.ConnState("two", time.Now(), http.StateClosed) // Should exist but doesn't
	if res {
		t.Error("Expected false return when referencing a non-existent key + Closed")
	}
	rep = trk.Report(true)
	if !strings.Contains(rep, "errs=1 (1/") {
		t.Error("Expected NoConnInMap error, got", rep)
	}

	// Test Closing a connection that has sessions active

	trk.ConnState("three", time.Now(), http.StateNew)
	trk.SessionAdd("three")
	res = trk.ConnState("three", time.Now(), http.StateClosed)
	if res {
		t.Error("Should have got a false return when closing connection with sessions", trk)
	}
	rep = trk.Report(true)
	if !strings.Contains(rep, "errs=1 (0/0/0/0/1/0)") {
		t.Error("Should have errNoConnForSession=1, not", rep)
	}

	// Test session count going negative

	trk.ConnState("four", time.Now(), http.StateNew)
	trk.SessionAdd("four")
	trk.SessionDone("four")
	res = trk.SessionDone("four")
	if res {
		t.Error("Expected false when decrementing sessions into negative")
	}
	rep = trk.Report(true)
	if !strings.Contains(rep, "errs=1 (0/0/0/1/0/0)") {
		t.Error("Should have errNegativeConcurrency=1, not", rep)
	}

	// Test referring to a session that doesn't exist

	res = trk.SessionAdd("five")
	if res {
		t.Error("Expected a false return for SessionAdd ref to non-existent connection", trk)
	}
	res = trk.SessionDone("five")
	if res {
		t.Error("Expected a false return for SessionDone ref to non-existent connection", trk)
	}

	// Test unknown state

	trk.ConnState("six", time.Now(), http.StateNew)
	res = trk.ConnState("six", time.Now(), http.StateNew+100)
	if res {
		t.Error("Invalid state should have returned false", trk)
	}
}
