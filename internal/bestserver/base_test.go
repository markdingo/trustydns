package bestserver

import (
	"strings"
	"testing"
	"time"
)

var (
	dupe   = &defaultServer{name: "dupe"}
	unique = &defaultServer{name: "unique"}
	one    = &defaultServer{name: "one"}
	two    = &defaultServer{name: "two"}
	three  = &defaultServer{name: "three"}
)

func TestBaseInit(t *testing.T) {
	bm := &baseManager{}
	err := bm.init(LatencyAlgorithm, []Server{dupe, unique, dupe})
	if err == nil {
		t.Error("Expected dupe server error")
	}
	if err != nil {
		if !strings.Contains(err.Error(), "Duplicate") {
			t.Error("Expected 'Duplicate' error, not", err)
		}
	}
}

func TestBaseName(t *testing.T) {
	bm := &baseManager{}
	err := bm.init(LatencyAlgorithm, []Server{one, two})
	if err != nil {
		t.Fatal("Did not expect error during setup", err)
	}

	if bm.Algorithm() != string(LatencyAlgorithm) {
		t.Error("t.Name() mismatch. Expected", LatencyAlgorithm, "got", bm.Algorithm())
	}
}

func TestBaseBest(t *testing.T) {
	bm := &baseManager{}
	err := bm.init(LatencyAlgorithm, []Server{one, two})
	if err != nil {
		t.Fatal("Did not expect error during setup", err)
	}

	b, _ := bm.Best()
	if b.Name() != "one" {
		t.Error("Expected Best to be first cab off the rank, not", b)
	}
}

func TestBaseServers(t *testing.T) {
	bm := &baseManager{}
	origServers := []Server{one, two, three}
	err := bm.init(LatencyAlgorithm, origServers)
	if err != nil {
		t.Fatal("Did not expect error during setup", err)
	}

	sList := bm.Servers()
	if !sameServers(origServers, sList) {
		t.Error("server lists not the same", origServers, "and", sList)
	}

	if bm.Len() != 3 {
		t.Error("Len() did not return 3, got", bm.Len())
	}
}

// Test reader/writer lock functions (just wrappers around mutex, but still). Any errors are fatal
// as the lock is in an indeterminant state.
func TestBaseLocking(t *testing.T) {
	bm := &baseManager{}
	err := bm.init(LatencyAlgorithm, []Server{one})
	if err != nil {
		t.Fatal("Did not expect error during setup", err)
	}

	// Check writer lock
	bm.lock()
	otherGotLock := false
	go func() {
		bm.lock()
		otherGotLock = true
		bm.unlock()
	}()

	time.Sleep(50 * time.Millisecond)
	if otherGotLock {
		t.Fatal("writer lock didn't stop concurrent access")
	}
	bm.unlock()
	time.Sleep(50 * time.Millisecond)
	if !otherGotLock {
		t.Fatal("writer unlock did not allow other writer to lock")
	}

	// Check reader lock
	bm.rlock() // This may wait fractionally for the above go-routine to unlock, no matter
	otherGotLock = false
	go func() {
		bm.rlock()
		otherGotLock = true // Two readers should be fine
		bm.runlock()
	}()
	time.Sleep(50 * time.Millisecond)
	if !otherGotLock {
		t.Fatal("reader lock blocked second reader")
	}
	otherGotLock = false
	go func() {
		bm.lock() // Writer should block
		otherGotLock = true
		bm.unlock()
	}()
	time.Sleep(50 * time.Millisecond)
	if otherGotLock {
		t.Fatal("reader lock did not block writer")
	}
	bm.runlock()
	time.Sleep(50 * time.Millisecond)
	if !otherGotLock {
		t.Fatal("reader unlock did not release blocked writer")
	}
}

func TestServersFromNames(t *testing.T) {
	sl := ServersFromNames([]string{"a", "b", "c", "a"})
	if sl[0].Name() != "a" {
		t.Error("[0] name should EQ 'a', not", sl[0].Name())
	}
	if sl[1].Name() != "b" {
		t.Error("[1] name should EQ 'b', not", sl[1].Name())
	}
	if sl[2].Name() != "c" {
		t.Error("[2] name should EQ 'c', not", sl[2].Name())
	}
	if sl[3].Name() != "a" {
		t.Error("[3] name should EQ 'a', not", sl[3].Name())
	}
}

// A not very comprehesive matcher. We know that goodList has the correct entries which are also
// promised to be unique so we can shortcut the comprehensive two-way comparison needed if the two
// lists were completely unknown.
func sameServers(goodList, newList []Server) bool {
	if len(goodList) != len(newList) {
		return false
	}

	found := 0
	for _, g := range goodList {
	matchNew:
		for _, n := range newList {
			if n == g {
				found++
				break matchNew
			}
		}
	}

	return found == len(goodList)
}
