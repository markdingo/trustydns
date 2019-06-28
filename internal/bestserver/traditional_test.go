package bestserver

import (
	"strings"
	"testing"
	"time"
)

func TestTraditionalNew(t *testing.T) {
	_, err := NewTraditional(TraditionalConfig{}, []Server{first, second, third, fourth})
	if err != nil {
		t.Fatal("Unexpected error with hen setting up for test", err)
	}

	_, err = NewTraditional(TraditionalConfig{}, []Server{})
	if err == nil {
		t.Fatal("Expected an error with no servers")
	}
	if err != nil {
		if !strings.Contains(err.Error(), "No servers") {
			t.Error("Expected 'No servers' in error, not", err)
		}
	}
}

func TestTraditionalResult(t *testing.T) {
	bs, err := NewTraditional(TraditionalConfig{}, []Server{first, second, third, fourth})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}

	now := time.Now()
	s, _ := bs.Best()
	if s != first {
		t.Error("traditional did not return first server on first Best()", s)
	}

	s, _ = bs.Best()
	if s != first {
		t.Error("traditional did not return first server on second Best()", s)
	}

	bs.Result(first, true, now, time.Second)
	s, _ = bs.Best()
	if s != first {
		t.Error("traditional did not return first server on success Report()", s)
	}

	// Any sort of report on the non-Best should have no influence on current best
	bs.Result(second, false, now, time.Second)
	s, _ = bs.Best()
	if s != first {
		t.Error("traditional did not return first server on !success Report(second)", s)
	}

	bs.Result(s, false, now, time.Second) // Should move to second immediately
	s, _ = bs.Best()
	if s != second {
		t.Error("traditional did not return second server on !success Report of best", s)
	}
	bs.Result(s, false, now, time.Second) // Should move to third
	s, _ = bs.Best()
	if s != third {
		t.Error("traditional did not return third server on !success Report of best", s)
	}
	bs.Result(s, false, now, time.Second) // Should move to fourth
	s, _ = bs.Best()
	if s != fourth {
		t.Error("traditional did not return fourth server on !success Report of best", s)
	}

	bs.Result(s, false, now, time.Second) // Should wrap back to first
	s, _ = bs.Best()
	if s != first {
		t.Error("traditional did not loop back to first on !success Report of best", s)
	}

	ok := bs.Result(s, false, now, time.Second)
	if !ok {
		t.Error("Result did not return true with a legit server name")
	}
	ok = bs.Result(&defaultServer{name: "bogus"}, false, now, time.Second)
	if ok {
		t.Error("Result returned true with a bogus server name")
	}
}
