package tlsutil

import (
	"testing"
)

func TestLoadRoots(t *testing.T) {
	pool, err := loadroots(false, zeroCAs)
	if err != nil {
		t.Error("Unexpected error with minimalist loadroots", err)
	}
	if pool == nil {
		t.Error("Expected a pool back from loadroots when no error returned")
	}
	pool, err = loadroots(true, zeroCAs)
	if err != nil {
		t.Error("Unexpected error with almost minimalist loadroots", err)
	}
	if pool == nil {
		t.Error("Expected a pool back from loadroots when no error returned")
	}

	// Good path tests
	pool, err = loadroots(false, oneCA)
	if err != nil {
		t.Error("Unexpected error with oneCA", err)
	}
	pool, err = loadroots(true, oneCA)
	if err != nil {
		t.Error("Unexpected error with oneCA + useSystemRoot", err)
	}
}
