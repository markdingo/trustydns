package tlsutil

import (
	"testing"
)

var (
	emptyAr = []string{}
	certAr  = []string{"testdata/proxy.cert"}
	keyAr   = []string{"testdata/proxy.key"}
	blankAr = []string{""} // This can come from a bogus command line caller with --tls-cert ""
)

func TestNewServer(t *testing.T) {
	cfg, err := NewServerTLSConfig(false, zeroCAs, emptyAr, emptyAr)
	if err != nil {
		t.Error("Unexpected error with minimalist NewServerTLSConfig", err)
	}
	if cfg == nil {
		t.Fatal("cfg should be non-nil if no error")
	}
	cfg, err = NewServerTLSConfig(true, zeroCAs, emptyAr, emptyAr)
	if err != nil {
		t.Error("Unexpected error with almost minimalist NewServerTLSConfig", err)
	}
	if cfg == nil {
		t.Fatal("cfg should be non-nil if no error")
	}

	// Good path tests
	cfg, err = NewServerTLSConfig(false, oneCA, certAr, keyAr)
	if err != nil {
		t.Error("Unexpected error with good data files", err)
	}
	cfg, err = NewServerTLSConfig(true, oneCA, certAr, keyAr)
	if err != nil {
		t.Error("Unexpected error with good data files and useSystemRoot", err)
	}

	// Bad path tests
	cfg, err = NewServerTLSConfig(false, oneCA, certAr, emptyAr)
	if err == nil {
		t.Error("Expected error with missing key file")
	}
	cfg, err = NewServerTLSConfig(false, oneCA, certAr, blankAr)
	if err == nil {
		t.Error("Expected error with blank key file")
	}
	cfg, err = NewServerTLSConfig(false, oneCA, blankAr, keyAr)
	if err == nil {
		t.Error("Expected error with blank cert file")
	}
	cfg, err = NewServerTLSConfig(false, oneCA, emptyAr, keyAr)
	if err == nil {
		t.Error("Expected error with missing cert file")
	}
	cfg, err = NewServerTLSConfig(true, emptyCA, certAr, keyAr)
	if err == nil {
		t.Error("Expected an error with an empty root CA")
	}
	cfg, err = NewServerTLSConfig(true, missingCA, certAr, keyAr)
	if err == nil {
		t.Error("Expected an error return with a bad rootCA file")
	}
	cfg, err = NewServerTLSConfig(true, oneCA, []string{"testdata/proxy.certNoExit"}, keyAr)
	if err == nil {
		t.Error("Expected an error return with a bad proxy certificate file")
	}
}
