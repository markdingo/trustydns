package tlsutil

import (
	"testing"
)

var zeroCAs = []string{}
var oneCA = []string{"testdata/rootCA.cert"}
var twoCAs = []string{"testdata/rootCA.cert", "testdata/rootCA.cert2"}
var emptyCA = []string{"testdata/emptyfile"}
var missingCA = []string{"testdata/rootCANO"}

func TestNewClient(t *testing.T) {
	cfg, err := NewClientTLSConfig(false, zeroCAs, "", "")
	if err != nil {
		t.Error("Unexpected error with minimalist NewClientTLSConfig", err)
	}
	if cfg == nil {
		t.Error("Expected a config back from NewClientTLSConfig when no error returned")
	}
	cfg, err = NewClientTLSConfig(true, zeroCAs, "", "")
	if err != nil {
		t.Error("Unexpected error with almost minimalist NewClientTLSConfig", err)
	}
	if cfg == nil {
		t.Error("Expected a config back from NewClientTLSConfig when no error returned")
	}

	// Good path tests
	cfg, err = NewClientTLSConfig(false, oneCA, "testdata/proxy.cert", "testdata/proxy.key")
	if err != nil {
		t.Error("Unexpected error with good data files", err)
	}
	cfg, err = NewClientTLSConfig(true, oneCA, "testdata/proxy.cert", "testdata/proxy.key")
	if err != nil {
		t.Error("Unexpected error with good data files and useSystemRoot", err)
	}

	// Wrong path test
	cfg, err = NewClientTLSConfig(false, oneCA, "testdata/proxy.key", "testdata/proxy.cert")
	if err == nil {
		t.Error("Expected error with switch key and cert files")
	}

	// Bad path tests
	cfg, err = NewClientTLSConfig(false, oneCA, "testdata/proxy.cert", "")
	if err == nil {
		t.Error("Expected error with missing key file")
	}
	cfg, err = NewClientTLSConfig(false, oneCA, "", "testdata/proxy.key")
	if err == nil {
		t.Error("Expected error with missing cert file")
	}
	cfg, err = NewClientTLSConfig(true, emptyCA, "testdata/proxy.cert", "testdata/proxy.key")
	if err == nil {
		t.Error("Expected an error with an empty root CA")
	}
	cfg, err = NewClientTLSConfig(true, missingCA, "testdata/proxy.cert", "testdata/proxy.key")
	if err == nil {
		t.Error("Expected an error return with a bad rootCA file")
	}
	cfg, err = NewClientTLSConfig(true, oneCA, "testdata/proxy.certNO", "testdata/proxy.key")
	if err == nil {
		t.Error("Expected an error return with a bad proxy certificate file")
	}
}
