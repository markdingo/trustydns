package constants

import (
	"testing"
)

func TestPostGet(t *testing.T) {
	if readOnlyConstants == nil {
		t.Error("Expected readOnlyConstants to be set by init() prior to me")
	}
}

// TestValues tests that at least a few of the constants have been
// initialized. Too tiresome to test them all and obviously of limited
// value.
func TestValues(t *testing.T) {
	consts := Get()
	if len(consts.ProxyProgramName) == 0 {
		t.Error("consts.ProxyProgramName should be set but it's zero length")
	}
	if len(consts.RFC) == 0 {
		t.Error("consts.RFC should be set but it's zero length")
	}

	if len(consts.HTTPSDefaultPort) == 0 {
		t.Error("consts.HTTPSDefaultPort should be set but it's zero length")
	}
	if len(consts.TrustySynthesizeECSRequestHeader) == 0 {
		t.Error("consts.TrustySynthesizeECSRequestHeader should be set but it's zero length")
	}

	if len(consts.DNSDefaultPort) == 0 {
		t.Error("consts.DNSDefaultPort should be set but it's zero length")
	}
	if consts.MinimumViableDNSMessage == 0 {
		t.Error("consts.MinimumViableDNSMessage should be set but it's zero")
	}
}
