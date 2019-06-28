package dnsutil

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestPadding(t *testing.T) {
	a1, err := dns.NewRR("a.name.example.net. 300 IN A 1.2.3.4") // Create non-sensical but valid message
	checkFatal(t, err, "newRR a1")
	a2, err := dns.NewRR("a.name.example.net. 300 IN AAAA fe80::f0a2:46ff:feb5:3c98")
	checkFatal(t, err, "newRR a2")
	a3, err := dns.NewRR("compress.name.example.net. 300 IN TXT 'Some text'")
	checkFatal(t, err, "newRR a3")
	n1, err := dns.NewRR("nocompress.example.com. 300 IN NS a.ns.example.net.")
	checkFatal(t, err, "newRR n1")
	n2, err := dns.NewRR("example.net. 600 IN NS b.ns.example.net.")
	checkFatal(t, err, "newRR n2")
	e1, err := dns.NewRR("example.com. 600 IN SOA internal.e hostmaster. 1554301415 16384 2048 1048576 480")
	checkFatal(t, err, "newRR e1")
	e2, err := dns.NewRR("example.net. 600 IN MX 10 smtp.example.net.")
	checkFatal(t, err, "newRR e2")

	baseMsg := &dns.Msg{
		Answer: []dns.RR{a1, a2, a3},
		Ns:     []dns.RR{n1, n2},
		Extra:  []dns.RR{e1, e2},
	}

	tt := []struct {
		compress    bool
		modulo      int
		expectError bool
		canFuzz     bool
		what        string
	}{
		{false, 17, false, true, "Small size w/o compress"},
		{true, 17, false, true, "Small size with compress"},
		{false, 128, false, true, "Recommended query size"}, // RFC8467 recommended client padding size
		{true, 128, false, true, "Recommended query size"},
		{false, 468, false, true, "Recommended response size"}, // RFC8467 recommended client padding size
		{true, 468, false, true, "Recommended response size"},
		{false, 241, false, true, "Empirically determined compressed message size"},
		{true, 241, false, true, "Empirically determined compressed message size"},
		{false, 344, false, true, "Empirically determined uncompressed message size"},
		{true, 344, false, true, "Empirically determined uncompressed message size"},
		{false, 0, true, false, "Expect error due to small modulo"},
		{true, 0, true, false, "Expect error due to small modulo"},
		{false, 0, true, false, "Expect error due to small modulo"},
		{true, 0, true, false, "Expect error due to small modulo"},
		{false, 65535 + 1, true, false, "Expect error due to oversized modulo"},
		{true, 65535 + 1, true, false, "Expect error due to oversize modulo"},
	}

	for _, tc := range tt {
		start := tc.modulo
		end := tc.modulo
		if tc.canFuzz {
			start -= 4 // Fuzz around the specified values to catch boundary conditions
			end += 4
		}
		for mod := start; mod < end; mod++ {
			m1 := baseMsg.Copy()
			m1.Compress = tc.compress
			b, err := PadAndPack(m1, uint(mod))
			if (b == nil && err == nil) || (b != nil && err != nil) {
				t.Fatal("Both byte[] and err return cannot match", b, err)
			}
			switch {
			case err == nil && tc.expectError:
				t.Error("Expected error with", tc.what, "mod", uint(mod))
			case err != nil && !tc.expectError:
				t.Error("Unexpected Error with", tc.what, "mod", uint(mod), err)
			}
			if uint(mod) > 0 && b != nil {
				if len(b)%mod != 0 {
					t.Error("PadAndPack returned wrong length", len(b), mod)
				}
			}
		}
	}

	// Check for explicit size errors

	m1 := baseMsg.Copy()
	_, err = PadAndPack(m1, 0)
	if err == nil {
		t.Fatal("Expected error return with a zero modulo")
	}
	if !strings.Contains(err.Error(), "not in range") {
		t.Error("Expected error message to contain 'not in range'", err)
	}

	_, err = PadAndPack(m1, 70000)
	if err == nil {
		t.Fatal("Expected error return with a huge modulo")
	}
	if !strings.Contains(err.Error(), "not in range") {
		t.Error("Expected error message to contain 'not in range'", err)
	}

	// Force dns.Pack() errors that in turn to cause PadAndPack to fail. Triggering this error
	// relies on the internals of miekg/dns which may change in the future and invalidate this
	// test.

	m1 = baseMsg.Copy()
	m1.Rcode = 0xFFF + 1 // dns.Pack() checks this for valid ranges
	_, err = PadAndPack(m1, 200)
	if err == nil {
		t.Fatal("Expected error return with a zero modulo")
	}
	if !strings.Contains(err.Error(), "dns.Pack") {
		t.Error("Expected error message to contain 'dns.Pack'", err)
	}
}

// Use bogus RR values to cause dns.Pack() to produce a different length than that indicated by
// dns.Msg.Len() this in turn triggers an error path within PadAndPack()
func TestTriggerPackError(t *testing.T) {
	a1 := &dns.A{Hdr: dns.RR_Header{Name: "3.to.2.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3}}
	a2 := &dns.AAAA{Hdr: dns.RR_Header{Name: "300.to.290.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}}
	a3 := &dns.TXT{Hdr: dns.RR_Header{Name: "10to.2.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10}}

	n1 := &dns.NS{Hdr: dns.RR_Header{Name: "11.to.2.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 11}}
	n2 := &dns.NS{Hdr: dns.RR_Header{Name: "12.to.2.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 12}}

	e1 := &dns.SOA{Hdr: dns.RR_Header{Name: "13.to.3.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 13}}
	e2 := &dns.MX{Hdr: dns.RR_Header{Name: "2.to.2.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 2}}

	m1 := &dns.Msg{
		Answer: []dns.RR{a1, a2, a3},
		Ns:     []dns.RR{n1, n2},
		Extra:  []dns.RR{e1, e2},
	}

	_, err := PadAndPack(m1, 248)
	if !strings.Contains(err.Error(), "unexpected length") {
		t.Error("Expected error message to contain 'unexpected length'", err)
	}
}

func TestFindPadding(t *testing.T) {
	a1, err := dns.NewRR("a.name.example.net. 300 IN A 1.2.3.4") // Create non-sensical but valid message
	checkFatal(t, err, "newRR a1")
	a2, err := dns.NewRR("a.name.example.net. 300 IN AAAA fe80::f0a2:46ff:feb5:3c98")
	checkFatal(t, err, "newRR a2")
	a3, err := dns.NewRR("compress.name.example.net. 300 IN TXT 'Some text'")
	checkFatal(t, err, "newRR a3")
	n1, err := dns.NewRR("nocompress.example.com. 300 IN NS a.ns.example.net.")
	checkFatal(t, err, "newRR n1")
	n2, err := dns.NewRR("example.net. 600 IN NS b.ns.example.net.")
	checkFatal(t, err, "newRR n2")
	e1, err := dns.NewRR("example.com. 600 IN SOA internal.e hostmaster. 1554301415 16384 2048 1048576 480")
	checkFatal(t, err, "newRR e1")
	e2, err := dns.NewRR("example.net. 600 IN MX 10 smtp.example.net.")
	checkFatal(t, err, "newRR e2")

	m1 := &dns.Msg{
		Answer: []dns.RR{a1, a2, a3},
		Ns:     []dns.RR{n1, n2},
		Extra:  []dns.RR{e1, e2},
	}

	if FindPadding(m1) >= 0 {
		t.Error("Did not expect to find padding with base message")
	}

	CreateECS(m1, 1, 19, net.IP{}) // Put an OPT (that lacks a padding sub-opt) in the message

	if FindPadding(m1) > 0 {
		t.Error("Did not expect to find padding with base message+ECS OPT")
	}

	// Extra contains {e1, e2, ECS}. So [2] is where we add the padding opt

	padding := &dns.EDNS0_PADDING{Padding: make([]byte, 0)}
	rr := m1.Extra[2]

	opt, ok := rr.(*dns.OPT) // Get our OPT back
	if !ok {
		t.Fatal("Type assertion to dns.OPT failed unexpectedly")
	}
	opt.Option = append(opt.Option, padding) // Add padding to OPT

	if FindPadding(m1) == -1 { // And hopefully find it now!
		t.Error("Did not find padding when expected")
	}
}
