package dnsutil

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const allOpts = "NSID,ECS[24/16],COOKIE,UL,LLQ,DAU,DHU,7,LOCAL,PAD"

func TestCompactString(t *testing.T) {
	a1, err := dns.NewRR("a.name.example.net. 300 IN A 1.2.3.4") // Create non-sensical but valid message
	checkFatal(t, err, "newRR a1")
	a2, err := dns.NewRR("a.name.example.net. 300 IN AAAA fe80::f0a2:46ff:feb5:3c98")
	checkFatal(t, err, "newRR a2")
	a3, err := dns.NewRR("compress.name.example.net. 300 IN TXT 'Some text'")
	checkFatal(t, err, "newRR a3")
	a4, err := dns.NewRR("service.example.net. 300 IN SRV 10 20 30 host1.example.net.")
	checkFatal(t, err, "newRR a4")
	n1, err := dns.NewRR("nocompress.example.com. 300 IN NS a.ns.example.net.")
	checkFatal(t, err, "newRR n1")
	n2, err := dns.NewRR("example.net. 600 IN NS b.ns.example.net.")
	checkFatal(t, err, "newRR n2")
	e1, err := dns.NewRR("example.com. 600 IN SOA internal.e hostmaster. 1554301415 16384 2048 1048576 480")
	checkFatal(t, err, "newRR e1")
	e2, err := dns.NewRR("example.net. 600 IN MX 10 smtp.example.net.")
	checkFatal(t, err, "newRR e2")

	m1 := &dns.Msg{
		Answer: []dns.RR{a1, a2, a3, a4},
		Ns:     []dns.RR{n1, n2},
		Extra:  []dns.RR{e1, e2},
	}

	m1.SetQuestion("a.name.example.net.", dns.TypeMX)
	s1 := CompactMsgString(m1)
	if !strings.Contains(s1, "AAAA*") {
		t.Error("Expected CompactMsgString to print out the AAAA", s1)
	}

	m1.MsgHdr.Response = true // Set all the bits to get the Ratsack decode
	m1.MsgHdr.Authoritative = true
	m1.MsgHdr.Truncated = true
	m1.MsgHdr.RecursionDesired = true
	m1.MsgHdr.RecursionAvailable = true
	m1.MsgHdr.Zero = true
	m1.MsgHdr.AuthenticatedData = true
	m1.MsgHdr.CheckingDisabled = true

	s1 = CompactMsgString(m1)
	if !strings.Contains(s1, "RATdaZsx") {
		t.Error("Expected CompactMsgString to generate 'RATdaZsx' to represent all header bits", s1)
	}

	// Create (almost) every OPT type on the planet!

	opt := NewOPT() // Use the official function to get/check legit OPT values
	opt.Option = append(opt.Option,
		&dns.EDNS0_NSID{},
		&dns.EDNS0_SUBNET{SourceNetmask: 24, SourceScope: 16},
		&dns.EDNS0_COOKIE{},
		&dns.EDNS0_UL{},
		&dns.EDNS0_LLQ{},
		&dns.EDNS0_DAU{},
		&dns.EDNS0_DHU{},
		&dns.EDNS0_N3U{}, // This is purposely unknown to CompactMsgString() to exercise the default switch
		&dns.EDNS0_LOCAL{},
		&dns.EDNS0_PADDING{})

	m1.Extra = append(m1.Extra, opt)
	s1 = CompactMsgString(m1)
	if !strings.Contains(s1, allOpts) {
		t.Error("Expected CompactMsgString to contain", allOpts, "not", s1)
	}

	if !strings.Contains(s1, "OPT(0,0,4096") {
		t.Error("Expected Extended OPT output", s1)
	}
}
