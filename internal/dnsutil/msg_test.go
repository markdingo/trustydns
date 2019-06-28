package dnsutil

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// Reduce RSI!
func checkFatal(t *testing.T, err error, what string) {
	if err != nil {
		t.Fatal("Unexpected failure generating test data ", what, err)
	}
}

func TestFindOPT(t *testing.T) {
	mno := &dns.Msg{}
	if opt := FindOPT(mno); opt != nil {
		t.Error("FindOPT found an OPT RR in an empty message")
	}

	mno.Answer = append(mno.Answer, &dns.OPT{}) // Populate all-but Extra
	mno.Ns = append(mno.Ns, &dns.OPT{})
	if opt := FindOPT(mno); opt != nil {
		t.Error("FindOPT found an OPT RR in an empty Extra list")
	}

	myes := &dns.Msg{}
	newOpt := &dns.OPT{}
	myes.Extra = append(myes.Extra, newOpt)
	opt := FindOPT(myes)
	if opt == nil {
		t.Error("FindOPT did not an OPT RR")
	}

	if newOpt != opt {
		t.Error("FindOPT returned the wrong OPT RR")
	}
}

//////////////////////////////////////////////////////////////////////

func TestFindECS(t *testing.T) {
	mno := &dns.Msg{}
	if opt, _ := FindECS(mno); opt != nil {
		t.Error("FindECS found an OPT RR in an empty message")
	}

	mno.Answer = append(mno.Answer, &dns.OPT{}) // Populate all lists with an unpopulated OPT
	mno.Ns = append(mno.Ns, &dns.OPT{})
	mno.Extra = append(mno.Extra, &dns.OPT{})
	if opt, _ := FindECS(mno); opt != nil {
		t.Error("FindECS found an OPT RR in an unpopulated OPT")
	}

	myes := &dns.Msg{}
	newOpt := &dns.OPT{}
	newSubOpt := &dns.EDNS0_SUBNET{}
	newOpt.Option = append(newOpt.Option, newSubOpt)
	myes.Extra = append(myes.Extra, newOpt)
	opt, subOpt := FindECS(myes)
	if opt == nil {
		t.Error("FindECS did not find the OPT RR")
	}
	if subOpt == nil {
		t.Error("FindECS did not find the EDNS0_SUBNET")
	}
	if opt != newOpt {
		t.Error("FindECS found the wrong OPT")
	}
	if subOpt != newSubOpt {
		t.Error("FindECS found the wrong EDNS0_SUBNET")
	}
}

//////////////////////////////////////////////////////////////////////

func TestRemoveEDNS0Single(t *testing.T) {
	m := &dns.Msg{}
	if RemoveEDNS0FromOPT(m, dns.EDNS0SUBNET) {
		t.Error("RemoveEDNS0FromOPT claimed success with an empty message")
	}

	newOpt := &dns.OPT{}
	newSubOpt := &dns.EDNS0_SUBNET{}
	newOpt.Option = append(newOpt.Option, newSubOpt)
	m.Extra = append(m.Extra, newOpt)

	opt, subOpt := FindECS(m) // Make sure FindECS works the first time
	if opt == nil {
		t.Error("FindECS did not find the OPT RR prior to RemoveEDNS0FromOPT(dns.EDNS0SUBNET)")
	}
	if subOpt == nil {
		t.Error("FindECS did not find the EDNS0_SUBNET prior to RemoveEDNS0FromOPT(dns.EDNS0SUBNET)")
	}

	if !RemoveEDNS0FromOPT(m, dns.EDNS0SUBNET) {
		t.Error("RemoveEDNS0FromOPT() failed to remove existing ECS")
	}

	opt, subOpt = FindECS(m) // This should now fail
	if opt != nil || subOpt != nil {
		t.Error("FindECS had unexpected success after RemoveEDNS0FromOPT(dns.EDNS0SUBNET)")
	}
}

// Test RemoveEDNS0FromOPT when multiple OPTs are present. This is potentially a malformed message
// but RemoveEDNS0FromOPT is purposely as aggressive as it can be.
func TestRemoveECSMultiple(t *testing.T) {
	m := &dns.Msg{}
	newOpt := &dns.OPT{}
	newSubOpt := &dns.EDNS0_SUBNET{}
	newOpt.Option = append(newOpt.Option, newSubOpt)
	newOther := &dns.NS{}
	m.Extra = append(m.Extra, newOther, newOpt, newOpt, newOpt, newOther)

	opt, subOpt := FindECS(m) // Make sure FindECS works the first time
	if opt == nil {
		t.Error("FindECS did not find the OPT RR prior to RemoveEDNS0FromOPT()")
	}
	if subOpt == nil {
		t.Error("FindECS did not find the EDNS0_SUBNET prior to RemoveEDNS0FromOPT()")
	}

	if !RemoveEDNS0FromOPT(m, dns.EDNS0SUBNET) {
		t.Error("RemoveEDNS0FromOPT failed to remove existing ECS")
	}

	// RemoveEDNS0FromOPT removes empty OPT RRs which they should be in this case
	opt = FindOPT(m)
	if opt != nil {
		t.Error("FindOPT had unexpected success when an empty OPT should have been removed")
	}

	opt, subOpt = FindECS(m) // This should now fail
	if opt != nil || subOpt != nil {
		t.Error("FindECS had unexpected success after RemoveEDNS0FromOPT")
	}

	if len(m.Extra) != 2 {
		t.Error("Should have two remaining NS RRs in Extra. Not", len(m.Extra))
	}
}

// If the OPT has other subopts in it then RemoveEDNS0FromOPT should leave those intact
func TestRemoveNonEmptyOPT(t *testing.T) {
	m := &dns.Msg{}
	newOpt := &dns.OPT{}
	newOpt.Option = append(newOpt.Option,
		&dns.EDNS0_COOKIE{},
		&dns.EDNS0_PADDING{},
		&dns.EDNS0_SUBNET{},
		&dns.EDNS0_PADDING{})
	m.Extra = append(m.Extra, newOpt)

	opt, subOpt := FindECS(m) // Make sure Find succeeds the first time round
	if opt == nil || subOpt == nil {
		t.Error("FindECS did not find embedded EDNS0_SUBNET")
	}

	if !RemoveEDNS0FromOPT(m, dns.EDNS0SUBNET) {
		t.Error("RemoveEDNS0FromOPT failed to remove embedded EDNS0_SUBNET")
	}
	opt, subOpt = FindECS(m) // Make sure Find fails
	if opt != nil || subOpt != nil {
		t.Error("FindECS did not fail after removal of embedded EDNS0_SUBNET")
	}

	opt = FindOPT(m) // But FindOPT should succeed!
	if opt == nil {
		t.Fatal("FindOPT failed but it should have found the multi-subopt OPT")
	}
	if len(opt.Option) != 3 {
		t.Error("Wrong number of remaining subopts. Expected 3, got", len(opt.Option))
	}

	// Now remove other types to make sure RemoveEDNS0FromOPT isn't type sensitive

	if !RemoveEDNS0FromOPT(m, dns.EDNS0COOKIE) {
		t.Error("RemoveEDNS0FromOPT failed to remove embedded EDNS0_COOKIE")
	}
	opt = FindOPT(m) // Re-get the opt as it may bave been re-generated
	if opt == nil {
		t.Fatal("FindOPT failed but it should have found the multi-subopt OPT")
	}
	if len(opt.Option) != 2 {
		t.Error("Wrong number of remaining subopts. Expected 2, got", len(opt.Option), opt)
	}

	if !RemoveEDNS0FromOPT(m, dns.EDNS0PADDING) {
		t.Error("RemoveEDNS0FromOPT failed to remove all embedded EDNS0_PADDING")
	}
	opt = FindOPT(m) // Re-get the opt as it may bave been re-generated
	if opt != nil {
		t.Error("OPT should have been removed when last subopt was removed")
	}
}

func TestCreateECS(t *testing.T) {
	m := &dns.Msg{}
	CreateECS(m, 1, 19, net.IP{})

	opt, subOpt := FindECS(m)
	if opt == nil || subOpt == nil {
		t.Error("FindECS did not find the CreateECS ECS")
	}

	if subOpt.Family != 1 {
		t.Error("CreateECS created wrong family. Want 1, got", subOpt.Family)
	}

	if subOpt.SourceNetmask != 19 {
		t.Error("CreateECS created wrong SourceNetmask. Want 19, got", subOpt.SourceNetmask)
	}

	// Make sure no other damage to the message

	if len(m.Extra) != 1 {
		t.Error("Should be exactly one OPT, not", len(m.Extra))
	}

	// Create with a prepopulated OPT

	m2 := &dns.Msg{}
	m2.Extra = append(m2.Extra, &dns.OPT{})

	CreateECS(m2, 2, 71, net.IP{})

	opt, subOpt = FindECS(m2)
	if opt == nil || subOpt == nil {
		t.Error("FindECS did not find the CreateECS ECS with existing OPT")
	}

	if subOpt.Family != 2 {
		t.Error("CreateECS created wrong family. Want 2, got", subOpt.Family)
	}

	if subOpt.SourceNetmask != 71 {
		t.Error("CreateECS created wrong SourceNetmask. Want 71, got", subOpt.SourceNetmask)
	}
}

func TestReduceTTL(t *testing.T) {
	a1, err := dns.NewRR("a.name.example.net. 3 IN A 1.2.3.4") // Create non-sensical but valid message
	checkFatal(t, err, "newRR a1")
	a2, err := dns.NewRR("b.name.example.net. 300 IN AAAA fe80::f0a2:46ff:feb5:3c98")
	checkFatal(t, err, "newRR a2")
	a3, err := dns.NewRR("compress.name.example.net. 10 IN TXT 'Some text'")
	checkFatal(t, err, "newRR a3")
	n1, err := dns.NewRR("nocompress.example.com. 11 IN NS a.ns.example.net.")
	checkFatal(t, err, "newRR n1")
	n2, err := dns.NewRR("c.name.example.net. 12 IN NS b.ns.example.net.")
	checkFatal(t, err, "newRR n2")
	e1, err := dns.NewRR("d.name.example.com. 13 IN SOA internal.e hostmaster. 1554301415 16384 2048 1048576 480")
	checkFatal(t, err, "newRR e1")
	e2, err := dns.NewRR("d.name.example.net. 2 IN MX 10 smtp.example.net.")
	checkFatal(t, err, "newRR e2")

	m := &dns.Msg{
		Answer: []dns.RR{a1, a2, a3},
		Ns:     []dns.RR{n1, n2},
		Extra:  []dns.RR{e1, e2},
	}

	tt := []struct {
		rr           dns.RR
		expectedType uint16
		expectedTTL  uint32
		why          string
	}{
		{a1, dns.TypeA, 2, "Reduces by 1 to minimum"},
		{a2, dns.TypeAAAA, 290, "Normal reduction without limits"},
		{a3, dns.TypeTXT, 2, "Reduces by 8 to minimum"},
		{n1, dns.TypeNS, 2, "Reduces by 9 to minimum"},
		{n2, dns.TypeNS, 2, "Reduces by 10 to minimum"},
		{e1, dns.TypeSOA, 3, "Reduces by 10 to 3"},
		{e2, dns.TypeMX, 2, "Unchanged at 2"},
	}

	rc := ReduceTTL(m, 10, 2000) // This should do nothing because minimum is so large
	if len(m.Answer) != 3 || len(m.Ns) != 2 || len(m.Extra) != 2 {
		t.Fatal("Message RR Counts have been modified!")
	}
	if rc > 0 {
		t.Error("ReduceTTL reduced below minimum of 2000", rc)
	}

	rc = ReduceTTL(m, 10, 2) // This should change most of the RRs
	if len(m.Answer) != 3 || len(m.Ns) != 2 || len(m.Extra) != 2 {
		t.Fatal("Message RR Counts have been modified!")
	}
	if rc != 6 {
		t.Error("ReduceTTL should have reduced 6, not", rc)
	}

	for ix, tc := range tt {
		hdr := tc.rr.Header()
		if hdr.Class != dns.ClassINET {
			t.Error(ix, tc.why, "qClass has changed to", hdr.Class)
		}
		if hdr.Rrtype != tc.expectedType {
			t.Error(ix, tc.why, "qType has changed to", hdr.Rrtype, "from", tc.expectedType)
		}
		if hdr.Ttl != tc.expectedTTL {
			t.Error(ix, tc.why, "TTL of", hdr.Ttl, "is not the expected", tc.expectedTTL)
		}
	}
}
