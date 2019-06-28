package local

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/markdingo/trustydns/internal/resolver"

	"github.com/miekg/dns"
)

func TestNew(t *testing.T) {
	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf"})
	if res == nil || err != nil {
		t.Error("New() failed which it should have succeeded", err)
	}

	res, err = New(Config{ResolvConfPath: ""})
	if err == nil {
		t.Error("New() did not failed with an empty path")
	}

	res, err = New(Config{ResolvConfPath: "testdata/does-not-exist"})
	if err == nil {
		t.Error("New() did not failed with a non-existent path")
	}

	res, err = New(Config{ResolvConfPath: "testdata/simplest.resolv.conf"})
	if err != nil {
		t.Error("New() fail with testdata/simplest.resolv.conf")
	}

	res, err = New(Config{ResolvConfPath: "testdata/empty.resolv.conf"})
	if err == nil {
		t.Error("New() should have fail with testdata/empty.resolv.conf")
	}

	res, err = New(Config{ResolvConfPath: "testdata/resolv.conf", LocalDomains: []string{"..Example.org"}})
	if err == nil {
		t.Error("Expected a double dot error with ..Example.org")
	}
	if !strings.Contains(err.Error(), "Double dots") {
		t.Error("Expected return error to complain about double dots, not", err)
	}
}

//////////////////////////////////////////////////////////////////////

func TestInBailiwickSimple(t *testing.T) {
	res, err := New(Config{ResolvConfPath: "testdata/simplest.resolv.conf"})
	if res == nil {
		t.Fatal("New() failed unexpectedly", err)
	}

	if res.InBailiwick("unqualified") { // Should fail as no "local" domain
		t.Error("unqalified did not fail with simplest.resolv.conf")
	}

	if res.InBailiwick("qualified.example.com") { // Should fail as example.com is not in search
		t.Error("qualified.example.com did not fail with simplest.resolv.conf")
	}
}

type ibTestCase struct {
	qName string
	ok    bool
	desc  string
}

var ibTestCases = []ibTestCase{{"unqualified", true, "unqualified failed with a non-empty resolv.conf"},
	{"good.dom.example.org", true, "Should have suffixed matched 'domain' entry"},
	{"example.com", true, "Should have *exact* matched LocalDomains:"},
	{"match.search1.example.net", true, "Should have suffix matched first 'search' entry"},
	{"search1.example.net", true, "Should have exact matched first 'search' entry"},
	{"match.search2.example.net", true, "Should have suffix matched second 'search' entry"},
	{"search2.example.net", true, "Should have exact matched second 'search' entry"},
	{"1.120.0.10.in-addr.arpa", true, "Should have suffix matched third 'search' entry"},
	{"matchsearch1.example.net", false, "A fake in-domain name matched unexpectedly"},
	{"good.exampLe.CoM", true, "Mixed case didn't match LocalDomains:"},
}

// resolv.conf has:
// search search1.example.net search2.exAmple.net 120.0.10.in-addr.arpa
func TestInBailiwickCases(t *testing.T) {
	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf",
		LocalDomains: []string{"EXample.COM", ".example.org"}})
	if err != nil {
		t.Fatal("New() failed unexpectedly", err)
	}

	for tx, tc := range ibTestCases {
		ok := res.InBailiwick(tc.qName)
		if ok != tc.ok {
			t.Error(tx, tc.qName, ok, "-", tc.desc)
		}
	}
}

// Different dot combinations
func TestInBailiwickDots(t *testing.T) {
	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf",
		LocalDomains: []string{".1.Example.org", "2.Example.org", ".3.Example.org."}})
	if err != nil {
		t.Fatal("Unexpected error on setup", err)
	}
	for _, domain := range []string{"a.1.example.Org", "b.2.example.Org", "c.3.example.Org"} {
		if !res.InBailiwick(domain) {
			t.Error("Expected domain to be InBailiwick in spite of dots", domain)
		}
	}
}

// Duplicate search1 domain  and guard dots should be removed.
func TestInBailiwickDomains(t *testing.T) {
	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf",
		LocalDomains: []string{".1.Example.org", "2.Example.org", "search1.example.net", ".3.Example.org."}})
	if err != nil {
		t.Fatal("Unexpected error on setup", err)
	}
	dList := res.InBailiwickDomains()
	if len(dList) != 6 {
		t.Error("Expected six InBailiwickDomains, not", dList)
	}
	found := false
	for _, d := range dList {
		if d == "3.example.org" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Should have found normalized and de-guarded 3.example.org", dList)
	}
}

//////////////////////////////////////////////////////////////////////
// The mock exchanger replaces the regular dns.Client.Exchange() interface. It contains an array of
// return values which are returned successively in each call to Exchange. Nothing fancy.

type mockResponse struct {
	reply    *dns.Msg
	duration time.Duration
	err      error
}

type mockExchanger struct {
	ix       int // Next response to return
	response []mockResponse
}

func (me *mockExchanger) append(reply *dns.Msg, duration time.Duration, err error) {
	me.response = append(me.response, mockResponse{reply, duration, err})
}

func (me *mockExchanger) Exchange(query *dns.Msg, server string) (reply *dns.Msg, rtt time.Duration, err error) {
	ix := me.ix
	if ix >= len(me.response) {
		return nil, 0, errors.New("Test setup probably bogus as exchange count exceeded")
	}
	me.ix++
	return me.response[ix].reply, me.response[ix].duration, me.response[ix].err
}

// Helpers to construct common mocks
func newMockOne(reply *dns.Msg, duration time.Duration, err error) *mockExchanger {
	me := &mockExchanger{}
	me.append(reply, duration, err)

	return me
}

func newMockRcode(rcode int) *mockExchanger {
	r := &dns.Msg{}
	r.MsgHdr.Rcode = rcode

	return newMockOne(r, time.Millisecond, nil)
}

//////////////////////////////////////////////////////////////////////

var (
	qMeta = &resolver.QueryMetaData{}
)

// This test is mainly checking the normal path thru resolution without any errors. The least
// interesting path of a test I guess, but the most interesting path for everyone else.  In this
// test we make our own exchanger so we can control the resolution process By default our Exchanger
// makes a good return with an empty reply but resolver doesn't check any of that stuff and it
// simply comes back as a good return.
func TestBasicResolver(t *testing.T) {
	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf",
		NewDNSClientExchangerFunc: func(string) DNSClientExchanger {
			return newMockOne(&dns.Msg{}, time.Second, nil)
		}})
	if err != nil {
		t.Fatal("New failed with mock Exchanger", err)
	}

	_, _, err = res.Resolve(&dns.Msg{}, qMeta)
	if err != nil {
		t.Fatal("Mock Exchanger failed", err)
	}
}

func TestNXDomain(t *testing.T) {
	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf",
		NewDNSClientExchangerFunc: func(string) DNSClientExchanger {
			return newMockRcode(dns.RcodeNameError)
		}})
	if err != nil {
		t.Fatal("New failed with mock Exchanger", err)
	}

	r, _, err := res.Resolve(&dns.Msg{}, qMeta)
	if err != nil {
		t.Fatal("Mock Exchanger failed", err)
	}

	if r.Rcode != dns.RcodeNameError {
		t.Error("Resolver didn't stop on NXDomain", r.MsgHdr)
	}
}

// Test various Resolv retry paths
func TestRetry(t *testing.T) {
	res, _ := New(Config{ResolvConfPath: "testdata/simplest.resolv.conf"})
	_, _, err := res.Resolve(&dns.Msg{}, qMeta)
	if err == nil {
		t.Error("An empty resolv.conf should not be able to resolve anything!")
	}

	// This next set of tests actually tests a couple of paths in the resolver go. It tests:
	//
	// - iterations over different servers
	// - reaching retry limit
	// - using ipv4 and ipv6 server addresses
	//
	// I could break these out into separate tests but it would be exactly the same code
	// repeated three times so why bother as I get the coverage with a single request.

	res, err = New(Config{ResolvConfPath: "testdata/timeout.resolv.conf"}) // Relies on no listeners on :65053
	if err != nil {
		t.Fatal("New unexpectedly failed with testdata/timeout.resolv.conf", err)
	}
	_, _, err = res.Resolve(&dns.Msg{}, qMeta) // Should fail on retries

	if err == nil {
		t.Fatal("Expected an error from Retries test with testdata/loopback.resolv.conf")
	}
	if !strings.Contains(err.Error(), "Query attempts exceeded") {
		t.Error("Got wrong error from Retry times", err)
	}
}

// Test for timeout exceeded
func TestTimeout(t *testing.T) {
	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf",
		NewDNSClientExchangerFunc: func(string) DNSClientExchanger {
			return newMockOne(nil, time.Second*5, errors.New("Timeout"))
		}})
	if err != nil {
		t.Fatal("New failed with mock Exchanger", err)
	}

	q := &dns.Msg{}
	q.MsgHdr.Id = 1002 // Make it easier to identify
	_, _, err = res.Resolve(q, qMeta)
	if err == nil {
		t.Fatal("Resolver MAX RTT exceeded should have failed")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Error("Got the expected error return but not with a timeout message:", err)
	}
}

// Test for rcode == refused moves best server to next
func TestRcodeRefused(t *testing.T) {
	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf",
		NewDNSClientExchangerFunc: func(string) DNSClientExchanger {
			return newMockRcode(dns.RcodeRefused)
		}})
	if err != nil {
		t.Fatal("New failed with mock Exchanger", err)
	}

	q := &dns.Msg{}
	q.MsgHdr.Id = 2003 // Make it easier to identify
	_, _, err = res.Resolve(q, qMeta)
	if err == nil {
		t.Fatal("Expected error return with Rcode Refused")
	}
	bs, _ := res.bestServer.Best()
	if bs.Name() != "10.0.0.3:53" {
		t.Error("Expected Best Server to be 10.0.0.3, not", bs.Name())
	}
}

// Test for rcode == ServerFailure moves best server to next
func TestRcodeServerFailure(t *testing.T) {
	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf",
		NewDNSClientExchangerFunc: func(string) DNSClientExchanger {
			return newMockRcode(dns.RcodeServerFailure)
		}})
	if err != nil {
		t.Fatal("New failed with mock Exchanger", err)
	}

	q := &dns.Msg{}
	q.MsgHdr.Id = 2004
	_, _, err = res.Resolve(q, qMeta)
	if err == nil {
		t.Fatal("Expected error return with Rcode ServerFailure")
	}
	bs, _ := res.bestServer.Best()
	if bs.Name() != "10.0.0.3:53" {
		t.Error("Expected Best Server to be 10.0.0.3, not", bs.Name())
	}
}

// Test for rcode == FORMERR stops iteration as query has a format problem
func TestRcodeFormErr(t *testing.T) {
	me := &mockExchanger{}
	r0 := &dns.Msg{}
	r0.Rcode = dns.RcodeFormatError
	r0.Id = 9000
	me.append(r0, time.Millisecond, nil)
	r1 := &dns.Msg{}
	r1.Id = 9001
	me.append(r1, time.Millisecond, nil)
	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf",
		NewDNSClientExchangerFunc: func(string) DNSClientExchanger {
			return me
		}})
	if err != nil {
		t.Fatal("New failed with mock Exchanger", err)
	}
	q := &dns.Msg{}
	r, _, err := res.Resolve(q, qMeta)
	if err != nil {
		t.Fatal("Unexpected error from Resolve:", err)
	}
	if r.Rcode != dns.RcodeFormatError {
		t.Error("Expected dns.RcodeFormatError, not", r.MsgHdr)
	}
}

// Not Impl should move to the next server
func TestRcodeNotImpl(t *testing.T) {
	me := &mockExchanger{}
	r0 := &dns.Msg{}
	r0.Rcode = dns.RcodeNotImplemented
	r0.Id = 9000
	me.append(r0, time.Millisecond, nil)
	r1 := &dns.Msg{}
	r1.Id = 9001
	me.append(r1, time.Millisecond, nil)
	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf",
		NewDNSClientExchangerFunc: func(string) DNSClientExchanger {
			return me
		}})
	if err != nil {
		t.Fatal("New failed with mock Exchanger", err)
	}
	q := &dns.Msg{}
	r, _, err := res.Resolve(q, qMeta)
	if err != nil {
		t.Fatal("Unexpected error from Resolve:", err)
	}
	if r.Id != 9001 {
		t.Error("Expected dns.RcodeNotImplemented, not", r.MsgHdr)
	}
}

func TestRcodeOther(t *testing.T) {
	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf",
		NewDNSClientExchangerFunc: func(string) DNSClientExchanger {
			return newMockRcode(dns.RcodeBadSig)
		}})
	if err != nil {
		t.Fatal("New failed with mock Exchanger", err)
	}
	q := &dns.Msg{}
	r, _, err := res.Resolve(q, qMeta)
	if err != nil {
		t.Fatal("Unexpected error from Resolve:", err)
	}
	if r.Rcode != dns.RcodeBadSig {
		t.Error("Expected dns.RcodeBadSig, not", r.MsgHdr)
	}
}

// Test that the return meta details about the resolution seem reasonable
func TestReplyMeta(t *testing.T) {
	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf",
		NewDNSClientExchangerFunc: func(string) DNSClientExchanger {
			return newMockOne(&dns.Msg{}, time.Second, nil)
		}})
	if err != nil {
		t.Fatal("New failed with mock Exchanger", err)
	}
	_, rMeta, err := res.Resolve(&dns.Msg{}, qMeta)
	if err != nil {
		t.Error("Did not expect an error from Resolve()", err)
	}
	if rMeta == nil {
		t.Error("rMeta from .Resolve() should not be nil on a good return")
	}
	if rMeta.TransportDuration == 0 ||
		rMeta.ResolutionDuration == 0 ||
		rMeta.PayloadSize == 0 ||
		rMeta.QueryTries == 0 ||
		rMeta.ServerTries == 0 ||
		rMeta.FinalServerUsed == "" {
		t.Error("rMeta returned from Resolve seem unpopulated", rMeta)
	}
}

// Test that a UDP truncated response falls back to TCP.
func TestResolveFallback(t *testing.T) {

	// This test simply checks that a truncated UDP response falls back to TCP which returns a
	// successful response.

	mte := &mockExchanger{}
	r0 := &dns.Msg{}
	r0.MsgHdr.Id = 3001
	r0.Truncated = true
	mte.append(r0, time.Second, nil)

	r1 := &dns.Msg{}
	r1.SetQuestion("Randomlength.example.net", dns.TypeNS)
	r1.MsgHdr.Id = 3002 // Id differentiatess between the UDP response above this this tcp response
	mte.append(r1, time.Second, nil)

	res, err := New(Config{ResolvConfPath: "testdata/resolv.conf",
		NewDNSClientExchangerFunc: func(string) DNSClientExchanger {
			return mte
		}})
	if err != nil {
		t.Fatal("Test setup failed unexpectedly", err)
	}
	r, meta, err := res.Resolve(&dns.Msg{}, qMeta)
	if r.MsgHdr.Id != r1.MsgHdr.Id {
		t.Error("Wrong response was returned. Expected TCP with id", r1.MsgHdr.Id, "not", r.MsgHdr)
	}
	if meta.TransportType != resolver.DNSTransportTCP {
		t.Error("Wrong transport returned. Expected resolver.DNSTransportTCP, got", meta)
	}
	if meta.QueryTries != 2 {
		t.Error("Expected two query tries overall, not", meta)
	}
	if meta.ServerTries != 1 {
		t.Error("Expected one server try overall, not", meta)
	}
	if meta.PayloadSize != r1.Len() {
		t.Error("Wrong message length returned. Expected", r1.Len(), "got", meta)
	}

	// The test also falls back to TCP, but the TCP returns a failure so Resolv() should return
	// the original truncated UDP response.

	mte = &mockExchanger{}
	r0 = &dns.Msg{}
	r0.MsgHdr.Id = 4001
	r0.Truncated = true // Force fall back to TCP
	mte.append(r0, time.Millisecond, nil)
	r1 = &dns.Msg{}
	r1.MsgHdr.Id = 4002
	r1.MsgHdr.Rcode = dns.RcodeServerFailure // Force iteration to next server *and* back to UDP
	mte.append(r1, time.Millisecond, nil)

	res, err = New(Config{ResolvConfPath: "testdata/resolv.conf",
		NewDNSClientExchangerFunc: func(string) DNSClientExchanger {
			return mte
		}})
	if err != nil {
		t.Fatal("Test setup failed unexpectedly", err)
	}
	r, meta, err = res.Resolve(&dns.Msg{}, qMeta)
	if r.MsgHdr.Id != r0.MsgHdr.Id {
		t.Error("Wrong response was returned. Expected TCP with id=", r0.MsgHdr.Id, "not", r.MsgHdr)
	}
	if meta.TransportType != resolver.DNSTransportUDP {
		t.Error("Wrong transport returned. Expected resolver.DNSTransportUDP, got", meta)
	}
	if meta.QueryTries != 2 {
		t.Error("Expected two query tries overall, not", meta)
	}
	if meta.ServerTries != 1 {
		t.Error("Expected one server try overall, not", meta)
	}
	if meta.PayloadSize != r0.Len() {
		t.Error("Wrong message length returned. Expected", r0.Len(), "got", meta)
	}
}
