package doh

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/markdingo/trustydns/internal/dnsutil"
	"github.com/markdingo/trustydns/internal/resolver"

	"github.com/miekg/dns"
)

var (
	qMeta = &resolver.QueryMetaData{}
)

/*
As a general rule these test avoid using the pre-defined constants and values that the production
code uses. The reason for this is to avoid an error in the constants value and other
assumptions. Put another way, theses tests try not to rely on any code that the code being tested
relies on. That means hard-coded header names and query params and such. Point being when you see
hard-coded values in this test module, well, that's on purpose.
*/

// mockDoSimple is a HTTPClientDo mock which simulates the HTTP exchange with the DoH Server via the
// Do() method.
type mockDoSimple struct {
	request  http.Request
	response http.Response
	err      error
}

func (mds *mockDoSimple) Do(r *http.Request) (*http.Response, error) {
	mds.request = *r
	mds.response.Request = &mds.request
	if mds.response.Body == nil { // This causes nil pointer errors if left unset so be helpful
		mds.setBody("", "")
	}
	return &mds.response, mds.err
}

// http.Response.Body is an ioReaderCloser (and apparently soon to be an io.Writer as well) and
// since there are no public constructors for a fully formed http.Response we have to do so
// ourselves.
type mockReaderCloser struct {
	io.Reader
}

func (*mockReaderCloser) Close() error {
	return nil
}

func addHTTPResponseHeader(r *http.Response, k, v string) {
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.Header.Add(k, v)
}

func (mds *mockDoSimple) setBody(contentType, body string) {
	mds.response.Body = &mockReaderCloser{Reader: strings.NewReader(body)}
	if contentType == "" {
		contentType = "text/plain"
	}
	addHTTPResponseHeader(&mds.response, "Content-Type", contentType)
}

func (mds *mockDoSimple) setStatus(statusCode int, status string) {
	mds.response.StatusCode = statusCode
	mds.response.Status = status
}

// Most commonly we'll want to mock up a return DNS Message
func newMockDoSimple(statusCode int, status, contentType, body string) *mockDoSimple {
	mds := &mockDoSimple{}
	mds.response.Request = &mds.request
	mds.setStatus(statusCode, status)
	mds.setBody(contentType, body)

	return mds
}

func newMockDoSimpleMsg(m *dns.Msg) *mockDoSimple {
	b, err := m.Pack()
	if err != nil {
		panic(err)
	}
	return newMockDoSimple(200, "200 ok", "application/dns-message", string(b))
}

// Extract the DNS message from a previously GET/POST request - return nil if the message cannot be
// extracted. This can only be called once per POST mock as the Body is consumed and closed and I
// don't know of a way to "rewind" Request.Body.
func (mds *mockDoSimple) extractHTTPRequestMsg() (*dns.Msg, []byte) {
	switch {
	case mds.request.Method == http.MethodGet:
		qp := mds.request.URL.Query()
		qpData, ok := qp["dns"]
		if !ok {
			return nil, nil
		}
		if len(qpData) != 1 {
			return nil, nil
		}

		body, err := base64.URLEncoding.DecodeString(qpData[0])
		if err != nil {
			return nil, nil
		}
		m := &dns.Msg{}
		err = m.Unpack(body)
		if err != nil {
			return nil, nil
		}
		return m, body

	case mds.request.Method == http.MethodPost:
		if mds.request.Body == nil {
			return nil, nil
		}

		defer mds.request.Body.Close()
		body, err := ioutil.ReadAll(mds.request.Body)
		if err != nil {
			return nil, nil
		}

		m := &dns.Msg{}
		err = m.Unpack(body)
		if err != nil {
			return nil, nil
		}

		return m, body
	}

	return nil, nil
}

// Return a simple well-formed DNS Query Message
func baseDNSQueryMsg() *dns.Msg {
	msg := &dns.Msg{}
	msg.SetQuestion("doh.example.net.", dns.TypeA)

	return msg
}

// Test dohresolver constructor. This is a complicated constructor largely because it does most of
// the heavy lifting for the proxy's CLI parameters that come in via the Config struct.
func TestNew(t *testing.T) {
	cfg := Config{ServerURLs: []string{"http://localhost"}}
	res, err := New(cfg, nil)
	if err != nil {
		t.Fatal("Unexpected error return from default Config", err)
	}
	if res.httpClient == nil {
		t.Error("New() should have set the default HTTP client when none supplied")
	}
	if res.httpMethod != http.MethodPost {
		t.Error("New() did not set the http POST method, it set", res.httpMethod)
	}
	if res.ecsFamily != 0 {
		t.Error("New() set.ecsFamily without a supplied CIDR", res.ecsFamily)
	}
	if len(res.ecsRequestData) == 0 {
		t.Error("New() did not set.ECSRequestData")
	}

	// Test New() error checks

	res, err = New(Config{}, nil)
	if err == nil {
		t.Error("Expected an error return with a Config not containing any server URLs")
	}
	if !strings.Contains(err.Error(), "No servers") {
		t.Error("Expected a 'No servers' error returned from New, not", err)
	}

	ip, cidr, err := net.ParseCIDR("8.8.8.8/24")
	if err != nil {
		t.Fatal("ParseCIDR failed while setting up test data", err)
	}
	cfg = Config{ECSSetCIDR: cidr, ECSRequestIPv4PrefixLen: 1}
	res, err = New(cfg, nil)
	if err == nil {
		t.Error("Error expected with ECSSetCIDR and ECSRequestIPv4PrefixLen set")
	}

	cfg = Config{ECSSetCIDR: cidr, ECSRequestIPv6PrefixLen: 1}
	res, err = New(cfg, nil)
	if err == nil {
		t.Error("Error expected with ECSSetCIDR and ECSRequestIPv6PrefixLen set")
	}

	// Create a bogus ipv4/ipv6 family

	cidr.IP = []byte{1, 2, 3, 4, 5}
	cfg = Config{ECSSetCIDR: cidr}
	res, err = New(cfg, nil)
	if err == nil {
		t.Error("Error expected with bogus CIDR")
	}

	// Create a bogus CIDR mask. Forcing this error relies a bit on the internals of net.IPMask
	// so if that changes we may have to rethink this trigger data.
	ip, cidr, err = net.ParseCIDR("8.8.8.8/24")
	cidr.Mask = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	cfg = Config{UseGetMethod: true, ECSSetCIDR: cidr}
	res, err = New(cfg, nil)
	if err == nil {
		t.Error("Error expected with bogus Mask")
	}

	cfg = Config{ECSRequestIPv4PrefixLen: -1}
	res, err = New(cfg, nil)
	if err == nil {
		t.Error("Error expected with bogus ECSRequestIPv4PrefixLen")
	}
	cfg = Config{ECSRequestIPv4PrefixLen: 33}
	res, err = New(cfg, nil)
	if err == nil {
		t.Error("Error expected with bogus ECSRequestIPv4PrefixLen")
	}
	cfg = Config{ECSRequestIPv6PrefixLen: -1}
	res, err = New(cfg, nil)
	if err == nil {
		t.Error("Error expected with bogus ECSRequestIPv6PrefixLen")
	}
	cfg = Config{ECSRequestIPv6PrefixLen: 129}
	res, err = New(cfg, nil)
	if err == nil {
		t.Error("Error expected with bogus ECSRequestIPv6PrefixLen")
	}

	// Check GET/POST settings
	cfg = Config{ServerURLs: []string{"http://localhost"}}
	res, err = New(cfg, nil)
	if err != nil {
		t.Fatal("Unexpected error setting up test Resolver", err)
	}
	if res.httpMethod != http.MethodPost {
		t.Error("New() did not set the http POST method, it set", res.httpMethod)
	}
	cfg = Config{UseGetMethod: true, ServerURLs: []string{"http://localhost"}}
	res, err = New(cfg, nil)
	if err != nil {
		t.Fatal("Unexpected error setting up test Resolver", err)
	}
	if res.httpMethod != http.MethodGet {
		t.Error("New() did not set the http GET method, it set", res.httpMethod)
	}

	// Construct a more fully populated resolver

	ip, cidr, err = net.ParseCIDR("8.8.8.8/24")
	cfg = Config{ECSSetCIDR: cidr, ServerURLs: []string{"http://localhost"}}
	res, err = New(cfg, nil)
	if err != nil {
		t.Fatal("Unexpected error setting up test Resolver", err)
	}
	if res.ecsFamily != 1 {
		t.Error("New() did not set.ecsFamily to IPv4, rather", res.ecsFamily)
	}
	if res.ecsPrefixLength != 24 {
		t.Error("New() did not set prefix length to 24, rather", res.ecsPrefixLength)
	}
	if res.ecsIP.String() == ip.String() { // Should not be equal due to masking
		t.Error("New() did not mask ip to 8.8.8.0 rather", res.ecsIP)
	}

	// For complete coverage, include an ipv6 CIDR

	ip, cidr, _ = net.ParseCIDR("2620:149:ae0::53/60")
	cfg = Config{ECSSetCIDR: cidr, ServerURLs: []string{"http://localhost"}}
	res, _ = New(cfg, nil)
	if res.ecsFamily != 2 {
		t.Error("New() did not set.ecsFamily to IPv6, rather", res.ecsFamily)
	}
	if res.ecsPrefixLength != 60 {
		t.Error("New() did not set prefix length to 60, rather", res.ecsPrefixLength)
	}
	if res.ecsIP.String() == ip.String() { // Should not be equal due to masking
		t.Error("New() did not mask ip to 2620:149:ae0:: rather", res.ecsIP)
	}
}

// Make sure that only FQDNs are said to be resolvable by dohresolver.
func TestInBailiwick(t *testing.T) {
	res, _ := New(Config{}, nil)

	if res.InBailiwick("zunzun") {
		t.Error("InBailiwick should only accept a FQDN")
	}
	if res.InBailiwick("zun.zun") {
		t.Error("InBailiwick should not accept a FQDN without a trailing '.'")
	}
	if !res.InBailiwick("zuN.zUn.") {
		t.Error("InBailiwick should accept a FQDN which is a bit weird but has a trailing '.'")
	}
}

// Since most of our tests run with a mock client, make sure that the production case with a real
// http.Client actually works as expected!
func TestDefaultHTTPClient(t *testing.T) {
	res, _ := New(Config{ServerURLs: []string{"http://127.0.0.1:63080/dns-query"}}, nil) // Pick an unused port!

	msg := &dns.Msg{}
	msg.SetQuestion(".", dns.TypeNS)
	_, _, err := res.Resolve(msg, qMeta)
	if err == nil {
		t.Error("Expected an error return from 'http://127.0.0.1:63080'")
	}
	if !strings.Contains(err.Error(), "connection refused") { // Expect this from default http.Client (2019)
		t.Error("Expected a 'connection refused message' from http.Client, not", err)
	}
}

// Check that the basic Resolve path and mock are working as needed by the rest of the tests.
func TestResolveBasic(t *testing.T) {
	mock := newMockDoSimpleMsg(baseDNSQueryMsg())
	res, _ := New(Config{ServerURLs: []string{"localhost"}}, mock)

	// First test that the Mock system is working with a benign query
	reply, _, err := res.Resolve(&dns.Msg{}, qMeta)
	if err != nil {
		t.Fatal("Unexpected Mock error return - cannot continue with tests", err)
	}
	if reply == nil {
		t.Fatal("Unexpected Mock nil reply - cannot continue with tests")
	}
}

// Check the errors paths of Resolve()
func TestResolveErrors(t *testing.T) {
	mock := newMockDoSimpleMsg(baseDNSQueryMsg())
	res, _ := New(Config{ServerURLs: []string{"localhost"}}, mock)

	// Test Msg.Pack() error

	bm := baseDNSQueryMsg()
	bm.Rcode = -1 // This relies on the internals of miekg/dns
	_, _, err := res.Resolve(bm, qMeta)
	if err == nil {
		t.Fatal("Expected error return with a bogus dns.Msg")
	}

	// Test an HTTP error return

	mock.setStatus(503, "503 Bad Status")
	q := &dns.Msg{}
	q.SetQuestion("example.net.", dns.TypeMX)
	reply, _, err := res.Resolve(q, qMeta)
	if err == nil {
		t.Fatal("Unexpected Mock nil error - cannot continue with tests", err)
	}
	if !strings.Contains(err.Error(), "Status: 503") {
		t.Error("Expected an error complaining about the HTTP status code, not", err)
	}
	if reply != nil {
		t.Fatal("Unexpected Mock reply - cannot continue with tests")
	}

	// Test Msg.Unpack() error

	mock = newMockDoSimple(200, "200 ok", "application/dns-message", "bogusbut big enough to be > minimal")
	res, _ = New(Config{ServerURLs: []string{"localhost"}}, mock)
	_, _, err = res.Resolve(baseDNSQueryMsg(), qMeta)
	if err == nil {
		t.Fatal("Expected error return with a bogus dns.Msg")
	}
	if !strings.Contains(err.Error(), "dns.Unpack") {
		t.Error("Expected a dns.Unpack error message, not", err)
	}

	// Test for http.Request construction errors

	mock = newMockDoSimpleMsg(baseDNSQueryMsg())
	res, err = New(Config{ServerURLs: []string{"\rlocalhost/get/"}}, mock)
	_, _, err = res.Resolve(&dns.Msg{}, qMeta)
	if err == nil {
		t.Fatal("Expected an error from Resolve() with bogus URL")
	}
	if !strings.Contains(err.Error(), "net/") {
		t.Error("Expected error to come from within net/*", err)
	}

	// Test for Do() returning an error

	mock = newMockDoSimpleMsg(baseDNSQueryMsg())
	mock.err = errors.New("Mock Do() failed on purpose")
	res, _ = New(Config{ServerURLs: []string{"localhost"}}, mock)
	_, _, err = res.Resolve(&dns.Msg{}, qMeta)
	if err == nil {
		t.Fatal("Expected an error from mock Do()")
	}
	if !strings.Contains(err.Error(), "failed on purpose") {
		t.Fatal("mock Do() error message not 'failed on purpose'", err)
	}
}

// Test good path for the HTTP request side of Resolve()
// XXXX Is there more we can test here?
func TestResolveHTTPRequest(t *testing.T) {
	mock := newMockDoSimpleMsg(baseDNSQueryMsg())
	res, _ := New(Config{ServerURLs: []string{"localhost"}}, mock)
	query := baseDNSQueryMsg()
	_, _, err := res.Resolve(query, qMeta)
	if err != nil {
		t.Fatal("Unexpected failure of mock setup", err)
	}
	hv := mock.request.Header.Get("User-Agent")
	if !strings.Contains(hv, "trustydns") {
		t.Error("User-Agent does not contain trustydns", hv)
	}
	hv = mock.request.Header.Get("Content-Type")
	if hv != "application/dns-message" {
		t.Error("Content-Type does not equal application/dns-message", hv)
	}
	hv = mock.request.Header.Get("Accept")
	if hv != "application/dns-message" {
		t.Error("Accept does not equal application/dns-message", hv)
	}

	// Check POST URL

	httpQPs := mock.request.URL.Query()
	_, ok := httpQPs["dns-query"]
	if ok {
		t.Error("Did not expected dns-query in HTTP POST", httpQPs)
	}

	// Check that POST data looks like the original DNS Message

	originalBody, _ := query.Pack()
	body, err := ioutil.ReadAll(mock.request.Body)
	if err != nil {
		t.Fatal("POST does not have body data", err)
	}

	if !bytes.Equal(body, originalBody) {
		t.Fatal("POST data does not look like original dns message", body, originalBody)
	}
}

// Test good path for the HTTP response side of Resolve()
// XXXX Is there more we can test here?
func TestResolveHTTPResponse(t *testing.T) {
	// Check that remote duration is decoded
	mock := newMockDoSimpleMsg(baseDNSQueryMsg())
	addHTTPResponseHeader(&mock.response, "X-trustydns-Duration", "23s")
	res, _ := New(Config{ServerURLs: []string{"localhost"}}, mock)
	_, _, err := res.Resolve(&dns.Msg{}, qMeta)
	if err != nil {
		t.Fatal("Unexpected error return with duration header - cannot continue with tests", err)
	}
	if res.bsList[0].serverLatency != time.Second*23 {
		t.Error("Expected a server latency of 23s, not", res.bsList[0].serverLatency)
	}

	// Check for error return due to bogus CT
	bm := baseDNSQueryMsg()
	binary, _ := bm.Pack()
	mock = newMockDoSimple(200, "200 ok", "application/blarty", string(binary))
	res, _ = New(Config{ServerURLs: []string{"localhost"}}, mock)
	_, _, err = res.Resolve(&dns.Msg{}, qMeta)
	if err == nil {
		t.Fatal("Expected a Content-Type error message")
	}
	if !strings.Contains(err.Error(), "Content-Type") {
		t.Error("Expected CT error message to contain 'Content-Type', not", err)
	}
}

// A replacement implementation of http.Response.Body (io.ReadCloser) which simulates errors.
type errorReadCloser struct{}

func (erc *errorReadCloser) Close() error { return errors.New("errorReadCloser Close() Error") }
func (erc *errorReadCloser) Read(p []byte) (n int, err error) {
	return 0, errors.New("errorReadCloser Read() Error")
}

// Test HTTP error paths.
//
// Body read and decode failures - these are highly improbably IRL as it impies HTTP package
// errors. But they are a returnable error so we should give them coverage if we can.
func TestHTTPReadFailures(t *testing.T) {
	mock := newMockDoSimpleMsg(baseDNSQueryMsg())
	mock.response.Body = &errorReadCloser{}
	res, _ := New(Config{ServerURLs: []string{"localhost"}}, mock)
	_, _, err := res.Resolve(&dns.Msg{}, qMeta)
	if err == nil {
		t.Fatal("Expected an error return when using mockRWError")
	}
	if !strings.Contains(err.Error(), "Body Read Error") {
		t.Error("Expected a 'Body Read' error message, not", err)
	}

	// Minimum viable DNS Message
	mock = newMockDoSimple(200, "200 ok", "application/dns-message", "")
	res, _ = New(Config{ServerURLs: []string{"localhost"}}, mock)
	_, _, err = res.Resolve(&dns.Msg{}, qMeta)
	if err == nil {
		t.Fatal("Expected error return when reply message is absurdly short")
	}
	if !strings.Contains(err.Error(), "minimum viable") {
		t.Error("Expected a 'minimum viable' error message, not", err)
	}
}

// Check that UseGetMethod causes a GET request instead of the default POST
func TestResolvePOSTvsGET(t *testing.T) {
	mock := newMockDoSimpleMsg(baseDNSQueryMsg())
	res, _ := New(Config{ServerURLs: []string{"localhost"}}, mock)
	qm1 := &dns.Msg{}
	qm1.MsgHdr.Id = 234 // A POST leaves the ID intact
	_, _, err := res.Resolve(qm1, qMeta)
	if err != nil {
		t.Fatal("Unexpected failure of Resolve() as part of mock setup", err)
	}
	if mock.request.Method != "POST" {
		t.Error("Expect 'POST' method, not", mock.request.Method)
	}
	httpQ, _ := mock.extractHTTPRequestMsg()
	if httpQ == nil {
		t.Fatal("Unexpected failure from mock while extracting Query Message")
	}
	if httpQ.MsgHdr.Id != 234 {
		t.Error("Message ID was modified with a POST request. From 234 to", httpQ.MsgHdr.Id)
	}

	// Now for GET

	mock = newMockDoSimpleMsg(baseDNSQueryMsg())
	res, _ = New(Config{UseGetMethod: true, ServerURLs: []string{"localhost"}}, mock)
	qm2 := &dns.Msg{}
	qm2.MsgHdr.Id = 345 // This should get zapped with a GET
	_, _, err = res.Resolve(qm2, qMeta)
	if err != nil {
		t.Fatal("Unexpected failure of Resolve() as part of mock setup", err)
	}
	if mock.request.Method != "GET" {
		t.Error("Expect 'GET' method, not", mock.request.Method)
	}

	httpQ, _ = mock.extractHTTPRequestMsg()
	if httpQ == nil {
		t.Fatal("Unexpected failure from mock while extracting Query Message")
	}
	if httpQ.MsgHdr.Id != 0 {
		t.Error("Message ID was not set to zero in a GET request. It's", httpQ.MsgHdr.Id)
	}
}

// Check that an Age header adjusts the reply TTLs down
func TestResolveGoodAgeHeader(t *testing.T) {
	dnsReply := baseDNSQueryMsg()
	a1 := &dns.A{Hdr: dns.RR_Header{Name: "3.to.1.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3}}
	a2 := &dns.AAAA{Hdr: dns.RR_Header{Name: "300.to.290.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}}
	a3 := &dns.TXT{Hdr: dns.RR_Header{Name: "10.to.1.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10}}

	n1 := &dns.NS{Hdr: dns.RR_Header{Name: "11.to.1.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 11}}
	n2 := &dns.NS{Hdr: dns.RR_Header{Name: "12.to.2.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 12}}

	e1 := &dns.SRV{Hdr: dns.RR_Header{Name: "13.to.3.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 13}}
	e2 := &dns.MX{Hdr: dns.RR_Header{Name: "1.to.1.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 1}}

	dnsReply.Answer = append(dnsReply.Answer, a1, a2, a3)
	dnsReply.Ns = append(dnsReply.Ns, n1, n2)
	dnsReply.Extra = append(dnsReply.Extra, e1, e2)

	mock := newMockDoSimpleMsg(dnsReply)
	addHTTPResponseHeader(&mock.response, "Age", "10")
	res, _ := New(Config{ServerURLs: []string{"localhost"}}, mock)
	httpR, _, err := res.Resolve(baseDNSQueryMsg(), qMeta)
	if err != nil {
		t.Fatal("Unexpected failure of Resolve() as part of mock setup", err)
	}
	if httpR == nil {
		t.Fatal("Unexpected failure from mock while extracting Reply Message")
	}

	// Verify that Age reduced the TTLs in the response message

	if len(httpR.Answer) != 3 {
		t.Fatal("Expected three Answer, not", len(httpR.Answer))
	}
	if len(httpR.Ns) != 2 {
		t.Fatal("Expected two Ns, not", len(httpR.Ns))
	}
	if len(httpR.Extra) != 2 {
		t.Fatal("Expected two Extra, not", len(httpR.Extra))
	}

	tt := []struct {
		rr   dns.RR
		ttl  uint32
		name string
	}{
		{httpR.Answer[0], 1, "a1"},
		{httpR.Answer[1], 290, "a2"},
		{httpR.Answer[2], 1, "a3"},

		{httpR.Ns[0], 1, "n1"},
		{httpR.Ns[1], 2, "n2"},

		{httpR.Extra[0], 3, "e1"},
		{httpR.Extra[1], 1, "e2"},
	}

	for _, tc := range tt {
		if tc.rr.Header().Ttl != tc.ttl {
			t.Error("TTL not age adjusted in", tc.name, tc.rr.Header().Ttl, tc.ttl)
		}
	}
}

// Check that a bad Age header is ignored
func TestResolveBadAgeHeader(t *testing.T) {
	dnsReply := baseDNSQueryMsg()
	a1 := &dns.A{Hdr: dns.RR_Header{Name: "3.to.1.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3}}
	a2 := &dns.AAAA{Hdr: dns.RR_Header{Name: "300.to.290.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}}

	dnsReply.Answer = append(dnsReply.Answer, a1, a2)

	mock := newMockDoSimpleMsg(dnsReply)
	addHTTPResponseHeader(&mock.response, "Age", "-10")
	res, _ := New(Config{ServerURLs: []string{"localhost"}}, mock)
	httpR, _, err := res.Resolve(baseDNSQueryMsg(), qMeta)
	if err != nil {
		t.Fatal("Unexpected failure of Resolve() as part of mock setup", err)
	}
	if httpR == nil {
		t.Fatal("Unexpected failure from mock while extracting Reply Message")
	}

	// Verify that Age reduced the TTLs in the response message

	if len(httpR.Answer) != 2 {
		t.Fatal("Expected two Answer, not", len(httpR.Answer))
	}

	tt := []struct {
		rr   dns.RR
		ttl  uint32
		name string
	}{
		{httpR.Answer[0], 3, "a1"},
		{httpR.Answer[1], 300, "a2"},
	}

	for _, tc := range tt {
		if tc.rr.Header().Ttl != tc.ttl {
			t.Error("TTL not age adjusted in", tc.name, tc.rr.Header().Ttl, tc.ttl)
		}
	}
}

// Set the ECSRemove option and make sure ECS options are eliminated
func TestResolveECSRemove(t *testing.T) {
	mock := newMockDoSimpleMsg(baseDNSQueryMsg())
	res, _ := New(Config{ECSRemove: true, ServerURLs: []string{"localhost"}}, mock)

	dnsQ := baseDNSQueryMsg()
	dnsutil.CreateECS(dnsQ, 1, 8, net.ParseIP("10.0.1.1")) // This should get removed

	dnsR, _, err := res.Resolve(dnsQ, qMeta)
	if err != nil {
		t.Fatal("Expected good reply from baseDNS query with ECS", err)
	}

	// With ECSRemove set neither the reply nor the DNS request in the HTTP Request payload
	// should have an ECS option.

	httpQ, _ := mock.extractHTTPRequestMsg()
	if httpQ == nil {
		t.Fatal("Unexpected failure from mock while extracting Query Message")
	}
	_, ecs := dnsutil.FindECS(httpQ)
	if ecs != nil {
		t.Error("HTTP Query has ECS when ECSRemove is set")
	}

	_, ecs = dnsutil.FindECS(dnsR)
	if ecs != nil {
		t.Error("DNS Reply has ECS when ECSRemove is set")
	}
}

// ECSSet query that does not contain an ECS. The HTTP request should have the Config ECS.
func TestResolveECSSet0(t *testing.T) {
	mock := newMockDoSimpleMsg(baseDNSQueryMsg())
	_, ipNet, err := net.ParseCIDR("10.0.1.1/16")
	if err != nil {
		t.Fatal("Unexpected fail of ParseCIDR", err)
	}
	res, _ := New(Config{ECSSetCIDR: ipNet, ServerURLs: []string{"localhost"}}, mock)

	dnsQ := baseDNSQueryMsg()
	_, _, err = res.Resolve(dnsQ, qMeta)
	if err != nil {
		t.Fatal("Expected good reply from baseDNS query with ECS", err)
	}

	httpQ, _ := mock.extractHTTPRequestMsg()
	if httpQ == nil {
		t.Fatal("Unexpected failure from mock while extracting Query Message")
	}
	_, ecs := dnsutil.FindECS(httpQ)
	if ecs == nil {
		t.Error("HTTP Query should have an ECS with ECSSet")
	}
	if !ecs.Address.Equal(net.ParseIP("10.0.0.0")) {
		t.Error("ECS in the HTTP Payload should be the masked httpQ value, not", ecs.Address)
	}
}

// ECSSet use a query that contains an ECS. The HTTP request should have the query ECS.
func TestResolveECSSet1(t *testing.T) {
	mock := newMockDoSimpleMsg(baseDNSQueryMsg())
	_, ipNet, err := net.ParseCIDR("10.0.1.1/16")
	if err != nil {
		t.Fatal("Unexpected fail of ParseCIDR", err)
	}
	res, _ := New(Config{ECSSetCIDR: ipNet, ServerURLs: []string{"localhost"}}, mock)

	dnsQ := baseDNSQueryMsg()
	dnsutil.CreateECS(dnsQ, 1, 24, net.ParseIP("1.2.3.4")) // Query has ECS

	_, _, err = res.Resolve(dnsQ, qMeta)
	if err != nil {
		t.Fatal("Expected good reply from baseDNS query with ECS", err)
	}

	httpQ, _ := mock.extractHTTPRequestMsg()
	if httpQ == nil {
		t.Fatal("Unexpected failure from mock while extracting Query Message")
	}
	_, ecs := dnsutil.FindECS(httpQ)
	if ecs == nil {
		t.Error("HTTP Query should have an ECS with ECSSet")
	}
	if !ecs.Address.Equal(net.ParseIP("1.2.3.0")) {
		t.Error("ECS in the HTTP Payload should be the masked Msg ECS, not", ecs.Address)
	}
}

// Test that only IN/Query is touched by ECS processing.
func TestResolveINQuery(t *testing.T) {
	dnsQ := baseDNSQueryMsg()
	dnsutil.CreateECS(dnsQ, 1, 24, net.ParseIP("1.2.3.4"))
	if subTestINQuery(t, dnsQ) { // First test tests the test that normally the query is modified
		t.Fatal("An IN/Query should have been modified by subTestINQuery")
	}

	dnsQ = baseDNSQueryMsg()
	dnsutil.CreateECS(dnsQ, 1, 24, net.ParseIP("1.2.3.4"))
	dnsQ.MsgHdr.Opcode = dns.OpcodeStatus // This should stop any modifications by Resolve()
	if !subTestINQuery(t, dnsQ) {
		t.Error("A Status op-code should cause the message to be unmodified in any way")
	}

	dnsQ = &dns.Msg{} // No question
	dnsutil.CreateECS(dnsQ, 1, 24, net.ParseIP("1.2.3.4"))
	if !subTestINQuery(t, dnsQ) {
		t.Error("A message lacking an IN question should not be modified")
	}

	dnsQ = baseDNSQueryMsg() // Two questions
	dnsQ.Question = append(dnsQ.Question, dnsQ.Question[0])
	dnsutil.CreateECS(dnsQ, 1, 24, net.ParseIP("1.2.3.4"))
	if !subTestINQuery(t, dnsQ) {
		t.Error("Multiple Questions should not be modified")
	}

	// None-IN class
	dnsQ = baseDNSQueryMsg()
	dnsQ.Question[0].Qclass = dns.ClassHESIOD
	dnsutil.CreateECS(dnsQ, 1, 24, net.ParseIP("1.2.3.4"))
	if !subTestINQuery(t, dnsQ) {
		t.Error("HESIOD class should not be modified")
	}
}

// Run Resolve() and see if the binary form of the dns query in the HTTP request payload is the same
// as the original query. Return true if they are the same.
func subTestINQuery(t *testing.T, dnsQ *dns.Msg) bool {
	mock := newMockDoSimpleMsg(baseDNSQueryMsg())
	_, ipNet, err := net.ParseCIDR("10.11.0.0/16") // This should get removed if it were an IN/Query
	if err != nil {
		t.Fatal("Unexpected fail of ParseCIDR setting up for a test", err)
	}
	res, _ := New(Config{ECSRemove: true, ECSSetCIDR: ipNet, ServerURLs: []string{"localhost"}}, mock)

	origQ := dnsQ.Copy() // Take a copy because Resolve potentially modifies the query
	_, _, err = res.Resolve(dnsQ, qMeta)
	if err != nil {
		t.Fatal("Unexpected Resolve() error when setting up test response", err)
	}

	httpBytes, err := ioutil.ReadAll(mock.request.Body)
	if err != nil {
		t.Fatal("Could not read query bytes from request.Body", err)
	}

	origBytes, _ := origQ.Pack()

	return bytes.Equal(origBytes, httpBytes)
}

// Test that if ECSRequest is set and the query contains no ECS then the HTTP request header is
// present.
func TestResolveECSRequest(t *testing.T) {
	mock := newMockDoSimpleMsg(baseDNSQueryMsg())
	res, _ := New(Config{
		ECSRequestIPv4PrefixLen: 17, ECSRequestIPv6PrefixLen: 53,
		ServerURLs: []string{"localhost"}}, mock)

	dnsQ := baseDNSQueryMsg()
	dnsutil.CreateECS(dnsQ, 1, 24, net.ParseIP("1.2.3.4")) // Query has ECS so no HTTP header

	res.Resolve(dnsQ, qMeta)

	hv := mock.request.Header.Get("X-trustydns-Synth")
	if len(hv) > 0 {
		t.Error("Did not expect a X-trustydns-Synth header when DNS query already has an ECS", hv)
	}

	// Now resolve without an ECS - should get an HTTP header
	mock = newMockDoSimpleMsg(baseDNSQueryMsg())
	res, _ = New(Config{
		ECSRequestIPv4PrefixLen: 17, ECSRequestIPv6PrefixLen: 53,
		ServerURLs: []string{"localhost"}}, mock)

	res.Resolve(baseDNSQueryMsg(), qMeta)

	hv = mock.request.Header.Get("X-trustydns-Synth")
	if hv != "17/53" {
		t.Error("Expected X-trustydns-Synth to contain 17/53, not", hv)
	}
}

// Test that.ECSReturned is set when a non-zero scope is returned
func TestResolveECSScope(t *testing.T) {
	dnsQ := baseDNSQueryMsg()
	dnsutil.CreateECS(dnsQ, 1, 24, net.ParseIP("1.2.3.4"))

	// Set the scope in the mock response message

	dnsR := dnsQ.Copy()
	_, ecs := dnsutil.FindECS(dnsR)
	if ecs == nil {
		t.Fatal("Ecs gone missing on setting", dnsR)
	}
	ecs.SourceScope = ecs.SourceNetmask

	mock := newMockDoSimpleMsg(dnsR)
	res, _ := New(Config{
		ECSRequestIPv4PrefixLen: 24, ECSRequestIPv6PrefixLen: 64,
		ServerURLs: []string{"localhost"}}, mock)

	res.Resolve(dnsQ, qMeta)
	if res.bsList[0].ecsReturned != 1 {
		t.Error("Scope not noticed", res.bsList[0].ecsReturned)
	}
}

// Test that subnet option is removed if in redaction mode
func TestECSRedact(t *testing.T) {
	dnsQ := baseDNSQueryMsg()

	// Set the scope in the mock response message

	dnsR := dnsQ.Copy()
	ecs := dnsutil.CreateECS(dnsR, 1, 24, net.ParseIP("1.2.3.4"))
	ecs.SourceScope = ecs.SourceNetmask

	_, cidr, err := net.ParseCIDR("8.8.8.8/24")
	if err != nil {
		t.Fatal("ParseCIDR failed while setting up test data", err)
	}

	mock := newMockDoSimpleMsg(dnsR)
	res, _ := New(Config{
		ECSSetCIDR: cidr, ECSRedactResponse: true,
		ServerURLs: []string{"localhost"}}, mock)

	reply, _, err := res.Resolve(dnsQ, qMeta)
	if err != nil {
		t.Fatal("Unexpected error setting up Redact", err)
	}
	_, ecs = dnsutil.FindECS(reply)
	if ecs != nil {
		t.Error("Redact did not remove ECS option", ecs, reply)
	}
}

// Padding rounds up messages by binary zero padding.
func TestPadding(t *testing.T) {
	tt := []struct {
		padding bool
		useGet  bool
	}{
		{false, false},
		{false, true},
		{true, false},
		{true, true},
	}

	for _, tc := range tt {
		mock := newMockDoSimpleMsg(baseDNSQueryMsg())
		res, _ := New(Config{GeneratePadding: tc.padding, UseGetMethod: tc.useGet,
			ServerURLs: []string{"https://localhost"}}, mock)

		dnsQ := baseDNSQueryMsg()
		_, _, err := res.Resolve(dnsQ, qMeta)
		if err != nil {
			t.Fatal("Expected good reply from baseDNS query with no padding", err)
		}

		// With ECSRemove set neither the reply nor the DNS request in the HTTP Request payload
		// should have an ECS option.

		httpQ, body := mock.extractHTTPRequestMsg()
		if body == nil {
			t.Fatal("Unexpected failure from mock while extracting Query Message body")
		}
		switch {
		case tc.padding:
			if len(body)%128 != 0 {
				t.Error("Padding did not create a modulo 128 payload", tc, httpQ)
			}
		default:
			if len(body) >= 127 { // Minimum query pad size - 1 (body is actually around 33 bytes)
				t.Error("Looks like padding has been added when non was requested", httpQ)
			}
		}
	}
}

// Test that the return resolution details seem reasonable
func TestResolveDetails(t *testing.T) {
	mock := newMockDoSimpleMsg(baseDNSQueryMsg())
	res, _ := New(Config{ServerURLs: []string{"https://localhost"}}, mock)
	dnsQ := baseDNSQueryMsg()
	_, details, err := res.Resolve(dnsQ, qMeta)
	if err != nil {
		t.Error("Did not expect an error from the Details resolve", err)
	}
	if details == nil {
		t.Error("Details from .Resolve() should not be nil on a good return")
	}
	if details.TransportDuration == 0 ||
		details.ResolutionDuration == 0 ||
		details.PayloadSize == 0 ||
		details.QueryTries == 0 ||
		details.ServerTries == 0 ||
		details.FinalServerUsed == "" ||
		details.TransportType == resolver.DNSTransportUndefined {
		t.Error("Details returned from Resolve seem unpopulated", details)
	}
}
