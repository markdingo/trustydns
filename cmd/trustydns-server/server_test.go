package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/markdingo/trustydns/internal/dnsutil"
	"github.com/markdingo/trustydns/internal/resolver"
	"github.com/markdingo/trustydns/internal/tlsutil"

	"github.com/miekg/dns"
)

// The mockResolver replaces the local resolver used by the server. This way we can control the
// response it gets from the Resolve() call as well as record the query as it looks after processing
// by the server code.
type mockResolver struct {
	ib       bool
	query    dns.Msg
	response dns.Msg
	rMeta    resolver.ResponseMetaData
	err      error
}

func (t *mockResolver) InBailiwick(qname string) bool {
	return t.ib
}

func (t *mockResolver) Resolve(query *dns.Msg, qMeta *resolver.QueryMetaData) (*dns.Msg, *resolver.ResponseMetaData, error) {
	query.CopyTo(&t.query)                                  // Take a deep copy of the query and
	return t.response.CopyTo(new(dns.Msg)), &t.rMeta, t.err // return a deep copy of the response
}

// Test that the basic server starts up correctly. May as well do this before proceeding.
func TestStart(t *testing.T) {
	s := &server{local: &mockResolver{}, listenAddress: "127.0.0.1:59053"}
	errorChannel := make(chan error)
	wg := &sync.WaitGroup{} // Wait on all servers
	s.start(nil, errorChannel, wg)
	var err error
	defer s.stop()
	select {
	case e := <-errorChannel:
		err = e
	case <-time.After(time.Second):
	}
	if err != nil {
		t.Error(err)
	}
}

type routingCase struct {
	method       string
	url          string
	statusCode   int
	responseBody string
}

var routingCases = []routingCase{
	{http.MethodGet, "", 404, "not found"},
	{http.MethodGet, "/junk", 404, "not found"},
	{http.MethodPost, "/junk", 404, "not found"},
	{"bogus", "/junk", 404, "not found"},
	{http.MethodGet, consts.Rfc8484Path, 415, "Expected Content-Type"},
	{http.MethodPost, consts.Rfc8484Path, 415, "Expected Content-Type"},
	{"bogus", consts.Rfc8484Path, 405, "Expected Method"},
}

// Test that the server correctly barfs invalid requests
func TestRouting(t *testing.T) {
	mainInit(os.Stdout, os.Stderr)
	resolver := &mockResolver{}
	dohServer := &server{local: resolver}

	httpServer := httptest.NewServer(dohServer.newRouter())
	defer httpServer.Close()
	client := http.Client{}

	for tx, tc := range routingCases {
		t.Run(fmt.Sprintf("%d", tx), func(t *testing.T) {
			url := httpServer.URL
			if len(tc.url) > 0 {
				url += tc.url
			}
			req, err := http.NewRequest(tc.method, url, strings.NewReader(""))
			if err != nil {
				t.Fatal("http.NewRequest failed", err)
			}
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(url, "Get returned error", err)
			}
			bodyBytes, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal(url, "ReadAll returned error", err)
			}
			if res.StatusCode != tc.statusCode {
				t.Error(url, "Expected Status", tc.statusCode, "got", res.StatusCode)
			}
			if len(tc.responseBody) > 0 {
				body := string(bodyBytes)
				if !strings.Contains(body, tc.responseBody) {
					t.Error(url, "Body does not contain", tc.responseBody, body)
				}
			}
		})
	}
}

type header struct {
	key string
	val string
}

type dnsQuestionParams struct {
	qId   uint16
	qType uint16
	qName string
}

// serverHTTPCase defines all the ways in which a test query can be manipulated to exercise
// serveDoH(). Unfortunately it's fairly complex as there are many different error paths and test
// cases that can occur within this functionq. Note that parameters are sometimes not enough thu the
// *Func() functions which actually define code to pre- or post-process a server query. Most of
// these test cases have been constructed by looking at the server code and looking for logic
// branches.
//
// One could argue that such a complex test definition suggests the serverDoH() is too complicated
// and should be deconstructed into more manageable components. Unfortunately that deconstruction
// has already occurred and in any event end-to-end tests are what these cases mainly supply. Further
// simplification and deconstruction ideas more than welcome.
type serverHTTPCase struct {
	method          string
	description     string
	httpHeaders     []header
	httpQueryParams string
	dnsQuestion     dnsQuestionParams
	prePacked       string  // Use as an alternative to the packed msg
	dnsQ            dns.Msg // Query constructed by test loop
	httpR           dns.Msg // Unpacked from HTTP response
	resolver        mockResolver
	statusCode      int
	responseBody    string
	prePackFunc     func(*serverHTTPCase, *dns.Msg)        // Called prior to packing DNS query
	preDoFunc       func(*serverHTTPCase, *http.Request)   // Called prior to http.Client.Do()
	postDoFunc      func(*serverHTTPCase, *testing.T) bool // Called after http.Client.Do()
	saveConfig      config
}

var serverHTTPCases = []*serverHTTPCase{
	{method: http.MethodGet, description: "Expect a good response to this GET request",
		httpHeaders: []header{
			{consts.ContentTypeHeader, consts.Rfc8484AcceptValue},
			{consts.UserAgentHeader, "serverHTTPCase"},
		},
		httpQueryParams: consts.Rfc8484QueryParam,
		dnsQuestion:     dnsQuestionParams{qId: 1, qType: dns.TypeNS, qName: "example.com."},
		statusCode:      200},

	{method: http.MethodGet, description: "Expect a good response with ID=0",
		httpHeaders: []header{
			{consts.ContentTypeHeader, consts.Rfc8484AcceptValue},
			{consts.UserAgentHeader, "serverHTTPCase"},
		},
		httpQueryParams: consts.Rfc8484QueryParam,
		dnsQuestion:     dnsQuestionParams{qId: 0, qType: dns.TypeNS, qName: "example.com."},
		statusCode:      200},

	{method: http.MethodPost, description: "Expect a good response to the POST request",
		httpHeaders: []header{{consts.ContentTypeHeader, consts.Rfc8484AcceptValue}},
		dnsQuestion: dnsQuestionParams{qId: 1, qType: dns.TypeNS, qName: "example.com."},
		statusCode:  200},

	{method: http.MethodGet, description: "Expect QP not present",
		httpHeaders:     []header{{consts.ContentTypeHeader, consts.Rfc8484AcceptValue}},
		httpQueryParams: "wrongQP",
		dnsQuestion:     dnsQuestionParams{qId: 1, qType: dns.TypeNS, qName: "example.com."},
		statusCode:      400, responseBody: "not present"},

	{method: http.MethodGet, description: "Superfluous QPs",
		httpHeaders:     []header{{consts.ContentTypeHeader, consts.Rfc8484AcceptValue}},
		httpQueryParams: "qp2=xxx&" + consts.Rfc8484QueryParam, // Contrive two query params
		dnsQuestion:     dnsQuestionParams{qId: 1, qType: dns.TypeNS, qName: "example.com."},
		statusCode:      400, responseBody: "Superfluous Query Params"},

	{method: http.MethodGet, description: "Base64 decode failure",
		httpHeaders:     []header{{consts.ContentTypeHeader, consts.Rfc8484AcceptValue}},
		httpQueryParams: consts.Rfc8484QueryParam + "=zubzub",
		dnsQuestion:     dnsQuestionParams{qId: 1, qType: dns.TypeNS, qName: "example.com."},
		statusCode:      400, responseBody: "illegal base64"},

	{method: http.MethodPost, description: "Unpack failure",
		httpHeaders: []header{{consts.ContentTypeHeader, consts.Rfc8484AcceptValue}},
		dnsQuestion: dnsQuestionParams{qId: 1, qType: dns.TypeNS},
		prePacked:   "xxxx",
		statusCode:  400, responseBody: "unpacking"},

	{method: http.MethodPost, description: "ECS remove from query",
		httpHeaders: []header{{consts.ContentTypeHeader, consts.Rfc8484AcceptValue}},
		dnsQuestion: dnsQuestionParams{qId: 101, qType: dns.TypeNS, qName: "example.com."},
		statusCode:  200,
		prePackFunc: func(tc *serverHTTPCase, q *dns.Msg) {
			tc.saveConfig = *cfg
			cfg.ecsRemove = true
			dnsutil.CreateECS(q, 1, 24, net.IPv4(254, 253, 252, 251))
		},
		postDoFunc: func(tc *serverHTTPCase, t *testing.T) bool {
			*cfg = tc.saveConfig              // Return to previous state
			_, e := dnsutil.FindECS(&tc.dnsQ) // Make sure original query has it
			if e == nil {
				t.Error("Original query does not have ECS", tc.dnsQ.String())
			}
			_, e = dnsutil.FindECS(&tc.resolver.query) // Should not be present due to ecsRemove
			if e != nil {
				t.Error("Post-server Query still has ECS option with ecsRemove set",
					tc.resolver.query.String())
			}
			return false
		}},

	{method: http.MethodPost, description: "config ecsSet",
		httpHeaders: []header{{consts.ContentTypeHeader, consts.Rfc8484AcceptValue}},
		dnsQuestion: dnsQuestionParams{qId: 102, qType: dns.TypeMX, qName: "example.com."},
		statusCode:  200,
		preDoFunc: func(tc *serverHTTPCase, req *http.Request) {
			*cfg = tc.saveConfig // Return to previous state
			cfg.ecsSet = true
			cfg.ecsSetIPv4PrefixLen = 22
			cfg.ecsSetIPv6PrefixLen = 54
		},
		postDoFunc: func(tc *serverHTTPCase, t *testing.T) bool {
			*cfg = tc.saveConfig                        // Return to previous state
			_, e := dnsutil.FindECS(&tc.resolver.query) // Should be present due to ecsSet
			if e == nil {
				t.Fatal("ecsSet not acted on by server", tc.resolver.query.String())
			}
			if e.SourceNetmask != 22 {
				t.Error("ecsSet did not honor cfg.ecsSetIPv4PrefixLen=22", e.String())
			}
			return false
		}},

	{method: http.MethodPost, description: "Synthesize ECS ok",
		httpHeaders: []header{
			{consts.ContentTypeHeader, consts.Rfc8484AcceptValue},
			{consts.TrustySynthesizeECSRequestHeader, "26/68"},
		},
		dnsQuestion: dnsQuestionParams{qId: 103, qType: dns.TypeA, qName: "example.com."},
		statusCode:  200,
	},
	{method: http.MethodPost, description: "Synthesize ECS ipv4 Nonumer",
		httpHeaders: []header{
			{consts.ContentTypeHeader, consts.Rfc8484AcceptValue},
			{consts.TrustySynthesizeECSRequestHeader, "nonumer/64"},
		},
		dnsQuestion: dnsQuestionParams{qId: 104, qType: dns.TypeA, qName: "example.com."},
		statusCode:  400, responseBody: "Could not convert",
	},
	{method: http.MethodPost, description: "Synthesize ECS ipv4 Too Big",
		httpHeaders: []header{
			{consts.ContentTypeHeader, consts.Rfc8484AcceptValue},
			{consts.TrustySynthesizeECSRequestHeader, "33/64"},
		},
		dnsQuestion: dnsQuestionParams{qId: 105, qType: dns.TypeA, qName: "example.com."},
		statusCode:  400, responseBody: "not in range 0-32",
	},
	{method: http.MethodPost, description: "Synthesize ECS ipv6 Nonumer",
		httpHeaders: []header{
			{consts.ContentTypeHeader, consts.Rfc8484AcceptValue},
			{consts.TrustySynthesizeECSRequestHeader, "24/nonumer"},
		},
		dnsQuestion: dnsQuestionParams{qId: 204, qType: dns.TypeAAAA, qName: "example.com."},
		statusCode:  400, responseBody: "Could not convert",
	},
	{method: http.MethodPost, description: "Synthesize ECS ipv6 Too Big",
		httpHeaders: []header{
			{consts.ContentTypeHeader, consts.Rfc8484AcceptValue},
			{consts.TrustySynthesizeECSRequestHeader, "24/129"},
		},
		dnsQuestion: dnsQuestionParams{qId: 205, qType: dns.TypeAAAA, qName: "example.com."},
		statusCode:  400, responseBody: "not in range 0-128",
	},
	{method: http.MethodPost, description: "Synthesize ECS tokens",
		httpHeaders: []header{
			{consts.ContentTypeHeader, consts.Rfc8484AcceptValue},
			{consts.TrustySynthesizeECSRequestHeader, "24/37/67"},
		},
		dnsQuestion: dnsQuestionParams{qId: 301, qType: dns.TypeSOA, qName: "example.com."},
		statusCode:  400, responseBody: "Expected i",
	},

	{method: http.MethodPost, description: "Padding",
		httpHeaders: []header{
			{consts.ContentTypeHeader, consts.Rfc8484AcceptValue},
		},
		dnsQuestion: dnsQuestionParams{qId: 501, qType: dns.TypeA, qName: "example.com."},
		statusCode:  200,
		prePackFunc: func(tc *serverHTTPCase, q *dns.Msg) {
			optRR := &dns.OPT{}
			optRR.SetVersion(0)
			optRR.SetUDPSize(dns.DefaultMsgSize)
			optRR.Hdr.Name = "."
			optRR.Hdr.Rrtype = dns.TypeOPT
			optRR.Option = append(optRR.Option, &dns.EDNS0_PADDING{Padding: make([]byte, 0)})
			q.Extra = append(q.Extra, optRR)
		},
		postDoFunc: func(tc *serverHTTPCase, t *testing.T) bool {
			padSize := dnsutil.FindPadding(&tc.httpR)
			if padSize <= 0 {
				t.Error("Expected GT zero padding, not", padSize)
			}
			return false
		},
	},

	{method: http.MethodPost, description: "Resolve Error",
		httpHeaders: []header{
			{consts.ContentTypeHeader, consts.Rfc8484AcceptValue},
		},
		dnsQuestion: dnsQuestionParams{qId: 601, qType: dns.TypeA, qName: "example.com."},
		statusCode:  503, responseBody: "local resolution failed: server_test_error",
		preDoFunc: func(tc *serverHTTPCase, req *http.Request) {
			tc.resolver.err = fmt.Errorf("server_test_error")
		},
	},

	{method: http.MethodPost, description: "Pad and Pack Error",
		httpHeaders: []header{
			{consts.ContentTypeHeader, consts.Rfc8484AcceptValue},
		},
		dnsQuestion: dnsQuestionParams{qId: 701, qType: dns.TypeA, qName: "example.com."},
		statusCode:  503, responseBody: "Pack Failed",
		preDoFunc: func(tc *serverHTTPCase, req *http.Request) {
			tc.resolver.response.Rcode = 0x1000 // Should cause a Pack failure
		},
	},
}

// Test via the http.Client.Do() interface - a real HTTP request in other words
func TestHTTP(t *testing.T) {
	for _, tc := range serverHTTPCases {
		t.Run(tc.description, func(t *testing.T) {
			client := http.Client{}
			stdout := &bytes.Buffer{} // Capture these outputs in case the test cases
			stderr := &bytes.Buffer{} // want to see what was written to these fds
			mainInit(stdout, stderr)

			cfg.logClientIn = true  // Turn on all logging to ensure that we exercise
			cfg.logClientOut = true // the logging paths and thus eliminate any egregious
			cfg.logHTTPIn = true    // errors in that code.
			cfg.logHTTPOut = true
			cfg.logLocalIn = true
			cfg.logLocalOut = true
			cfg.logTLSErrors = true

			dohServer := &server{}

			httpServer := httptest.NewServer(dohServer.newRouter())
			defer httpServer.Close()

			binary := []byte(tc.prePacked)
			dohServer.local = &tc.resolver
			var err error
			if len(tc.dnsQuestion.qName) > 0 {
				tc.dnsQ.SetQuestion(tc.dnsQuestion.qName, tc.dnsQuestion.qType)
				tc.dnsQ.Id = tc.dnsQuestion.qId
				if tc.prePackFunc != nil {
					tc.prePackFunc(tc, &tc.dnsQ)
				}
				binary, err = tc.dnsQ.Pack()
				if err != nil {
					t.Fatal("Packing DNS message failed", err)
				}
			}

			url := httpServer.URL + consts.Rfc8484Path
			var rd io.Reader // Needed for POST method
			if tc.method == http.MethodGet {
				url += "?" + tc.httpQueryParams
				if tc.httpQueryParams == consts.Rfc8484QueryParam {
					url += "=" + base64.URLEncoding.EncodeToString(binary)
				}
			} else {
				rd = bytes.NewReader(binary)
			}

			req, err := http.NewRequest(tc.method, url, rd)
			if err != nil {
				t.Fatal("http.NewRequest failed", err)
			}
			for _, h := range tc.httpHeaders {
				req.Header.Set(h.key, h.val)
			}

			if tc.preDoFunc != nil { // Call pre-request setup routing if present
				tc.preDoFunc(tc, req)
			}

			res, err := client.Do(req)
			if err != nil {
				t.Fatal(url, "Do() returned unexpected error", err)
			}
			bodyBytes, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal(url, "ReadAll() returned unexpected error", err)
			}
			if res.StatusCode != tc.statusCode {
				t.Error(url, "Expected Status", tc.statusCode, "got", res.Status, string(bodyBytes))
				return
			}
			if len(tc.responseBody) > 0 {
				body := string(bodyBytes)
				if !strings.Contains(body, tc.responseBody) {
					t.Error(url, "Body does not contain", tc.responseBody, body)
					return
				}
			}
			tc.httpR = dns.Msg{} // Make a feeble effort to unpack the response
			if res.StatusCode == 200 {
				tc.httpR.Unpack(bodyBytes)
			}

			if tc.postDoFunc != nil { // Call post-request checking routing if present
				fatal := tc.postDoFunc(tc, t)
				if fatal {
					return
				}
			}
		})
	}
}

type parseCase struct {
	addr string
	ip   string // What ip.String() should look like
	txt  string // len() = 0 if no error expected
}

var parseCases = []parseCase{
	{addr: "127.0.0.1:23", ip: "127.0.0.1"},
	{addr: "[::1]:80", ip: "::1"},
	{addr: "127.0.0.1", txt: "colon sep"}, // :port missing
	{addr: ":80", txt: "too short"},
	{addr: "255.256.257.258:80", txt: "Invalid IP"},
}

func TestParseRemoteAddr(t *testing.T) {
	for tx, tc := range parseCases {
		t.Run(fmt.Sprintf("%d", tx), func(t *testing.T) {
			ip, err := parseRemoteAddr(tc.addr)
			switch {
			case err != nil && len(tc.txt) == 0:
				t.Error("Got unexpected error", err)

			case err == nil && len(tc.txt) > 0:
				t.Error("Expected error, but got none")

			case err != nil && len(tc.txt) > 0 && !strings.Contains(err.Error(), tc.txt):
				t.Error("Expected:", tc.txt, "got", err.Error())

			case len(tc.ip) > 0 && ip.String() != tc.ip:
				t.Error("IP addresses don't match. Expect", tc.ip, "got", ip.String())
			}
			//			t.Log("pr=", tc.addr, ip, err)
		})
	}
}

// We need more finer grained control over the ResponseWriter than httptest gives us for i/o related
// errors, so we've mocked up our own.
type mockResponseWriter struct {
	header      http.Header
	writeN      int
	writeError  error
	writeBuffer []byte
	statusCode  int
}

func newMockResponseWriter() *mockResponseWriter {
	t := &mockResponseWriter{}
	t.header = make(http.Header)

	return t
}

func (t *mockResponseWriter) Header() http.Header {
	return t.header
}
func (t *mockResponseWriter) Write(b []byte) (int, error) {
	t.writeBuffer = append(t.writeBuffer, b...)

	return t.writeN, t.writeError
}

func (t *mockResponseWriter) WriteHeader(statusCode int) {
	t.statusCode = statusCode
}

// Return what was written by the HTTP server
func (t *mockResponseWriter) String() string {
	return string(t.writeBuffer)
}

// mockBody replaces http.Request.Body with our own implementation of an io.ReadCloser() to give us
// fine-grained control over the behaviour of serverDoH().
type mockBody struct {
	readError  error
	readData   []byte
	closeError error
}

func (t *mockBody) Read(p []byte) (n int, err error) {
	copy(p, t.readData)
	return len(p), t.readError
}

func (t *mockBody) Close() error {
	return t.closeError
}

// Test via serverDoH directly as this error cannot easily be exercised with a test client.
func TestReadBodyFailure(t *testing.T) {
	resolver := &mockResolver{err: errors.New("Mock Resolver Error")}
	s := &server{local: resolver, listenAddress: "127.0.0.1:59053"}
	mw := newMockResponseWriter()
	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeMX)
	body := &mockBody{readError: errors.New("Trip ioutil.ReadAll return")}

	r, err := http.NewRequest("POST", "http://localhost", body)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/dns-message")
	mainInit(os.Stdout, os.Stderr)
	s.serveDoH(mw, r)

	response := mw.String()
	if !strings.Contains(response, "not ReadAll request body") {
		t.Error("Expected 'not ReadAll request body' got,", response)
	}
}

// Test via serverDoH directly as this error cannot easily be exercised with a test client.
func TestParseRemoteFailure(t *testing.T) {
	mainInit(os.Stdout, os.Stderr)

	s := &server{local: &mockResolver{}}
	mw := newMockResponseWriter()

	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeMX)
	binary, err := msg.Pack()
	if err != nil {
		t.Fatal("Packing DNS message for test setup failed unexpectedly", err)
	}

	rd := bytes.NewReader(binary)
	r, err := http.NewRequest("POST", "http://localhost", rd)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/dns-message")
	r.Header.Set("X-trustydns-Synth", "24/64") // Force serveDoH to parse remote address
	r.RemoteAddr = "256.257.258.259:80"        // We just want to exercise the return not the parser
	s.serveDoH(mw, r)

	response := mw.String()
	if !strings.Contains(response, "Invalid RemoteAddr") {
		t.Error("Expected 'Invalid RemoteAddr' got,", response)
	}
}

// Test via serverDoH directly
func TestParseRemoteIPv6(t *testing.T) {
	mainInit(os.Stdout, os.Stderr)

	s := &server{local: &mockResolver{}}
	mw := newMockResponseWriter()

	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeMX)
	binary, err := msg.Pack()
	if err != nil {
		t.Fatal("Packing DNS message for test setup failed unexpectedly", err)
	}

	rd := bytes.NewReader(binary)
	r, err := http.NewRequest("POST", "http://localhost", rd)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/dns-message")
	r.Header.Set("X-trustydns-Synth", "24/64") // Force serveDoH to parse remote address
	r.RemoteAddr = "[::1]:80"
	s.serveDoH(mw, r)

	if mw.statusCode != 0 {
		t.Error("Request failed", mw.statusCode, mw.String())
	}
}

// Test via serverDoH directly
func TestWriterFailure(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	mainInit(stdout, stderr)
	cfg.logClientOut = true // Capture log output to confirm correct error processing
	s := &server{local: &mockResolver{}}
	mw := newMockResponseWriter()
	mw.writeError = errors.New("mockResponseWriter Write failed")

	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeMX)
	binary, err := msg.Pack()
	if err != nil {
		t.Fatal("Packing DNS message for test setup failed unexpectedly", err)
	}

	rd := bytes.NewReader(binary)
	r, err := http.NewRequest("POST", "http://localhost", rd)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/dns-message")
	s.serveDoH(mw, r)

	if mw.statusCode != 503 {
		t.Error("Expected request to fail with 503, not", mw.statusCode)
	}
	if !strings.Contains(stdout.String(), "writer.Write(body) failed") {
		t.Error("Expected a writer.Write error message, not", stdout.String())
	}
}

// Confirm that the verificaton failure is captured via the rather clunky httpLogCapture
func TestClientVerificationFailure(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	mainInit(stdout, stderr)
	dohServer := &server{local: &mockResolver{}}
	cfg.logTLSErrors = true

	cas := []string{"testdata/rootCA.cert"}
	tlsConfig, err := tlsutil.NewServerTLSConfig(false, cas,
		[]string{"testdata/server.cert"}, []string{"testdata/server.key"})
	if err != nil {
		t.Fatal("Got error setting up test", err)
	}
	httpsServer := httptest.NewUnstartedServer(dohServer.newRouter())
	httpsServer.TLS = tlsConfig
	httpsServer.Config = &http.Server{ErrorLog: log.New(&httpLogCapture{server: dohServer}, "", 0)}
	httpsServer.StartTLS()

	client := http.Client{}
	req, err := http.NewRequest("POST", httpsServer.URL+"/dns-query", strings.NewReader(""))
	if err != nil {
		t.Fatal("Unexpected error setting up POST request for test", err)
	}
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("Expected an error return from client.Do()")
	}
	if !strings.Contains(err.Error(), "cannot validate certificate") {
		t.Error("Expected 'cannot validate certificate' error message, not", err)
	}
}
