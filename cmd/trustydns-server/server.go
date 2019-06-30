package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/markdingo/trustydns/internal/concurrencytracker"
	"github.com/markdingo/trustydns/internal/connectiontracker"
	"github.com/markdingo/trustydns/internal/dnsutil"
	"github.com/markdingo/trustydns/internal/resolver"

	"github.com/miekg/dns"
)

type serFailureIndex int

const ( // ser = Server ERror index into failure counter array
	serBadContentType serFailureIndex = iota // iota resets to zero in each const() spec set
	serBadMethod
	serBadPrefixLengths
	serBadQueryParamDecode
	serBodyReadError
	serClientTLSBad
	serDNSPackResponseFailed
	serDNSUnpackRequestFailed
	serECSSynthesisFailed
	serHTTPWriterFailed
	serLocalResolutionFailed
	serQueryParamMissing
	serArraySize
)

type evIndex int

const ( // ev = EVent index into eventCounters
	evGet evIndex = iota // GET vs POST
	evTsig
	evEDNS0Removed
	evECSv4Synth
	evECSv6Synth
	evPadding
	evListSize
)

type events [evListSize]bool

type stats struct {
	successCount    int               // Queries that ran to completion without error
	totalLatency    time.Duration     // Duration of all successful queries
	eventCounters   [evListSize]int   // Events that occur during the course of a query
	failureCounters [serArraySize]int // Errors that stop a query from progressing
}

type server struct {
	stdout        io.Writer
	local         resolver.Resolver
	listenAddress string
	server        *http.Server               // Keep a copy solely for the stop() method
	ccTrk         concurrencytracker.Counter // Track peak concurrent server requests
	connTrk       *connectiontracker.Tracker

	mu sync.RWMutex // Protects everything below here
	stats
}

// httpLogCapture helps us capture errors logged by net/http so as to record HTTPS client
// certificate failures. Unfortunately there is no well defined way of detecting a client connecting
// with an invalid certificate so we basically scrape the error messages that the http package logs.
type httpLogCapture struct { // I/O Writer to statisfy log.New()
	server *server
	stdout io.Writer
	logit  bool
}

func (t *httpLogCapture) Write(data []byte) (int, error) {
	t.server.addFailureStats(serClientTLSBad, events{})
	if t.logit {
		fmt.Fprint(t.stdout, "Client TLS Error: ")
		return t.stdout.Write(data)
	}

	return len(data), nil
}

// start starts up a HTTP/HTTPS Server and writes to errorChan at server exit.
//
// tlsConfig is modified by the h2 start-up code prior to net/http cloning it. The code comment in
// "type Server struct" says "this value is cloned by ServeTLS and ListenAndServeTLS" but it doesn't
// say it does so *prior* to modification thus we cannot share a common tlsConfig across servers
// otherwise we create a race.
func (t *server) start(tlsConfig *tls.Config, errorChan chan error, wg *sync.WaitGroup) {
	t.server = &http.Server{
		Addr:     t.listenAddress,
		ErrorLog: log.New(&httpLogCapture{server: t, stdout: t.stdout, logit: cfg.logTLSErrors}, "", 0),
		Handler:  t.newRouter(),
	}
	if tlsConfig != nil {
		t.server.TLSConfig = tlsConfig.Clone()
	}

	t.connTrk = connectiontracker.New(t.listenName())
	t.server.ConnState = func(c net.Conn, state http.ConnState) {
		t.connTrk.ConnState(c.RemoteAddr().String(), time.Now(), state)
	}

	wg.Add(1)
	go func() {
		if cfg.tlsServerKeyFiles.NArg() > 0 {
			errorChan <- t.server.ListenAndServeTLS("", "") // Keys and certs are in tlsConfig
		} else {
			errorChan <- t.server.ListenAndServe() // Only returns on start-up error or shutdown request
		}
		wg.Done()
	}()
}

// newRouter creates the routing infrastructure independently of the server for ease of testing.
func (t *server) newRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(consts.Rfc8484Path, func(w http.ResponseWriter, r *http.Request) {
		t.serveDoH(w, r)
	})

	return mux
}

// serveDoH is called once per query in a newly created go-routine.
func (t *server) serveDoH(writer http.ResponseWriter, httpReq *http.Request) {
	var evs events

	t.ccTrk.Add() // Track peak concurrency
	defer t.ccTrk.Done()

	if t.connTrk != nil {
		t.connTrk.SessionAdd(httpReq.RemoteAddr) // Track sessions per-connection
		defer t.connTrk.SessionDone(httpReq.RemoteAddr)
	}

	if cfg.logHTTPIn {
		fmt.Fprintln(t.stdout, "HI:"+httpReq.RemoteAddr, http.MethodPost, httpReq.URL.String())
	}

	// Validate the request

	body, serx, httpStatusCode, errMsg := t.validateRequest(httpReq)
	if len(errMsg) > 0 {
		t.error(writer, httpReq.RemoteAddr, httpStatusCode, errMsg)
		t.addFailureStats(serx, evs)
		return
	}

	// If it was a POST request we already have the DNS binary message ready to go in 'body'. If
	// it's a GET request we have to base64URL decode the query-param. These should be very rare
	// requests as GET is mostly deprecated for POST.

	if httpReq.Method == http.MethodGet {
		evs[evGet] = true
		var serx serFailureIndex
		var errMsg string
		body, serx, errMsg = t.decodeQueryParam(httpReq)
		if len(errMsg) > 0 {
			t.error(writer, httpReq.RemoteAddr, http.StatusBadRequest, errMsg)
			t.addFailureStats(serx, evs)
			return
		}
	}

	// Decode the binary DNS query for DoH processing then re-encode for local resolution.

	dnsQ := &dns.Msg{}
	err := dnsQ.Unpack(body)
	if err != nil {
		msg := fmt.Sprintf("Error: dns.Unpack failed: %s", err.Error())
		t.error(writer, httpReq.RemoteAddr, http.StatusBadRequest, msg)
		if cfg.logClientIn {
			fmt.Fprintln(t.stdout, "CE:"+msg)
		}
		t.addFailureStats(serDNSUnpackRequestFailed, evs)
		return
	}

	if cfg.logClientIn {
		fmt.Fprintln(t.stdout, "CI:"+dnsutil.CompactMsgString(dnsQ))
	}

	// If the query Id is zero (which it should be for GET), generate a non-zero Id and remember
	// to reinstantiate the original Id in the response returned to the caller.

	originalId := dnsQ.MsgHdr.Id
	if originalId == 0 {
		dnsQ.MsgHdr.Id = dns.Id()
	}

	// Determine whether we can mutate the message for ECS and padding.

	msgIsMutable := dnsQ.IsTsig() == nil
	evs[evTsig] = !msgIsMutable
	addServerPadding := -1

	if msgIsMutable {
		ecsRequestData := httpReq.Header.Get(consts.TrustySynthesizeECSRequestHeader)
		if cfg.ecsRemove || len(ecsRequestData) > 0 || cfg.ecsSet { // Expunge any pre-existing ECS OPT?
			dnsutil.RemoveEDNS0FromOPT(dnsQ, dns.EDNS0SUBNET)
			evs[evEDNS0Removed] = true
		}

		if len(ecsRequestData) > 0 || cfg.ecsSet {
			evx, serx, errMsg := t.synthesizeECS(dnsQ, ecsRequestData, httpReq.RemoteAddr)
			if len(errMsg) > 0 {
				t.error(writer, httpReq.RemoteAddr, http.StatusBadRequest, errMsg)
				t.addFailureStats(serx, evs)
				return
			}
			evs[evx] = true
		}

		addServerPadding = dnsutil.FindPadding(dnsQ) // Remember to add padding to response if so signalled
		if addServerPadding >= 0 {                   // Remove as padding is hop-to-hop specific
			evs[evPadding] = true
			dnsutil.RemoveEDNS0FromOPT(dnsQ, dns.EDNS0PADDING)
		}
	}

	// Resolve

	if cfg.logLocalOut {
		fmt.Fprintln(t.stdout, "LO:"+dnsutil.CompactMsgString(dnsQ))
	}
	startTime := time.Now() // Track latency
	var dnsR *dns.Msg
	var dnsRMeta *resolver.ResponseMetaData
	queryMeta := &resolver.QueryMetaData{TransportType: resolver.DNSTransportType(httpReq.URL.Scheme)}
	dnsR, dnsRMeta, err = t.local.Resolve(dnsQ, queryMeta)
	if err != nil {
		msg := fmt.Sprintf("Error: local resolution failed: %s", err.Error())
		t.error(writer, httpReq.RemoteAddr, http.StatusServiceUnavailable, msg)
		if cfg.logLocalOut {
			fmt.Fprintln(t.stdout, "LE:"+msg)
		}
		t.addFailureStats(serLocalResolutionFailed, evs)
		return
	}

	if cfg.logLocalIn {
		fmt.Fprintln(t.stdout, "LI:"+dnsutil.CompactMsgString(dnsR),
			dnsRMeta.QueryTries, dnsRMeta.ServerTries, dnsRMeta.FinalServerUsed)
	}

	// Convert DNS message back into HTTP body binary

	dnsR.MsgHdr.Id = originalId // Arbitrarily reconstitute the original Id

	if msgIsMutable && (addServerPadding >= 0) {
		body, err = dnsutil.PadAndPack(dnsR, consts.Rfc8467ServerPadModulo) // Back into binary+padding
	} else {
		body, err = dnsR.Pack() // Turn back into binary
	}
	if err != nil {
		msg := fmt.Sprintf("DNS Pack Failed: %s", err.Error())
		t.error(writer, httpReq.RemoteAddr, http.StatusServiceUnavailable, msg)
		if cfg.logClientOut {
			fmt.Fprintln(t.stdout, "LE:"+msg)
		}
		t.addFailureStats(serDNSPackResponseFailed, evs)
		return
	}

	// Return message to caller

	duration := time.Now().Sub(startTime)
	writer.Header().Set(consts.ContentTypeHeader, consts.Rfc8484AcceptValue)
	writer.Header().Set(consts.TrustyDurationHeader, duration.String())

	_, err = writer.Write(body)
	if err != nil {
		msg := fmt.Sprintf("writer.Write(body) failed %s", err.Error())
		t.error(writer, httpReq.RemoteAddr, http.StatusServiceUnavailable, msg)
		if cfg.logClientOut {
			fmt.Fprintln(t.stdout, "DE:"+msg)
		}
		t.addFailureStats(serHTTPWriterFailed, evs)
		return
	}

	t.addSuccessStats(duration, evs)
	if cfg.logClientOut {
		fmt.Fprintln(t.stdout, "CO:"+dnsutil.CompactMsgString(dnsR),
			dnsRMeta.QueryTries, dnsRMeta.ServerTries, dnsRMeta.FinalServerUsed, duration)
	}
	if cfg.logHTTPOut {
		fmt.Fprintln(t.stdout, "HO:", httpReq.RemoteAddr, "200 Ok", len(body), duration)
	}
}

// validateRequest does some preliminary decoding of the HTTP requesst and returns the POST body, if any.
// Returns serx and a non-empty errMsg if any errors occur.
func (t *server) validateRequest(httpReq *http.Request) (body []byte, serx serFailureIndex, hsc int, errMsg string) {

	// Check Method first

	if httpReq.Method != http.MethodPost && httpReq.Method != http.MethodGet {
		serx = serBadMethod
		hsc = http.StatusMethodNotAllowed
		errMsg = fmt.Sprintf("Error: Expected Method '%s' or '%s', not '%s'",
			http.MethodPost, http.MethodGet, httpReq.Method)
		return
	}

	// Path has already been validated by muxer so move onto headers.

	ct := httpReq.Header.Get(consts.ContentTypeHeader)
	if ct != consts.Rfc8484AcceptValue {
		serx = serBadContentType
		hsc = http.StatusUnsupportedMediaType
		errMsg = fmt.Sprintf("Error: Expected %s: '%s' not '%s'",
			consts.ContentTypeHeader, consts.Rfc8484AcceptValue, ct)
		return
	}

	// Reading the body should be ok for POST *and* GET. The http.Server closes the Body so we
	// don't need to worry about that.

	var err error
	body, err = ioutil.ReadAll(httpReq.Body)
	if err != nil {
		serx = serBodyReadError
		hsc = http.StatusBadRequest
		errMsg = fmt.Sprintf("Error: Could not ReadAll request body: %s", err)
		return
	}

	return
}

// decodeQueryParam converts the GET qp into a byte slice ready for converting back into a DNS
// message. Return serx and a non-empty errMsg if any errors occur.
func (t *server) decodeQueryParam(httpReq *http.Request) (body []byte, serx serFailureIndex, errMsg string) {
	qp := httpReq.URL.Query()
	qpData, ok := qp[consts.Rfc8484QueryParam]
	if !ok {
		serx = serQueryParamMissing
		errMsg = fmt.Sprintf("Error: Query Param '%s' not present in '%s' request",
			consts.Rfc8484QueryParam, http.MethodGet)
		return
	}
	if len(qp) != 1 {
		serx = serQueryParamMissing
		errMsg = fmt.Sprintf("Error: Superfluous Query Params beyond the singular '%s' (%d)",
			consts.Rfc8484QueryParam, len(qp))
		return
	}

	body, err := base64.URLEncoding.DecodeString(qpData[0])
	if err != nil {
		serx = serBadQueryParamDecode
		errMsg = fmt.Sprintf("Error: Query Param '%s': %s", consts.Rfc8484QueryParam, err)
		return
	}

	return
}

// synthesizeECS sets the query ECS based on the inbound request as well as our config settings
// (which ultimately originate from command line options). Return a non-empty errMsg and serx if
// there is an error.
func (t *server) synthesizeECS(dnsQ *dns.Msg, ecsRequestData, remoteAddr string) (evx evIndex, serx serFailureIndex, errMsg string) {
	ipv4PrefixLen := cfg.ecsSetIPv4PrefixLen
	ipv6PrefixLen := cfg.ecsSetIPv6PrefixLen
	var err error

	if len(ecsRequestData) > 0 { // If prefixLen supplied, it usurps ecsSet
		ipv4PrefixLen, ipv6PrefixLen, err = extractPrefixLengths(ecsRequestData)
		if err != nil {
			errMsg = fmt.Sprintf("Error: Invalid Prefix Lengths %s: %s", ecsRequestData, err)
			serx = serBadPrefixLengths
			return
		}
	}

	var ip net.IP
	ip, err = parseRemoteAddr(remoteAddr)
	if err != nil {
		errMsg = fmt.Sprintf("Error: Invalid RemoteAddr: %s", err)
		serx = serECSSynthesisFailed
		return
	}

	// Synthesize ECS. Consider the special-case of prefix-len eq zero.

	switch {
	case ip.To4() != nil && ipv4PrefixLen > 0:
		evx = evECSv4Synth
		dnsutil.CreateECS(dnsQ, 1, ipv4PrefixLen, ip)

	case ip.To16() != nil && ipv6PrefixLen > 0:
		evx = evECSv6Synth
		dnsutil.CreateECS(dnsQ, 2, ipv6PrefixLen, ip)
	}

	return
}

// extractPrefixLengths teases out the ipv4 and ipv6 prefix lengths supplied in the HTTP request
// header.
//
// The format is: X-trustydns-Synth: ipv4prefixlen/ipv6prefixlen e.g. X-trustydns-Synth: 24/64
func extractPrefixLengths(requestData string) (int, int, error) {
	params := strings.Split(requestData, "/")
	if len(params) != 2 {
		return 0, 0, fmt.Errorf("Expected ipv4prefixlen/ipv6prefixlen, not '%s'", requestData)
	}
	var err error
	var ipv4PrefixLen, ipv6PrefixLen uint64
	ipv4PrefixLen, err = strconv.ParseUint(params[0], 10, 8)
	if err != nil {
		return 0, 0, fmt.Errorf("Could not convert ipv4prefixlen: %s", err)
	}
	ipv6PrefixLen, err = strconv.ParseUint(params[1], 10, 8)
	if err != nil {
		return 0, 0, fmt.Errorf("Could not convert ipv6prefixlen: %s", err)
	}

	if ipv4PrefixLen > 32 {
		return 0, 0, fmt.Errorf("IPv4 prefix length of %d is not in range 0-32", ipv4PrefixLen)
	}

	if ipv6PrefixLen > 128 {
		return 0, 0, fmt.Errorf("IPv6 prefix length of %d is not in range 0-128", ipv6PrefixLen)
	}

	return int(ipv4PrefixLen), int(ipv6PrefixLen), nil
}

// parseRemoteAddr parses the IP:port from the HTTP Request's RemoteAddr
//
// The http.Request.RemoteAddr value is documented to be of the form ipv4:port or
// [ipv6]:port. Extract out an IP address for the caller but don't get to hep up about failures,
// just return nil if it looks odd.
func parseRemoteAddr(ra string) (net.IP, error) {
	colon := strings.LastIndexByte(ra, ':')
	if colon == -1 {
		return nil, fmt.Errorf("No colon separating port %s", ra) // No :port
	}
	ipString := ra[:colon] // Extract everything before the last colon
	if len(ipString) < 2 { // Safety check for a minimum of []
		return nil, fmt.Errorf("IP Address too short: %s", ra)
	}
	if ipString[0] == '[' && ipString[len(ipString)-1] == ']' { // ipv6
		ipString = ipString[1 : len(ipString)-1]
	}

	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, fmt.Errorf("Invalid IP Address: %s", ipString)
	}

	return ip, nil
}

// error is our generic HTTP error responder which constructs the HTTP error
func (t *server) error(writer http.ResponseWriter, remoteAddr string, statusCode int, msg string) {
	http.Error(writer, msg, statusCode)
	if cfg.logHTTPOut {
		fmt.Fprintln(t.stdout, "HE:", remoteAddr, statusCode, msg)
	}
}

// stop performs an orderly shutdown of listen sockets. Mainly for tests!
func (t *server) stop() {
	if t.server != nil {
		err := t.server.Shutdown(context.Background())
		if cfg.logHTTPOut && err != nil {
			fmt.Fprintln(t.stdout, "HE:Shutdown:", err.Error())
		}
	}
}
