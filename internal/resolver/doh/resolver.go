/*
Package doh (aka) internal/resolver/doh is a resolver implementation which handles (DoH) lookups via
remote servers.

Typical usage is pretty straightforward. Create the resolver once then use it to resolve dns.Msgs.


     res, err := dohresolver.New(dohresolver.Config{....}, &http.Client)
     for {
         qname, msg := getMsg()
         if res.InBailiwick(qname) {
            reply, details, err := res.Resolve(*dns.Msg)
            if err == nil {
               handleReply(reply)
                ..
            }
         }
     }
*/
package doh

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/markdingo/trustydns/internal/bestserver"
	"github.com/markdingo/trustydns/internal/constants"
	"github.com/markdingo/trustydns/internal/dnsutil"
	"github.com/markdingo/trustydns/internal/resolver"

	"github.com/miekg/dns"
)

// HTTPClientDo is an interface which implements http.Client.Do() - the only http.Client method used
// by the DoH resolver. It mainly exists so we can supply a mock http.Client for testing. We cannot
// provide an alternate http.Client because http.Client is an implementation struct rather than an
// interface.
type HTTPClientDo interface {
	Do(*http.Request) (*http.Response, error)
}

const me = "resolver/doh"

// dgx = Doh General error indeX into resolver errors array
type dgxInt int

const (
	dgxPackDNSQuery dgxInt = iota // iota is reset to zero in each const() spec set
	dgxRFFU
	dgxArraySize
)

// dex = Doh Error indeX into per-best-server errors array
type dexInt int

const (
	dexCreateHTTPRequest dexInt = iota
	dexDoRequest
	dexNonStatusOk
	dexResponseReadAll
	dexContentType
	dexUnpackDNSResponse
	dexArraySize
)

type bestServerStats struct {
	success                                     int
	ecsRemoved, ecsSet, ecsRequest, ecsReturned int
	totalLatency, serverLatency                 time.Duration
	failures                                    [dexArraySize]int
}

// bestServer tracks the statistics of each of our best servers for reporter purposes.
type bestServer struct {
	name string
	bestServerStats
}

// Name meets the bestserver.Server interface
func (t *bestServer) Name() string {
	return t.name
}

func (t *bestServer) resetCounters() {
	t.bestServerStats = bestServerStats{}
}

type resolverStats struct {
	failures [dgxArraySize]int
}

type remote struct {
	consts constants.Constants // A bit of a stutter going on here here here
	config Config              // Pass in to New()

	httpClient      HTTPClientDo
	httpMethod      string // Normally POST
	ecsFamily       int    // 0 = none, 1 = ip4, 2 = ipv6 (There are no miekg/dns consts for these values)
	ecsPrefixLength int    // Only valid if ecsFamily != 0
	ecsIP           net.IP // Only valid if ecsFamily != 0
	ecsRequestData  string

	bestServer bestserver.Manager // Tracks which servers are performing well for us

	mu sync.RWMutex // Protects everything below here

	bsList []*bestServer
	resolverStats
}

func (t *remote) resetCounters() {
	t.resolverStats = resolverStats{}
}

// New creates a remote struct which supplies the internal/resolver/Resolver interface. A
// constructor Config is pass in which contains the various parameters needed to create the
// Resolver. We have to re-check a lot of what the cli programs using us have already done, but
// that's unavoidable really as we can't rely on callers to get our config right.
func New(config Config, httpClient HTTPClientDo) (*remote, error) {
	t := &remote{config: config, httpClient: httpClient}
	if t.httpClient == nil {
		t.httpClient = http.DefaultClient
	}

	t.consts = constants.Get() // Get system-wide read-only constants

	t.httpMethod = http.MethodPost // Default is POST
	if t.config.UseGetMethod {
		if t.config.ECSSetCIDR != nil ||
			t.config.ECSRequestIPv4PrefixLen != 0 || t.config.ECSRequestIPv6PrefixLen != 0 {
			return nil, errors.New("Cannot have ECS settings active when using HTTP GET")

		}
		t.httpMethod = http.MethodGet
	}

	if t.config.ECSSetCIDR != nil { // Validate the CIDR if present then prepopulate the config
		if t.config.ECSRequestIPv4PrefixLen != 0 || t.config.ECSRequestIPv6PrefixLen != 0 {
			return nil, errors.New("Cannot have ECSSetCIDR active with ECSRequest*PrefixLen settings")
		}
		maxMaskSize := 0
		switch {
		case t.config.ECSSetCIDR.IP.To4() != nil:
			t.ecsFamily = 1 // 1 = ipv4
			maxMaskSize = 32

		case t.config.ECSSetCIDR.IP.To16() != nil:
			t.ecsFamily = 2
			maxMaskSize = 128

		default:
			return nil, fmt.Errorf(me+":Unknown IP family in ECSSetCIDR: %v", t.config.ECSSetCIDR)
		}

		maskSize, _ := t.config.ECSSetCIDR.Mask.Size()
		if maskSize < 0 || maskSize > maxMaskSize {
			return nil, fmt.Errorf(me+"Mask size of %d exceeds family limit of %d in ECSSetCIDR: %v",
				maskSize, maxMaskSize, t.config.ECSSetCIDR)
		}

		t.ecsPrefixLength = maskSize
		t.ecsIP = t.config.ECSSetCIDR.IP
	}

	if t.config.ECSRequestIPv4PrefixLen < 0 || t.config.ECSRequestIPv4PrefixLen > 32 {
		return nil, fmt.Errorf(me+": Invalid IPv4 Prefix Length: %d. Must be in range 0-32",
			t.config.ECSRequestIPv4PrefixLen)
	}
	if t.config.ECSRequestIPv6PrefixLen < 0 || t.config.ECSRequestIPv6PrefixLen > 128 {
		return nil, fmt.Errorf(me+": Invalid IPv6 Prefix Length: %d. Must be in range 0-128",
			t.config.ECSRequestIPv6PrefixLen)
	}
	t.ecsRequestData = fmt.Sprintf("%d/%d", t.config.ECSRequestIPv4PrefixLen, t.config.ECSRequestIPv6PrefixLen)

	// Create a "latency" bestserver.Manager to pick the fastest, most reliable server.

	var err error
	t.bsList = make([]*bestServer, 0, len(t.config.ServerURLs))
	ifList := make([]bestserver.Server, 0, len(t.config.ServerURLs)) // go doesn't coerce arrays
	for _, n := range t.config.ServerURLs {
		bs := &bestServer{name: n}
		t.bsList = append(t.bsList, bs)
		ifList = append(ifList, bs)
	}
	t.bestServer, err = bestserver.NewLatency(t.config.LatencyConfig, ifList)
	if err != nil {
		return nil, fmt.Errorf(me + ": Could not construct bestServer Manager" + err.Error())
	}

	return t, nil
}

// InBailiwick is a not-very-robust test for whether this resolver can handle the name in
// question. It liberally accept anything that looks vaguely like a FQDN according to the miekg
// checker routines.
func (t *remote) InBailiwick(qName string) bool {
	if strings.Index(qName, ".") == -1 {
		return false
	}

	_, ok := dns.IsDomainName(qName)
	return ok && dns.IsFqdn(qName)
}

// Resolve implements the client side of DoH including our trustydns-specific features. In
// particular that means adjusting ECS according to our config. The general philosophy of this
// method is to know as little about the query as possible - in part because we don't need to and in
// part to insulate us from any future DNS enhancements we may not understand.
//
// ECS changes only apply to IN/Queries. They are:
//
// 1. If ECSRemove is set remove any ECS OPT from the query
//
// 2. If ECSSetCIDR is non-nil and there is no ECS OPT in the query (perhaps because of rule 1.)
//    then synthesize an ECS OPT from the CIDR.
//
// 3. If ECSRequest is set and there is no ECS OPT in the query (perhaps because of rule 1.) then
//    set the SynthesizeECS HTTP headers to ask trustydns-server to synthesize an ECS option based on the
//    HTTPS Client source address.
//
// These rules are sequentially processed which means that the step 2. test occurs after whatever
// step 1. may have done.
//
// Zero values in the SynthesizeECS HTTP headers have special meaning to the trustydns server in
// that they instruct it *not* to generate an ECS option under *any* circumstances.
//
func (t *remote) Resolve(dnsQ *dns.Msg, dnsQMeta *resolver.QueryMetaData) (*dns.Msg, *resolver.ResponseMetaData, error) {
	startTime := time.Now() // Track stats

	originalECSRetained := true  // Track whether the original ECS was forwarded to the DoH server
	ecsRequestData := ""         // Default ECSRequest prefix length data is the empty string
	originalId := dnsQ.MsgHdr.Id // Save for reconstitution from returned result

	ecsPresent := false  // If the query currently contains an ECS or ECS Synthesis request
	ecsRemoved := false  // If the caller-supplied ECS is removed from the query
	ecsSet := false      // If an ECS is set by this method
	ecsRequest := false  // If an ECS synthesis request is sent via HTTP
	ecsReturned := false // If a populated ECS response is found in the DNS reply

	// RFC2845 says a TSIG message *cannot* be modified in *any* way excepting the Id otherwise
	// the signature will become invalid.

	msgIsMutable := dnsQ.IsTsig() == nil

	// Constrain special processing to legitimate looking IN queries that lack a TSIG

	if dnsQ.MsgHdr.Opcode == dns.OpcodeQuery &&
		len(dnsQ.Question) == 1 &&
		dnsQ.Question[0].Qclass == dns.ClassINET &&
		msgIsMutable {

		if _, ecs := dnsutil.FindECS(dnsQ); ecs != nil { // Does the original Q contain an ECS?
			ecsPresent = true
		}

		// Rule 1. Remove any and all ECS options from the query
		if t.config.ECSRemove && ecsPresent {
			ecsRemoved = dnsutil.RemoveEDNS0FromOPT(dnsQ, dns.EDNS0SUBNET)
			originalECSRetained = false
			ecsPresent = false
		}

		// Rule 2. If Set configured and no ECS present in the query then set configured ECS.
		if t.config.ECSSetCIDR != nil && !ecsPresent {
			dnsutil.CreateECS(dnsQ, t.ecsFamily, t.ecsPrefixLength, t.ecsIP)
			originalECSRetained = false
			ecsSet = true
			ecsPresent = true
		}

		// Rule 3. If ECS Request configured and no ECS present in the query then set HTTP
		// Synthesize request header.
		if len(t.ecsRequestData) > 0 && !ecsPresent {
			ecsRequestData = t.ecsRequestData
			originalECSRetained = false
			ecsPresent = true // Strictly not true yet, but will be
			ecsRequest = true
		}
	}

	// For all query types adjust message ID for transport. This is allowed even for TSIG.

	if t.httpMethod == http.MethodGet { // Msg ID SHOULD be zero for GET to aid cache friendliness
		dnsQ.MsgHdr.Id = 0
	}

	// Serialize the DNS Query into raw binary - perhaps an odd statement, but that's what
	// happening as the transport of the query is more or less a semantic-free binary blob as
	// far as the HTTPS part of DoH is concerned.
	//
	// If we're configured to generate padding then remove any existing padding and apply
	// RFC8467 padding rules. Otherwise leave any padding in place. Arguably since padding is a
	// transport-specific (or point-to-point specific) option then any existing padding
	// should/could be removed by this proxy. An alternative argument is that if a client has
	// generated padding they have done so for good reason and we just leave it intact as it's
	// not entirely clear whether padding is truly a transport-specific option or an end-to-end
	// option. We could introduce yet-another-config option to strip any inbound padding
	// arbitrarily even if we don't add any padding, but that seems to be getting down into the
	// weeds of functionality without adding much value. Phew! Enough said about a rarely used
	// DNS feature.

	var binary []byte
	var err error

	if t.config.GeneratePadding && msgIsMutable { // If padding and mutable, use PadAndPack() to serialize
		binary, err = dnsutil.PadAndPack(dnsQ, t.consts.Rfc8467ClientPadModulo)
	} else {
		binary, err = dnsQ.Pack() // Otherwise use the regular Pack() method
	}
	if err != nil {
		t.addGeneralFailure(dgxPackDNSQuery)
		return nil, nil, errors.New(me + ":Msg Pack" + err.Error())
	}

	// Form the URL based on the current best server

	bestURL, bsix := t.bestServer.Best()
	url := bestURL.Name() // Extract the actual base URL

	// If using HTTP GET the DNS query is base64URL encoded as the value of the query string. If
	// using POST the DNS query is transported as raw binary POST data. The io.Reader 'rd'
	// remains as nil for GET but is set as a bytes.Reader of the binary query for POST.

	var rd io.Reader
	if t.httpMethod == http.MethodGet {
		url += "?" + t.consts.Rfc8484QueryParam + "=" + base64.URLEncoding.EncodeToString(binary)
	} else {
		rd = bytes.NewReader(binary)
	}

	// Explicitly construct the http.Request for http.Client.Do() so that we can add Headers and
	// conditionally supply an io.Reader.

	req, err := http.NewRequest(t.httpMethod, url, rd)
	if err != nil {
		t.addServerFailure(bsix, dexCreateHTTPRequest)
		return nil, nil, err
	}

	// Set all our standard HTTP headers

	req.Header.Set(t.consts.AcceptHeader, t.consts.Rfc8484AcceptValue)      // RFC SHOULD
	req.Header.Set(t.consts.ContentTypeHeader, t.consts.Rfc8484AcceptValue) // RFC MUST
	req.Header.Set(t.consts.UserAgentHeader,
		t.consts.PackageName+"/"+t.consts.Version+" ("+t.consts.PackageURL+")")

	// Are we configured to request ECS synthesis by the DoH server based on client IP and are
	// we allowed to mutate the message? The DoH server will similarly check for mutability so
	// we could avoid the test, but we may as well save the payload space if we know it's an
	// impossible request.

	if len(ecsRequestData) > 0 && msgIsMutable {
		req.Header.Set(t.consts.TrustySynthesizeECSRequestHeader, ecsRequestData)
	}

	resp, err := t.httpClient.Do(req) // Issue the HTTP request
	endTime := time.Now()
	totalDuration := endTime.Sub(startTime)

	if err != nil {
		t.addServerFailure(bsix, dexDoRequest)
		t.bestServer.Result(bestURL, false, endTime, 0)
		return nil, nil, err
	}

	t.bestServer.Result(bestURL, true, endTime, totalDuration)

	// Decode and validate the DoH server response.

	defer resp.Body.Close() // net/http advises this Close() to avoid a resource leak

	if resp.StatusCode != http.StatusOK { // Only accept a 200 ok status
		t.addServerFailure(bsix, dexNonStatusOk)
		qName := "?"
		if len(dnsQ.Question) >= 1 {
			qName = dnsQ.Question[0].Name
		}
		return nil, nil, fmt.Errorf(me+": Bad HTTP Status: %s with %s query id=%d qName=%s",
			resp.Status, bestURL.Name(), dnsQ.Id, qName)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.addServerFailure(bsix, dexResponseReadAll)
		return nil, nil, fmt.Errorf(me+": Body Read Error: %s", err.Error())
	}

	ct := resp.Header.Get(t.consts.ContentTypeHeader)
	if ct != t.consts.Rfc8484AcceptValue {
		t.addServerFailure(bsix, dexContentType)
		return nil, nil, fmt.Errorf(me+": Expected Content-Type of '%s' but got '%s'",
			t.consts.Rfc8484AcceptValue, ct)
	}

	if uint(len(body)) < t.consts.MinimumViableDNSMessage {
		t.addServerFailure(bsix, dexContentType)
		return nil, nil, fmt.Errorf(me+": Response message length of %d is less than minimum viable of %d",
			len(body), t.consts.MinimumViableDNSMessage)
	}

	// Phew! The HTTP response is starting to look good. Extract the payload.

	remoteDurationHeader := resp.Header.Get(t.consts.TrustyDurationHeader)
	var remoteDuration time.Duration
	if len(remoteDurationHeader) > 0 {
		remoteDuration, _ = time.ParseDuration(remoteDurationHeader) // Ignore errors as it doesn't matter
	}

	// Reconstitute the DNS Reply to return to the caller

	httpR := &dns.Msg{}
	err = httpR.Unpack(body)
	if err != nil {
		t.addServerFailure(bsix, dexUnpackDNSResponse)
		return nil, nil, fmt.Errorf(me+": dns.Unpack of reply failed: %s", err.Error())
	}

	msgIsMutable = httpR.IsTsig() == nil // Set whether the response is immutable due to the presence of a TSIG

	// RFC8484 5.1 says to adjust down TTL by Age. It fails to say what to do if Age is greater
	// than the TTL. Retry again with "Cache-Control: no-cache"? The trustydns-server never does any
	// HTTP caching so if we're talking to one of them this problem should never occur. In any
	// case we never reduce a TTL to below 1s just to be a bit protective of the caller as a TTL
	// of zero is not well defined.

	if msgIsMutable {
		ageValue := resp.Header.Get(t.consts.AgeHeader) // A caching HTTPS proxy could return an 'age' response
		if len(ageValue) > 0 {
			ttlAdjust, err := strconv.ParseUint(ageValue, 10, 32) // TTL is 32bit so...
			if err == nil && ttlAdjust > 0 {
				dnsutil.ReduceTTL(httpR, uint32(ttlAdjust), 1)
			}
		}
	}

	// Are we expecting an ECS response to be returned?

	if ecsPresent {
		if _, ecs := dnsutil.FindECS(httpR); ecs != nil { // Does the response contain an ECS?
			if ecs.SourceScope > 0 {
				ecsReturned = true
			}
		}
	}

	// If allowed, modified the response to more closely match the query. This includes:
	//  - recover original ID in case this was zeroed for GET
	//  - conditionally redact ECS if we synthesized or modified original
	//  - remove returned padding if we generated query padding

	httpR.MsgHdr.Id = originalId
	if msgIsMutable {
		if !originalECSRetained && t.config.ECSRedactResponse {
			dnsutil.RemoveEDNS0FromOPT(httpR, dns.EDNS0SUBNET)
		}
		if t.config.GeneratePadding {
			dnsutil.RemoveEDNS0FromOPT(httpR, dns.EDNS0PADDING)
		}
	}

	t.addSuccessStats(bsix, totalDuration, remoteDuration, ecsRemoved, ecsSet, ecsRequest, ecsReturned)

	respMeta := &resolver.ResponseMetaData{
		TransportType:      resolver.DNSTransportHTTP,
		TransportDuration:  totalDuration - remoteDuration,
		ResolutionDuration: remoteDuration,
		PayloadSize:        httpR.Len(),
		QueryTries:         1,
		ServerTries:        1,
		FinalServerUsed:    bestURL.Name(),
	}
	if respMeta.TransportDuration <= 0 {
		respMeta.TransportDuration = 1 // Never let durations be LE 0
	}
	if respMeta.ResolutionDuration <= 0 {
		respMeta.ResolutionDuration = 1
	}

	return httpR, respMeta, nil
}
