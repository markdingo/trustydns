// Package internal/resolver/local is a resolver implementation which handle local lookups via /etc/resolv.conf
package local

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/markdingo/trustydns/internal/bestserver"
	"github.com/markdingo/trustydns/internal/resolver"

	"github.com/miekg/dns"
)

const me = "localresolver"

// gfx = General Failure Index into error array for non-server specific errors

type gfxInt int

const (
	gfxTimeout     gfxInt = iota
	gfxMaxAttempts        // Maximum number of attempts exceeded
	gfxArraySize
)

// sfx = Server Failure Index into per-best-server error array

type sfxInt int

const (
	sfxExchangeError sfxInt = iota
	sfxFormatError
	sfxServerFail
	sfxRefused
	sfxNotImplemented
	sfxOther
	sfxArraySize
)

// evx = EVent indeX into per-best-server event array
const (
	evxTCPFallback = iota
	evxTCPSuperior
	evxArraySize
)

// DNSClientExchanger is an interface which implements dns.Client.Exchange() - the only dns.Client
// method used by localresolver. It exists so we can supply a mock dns.Client for testing.
type DNSClientExchanger interface {
	Exchange(query *dns.Msg, server string) (reply *dns.Msg, rtt time.Duration, err error)
}

// defaultNewDNSClientExchangerFunc returns the default struct which meets the DNSClientExchanger
// interface, namely a miekg/dns.Client.
func defaultNewDNSClientExchangerFunc(net string) DNSClientExchanger {
	return &dns.Client{Net: net}
}

// bestServerStats is kept as a separate struct from bestServer so that resetCounters() is trivial
// and future-proof via the simple expedient of a struct copy.
type bestServerStats struct {
	success int

	events   [evxArraySize]int
	failures [sfxArraySize]int

	latency time.Duration
}

// bestServer is our struct for tracking the best local resolvers. We need our own struct rather
// than the default one as we track statistics and behavior above and beyond what the bestserver
// package does.
type bestServer struct {
	name string
	bestServerStats
}

// Name meets the bestserver.Server interface
func (t *bestServer) Name() string {
	return t.name
}

// resetCounters sets all bestServer counters back to zero. Caller has protected the structure from
// concurrent access.
func (t *bestServer) resetCounters() {
	t.bestServerStats = bestServerStats{}
}

// resolverStats contains global stats for this resolver instance and is used the reporter. It's a
// separate struct to make resetCounters() simple and resilient to changes.
type resolverStats struct {
	success      int
	failures     [gfxArraySize]int
	totalLatency time.Duration
}

type local struct {
	config Config

	resolverConfig *dns.ClientConfig
	domains        []string // Extracted from resolverConfig and LocalDomains then deduped

	bestServer bestserver.Manager // Tracks which servers are performing well for us

	mu sync.RWMutex // Protects everything below here

	bsList []*bestServer
	resolverStats
}

// Caller has protected data structures
func (t *local) resetCounters() {
	t.resolverStats = resolverStats{}
}

// New is the constructor for a local resolver
func New(config Config) (*local, error) {
	t := &local{config: config} // Take a copy of the supplied config
	err := t.loadResolvConf(t.config.ResolvConfPath)
	if err != nil {
		return nil, err
	}

	if t.config.NewDNSClientExchangerFunc == nil {
		t.config.NewDNSClientExchangerFunc = defaultNewDNSClientExchangerFunc
	}

	// Keep local resolver name servers in bestserver and use the "traditional" algorithm to
	// pick our "best". Clean up the resolv.conf nameserver format to suit the go Dial functions.

	servers := make([]string, 0, len(t.resolverConfig.Servers))
	for _, s := range t.resolverConfig.Servers {
		if strings.Index(s, ":") >= 0 { // If ipv6 wrap in [] so the port can be safely appended
			s = "[" + s + "]"
		}
		s += ":" + t.resolverConfig.Port
		servers = append(servers, s)
	}

	// Construct our best server collection with the traditional bestserver algorithm as that is
	// intended to mimic res_send semantics.

	t.bsList = make([]*bestServer, 0, len(servers))
	ifList := make([]bestserver.Server, 0, len(servers)) // Need a separate list as go doesn't coerce arrays
	for _, n := range servers {
		bs := &bestServer{name: n}
		t.bsList = append(t.bsList, bs)
		ifList = append(ifList, bs)
	}
	t.bestServer, err = bestserver.NewTraditional(bestserver.TraditionalConfig{}, ifList)
	if err != nil {
		return nil, errors.New(me + ":Loading '" + t.config.ResolvConfPath + "' " + err.Error())
	}

	return t, nil
}

// loadResolvConf loads a /etc/resolv.conf file and extract all domain and search parameters.
//
// Above and beyond limits within dns.ClientConfigFromFile(), this code does not superimpose the
// same limits as defined by most RESOLVER(5) manual pages such as a MAXNS set of name servers or
// maximum number of search domains.
//
// Frankly the whole resolv.conf parsing is not well defined and seems to be implemented differently
// on different platforms. E.g. A port number on nameservers is separated with a dot. So for an ipv6
// nameserver does that mean ::1.53 as oppposed to the more conventional [::1}:53? Anyhoo, we mostly
// live with whatever dns.ClientConfigFromFile() gives us. This includes possibly corrected values
// for t.resolverConfig.Attempts and t.resolverConfig.Timeout.
//
// Yet another gotcha is that you cannot sensibly have both a "search" and a "domain" option in the
// same resolv.conf. Both over-write each other and order matters depending on which resolver
// library is reading the file. In other words a file like this:
//
// domain a.b
// search b.c d.e
//
// results in a different client config than a file like this:
//
// search b.c d.e
// domain a.b
func (t *local) loadResolvConf(resolvConfPath string) (err error) {
	if len(resolvConfPath) == 0 {
		return errors.New(me + ": Empty resolv.conf path is invalid")
	}
	t.resolverConfig, err = dns.ClientConfigFromFile(resolvConfPath)
	if err != nil {
		return errors.New(me + ": " + err.Error())
	}

	// miekg/dns fixes bogus config values so we don't need to check these, but we do anyway as any
	// change in behaviour of miekg/dns could break us.

	if t.resolverConfig.Attempts <= 0 {
		t.resolverConfig.Attempts = 1
	}
	if t.resolverConfig.Timeout <= 0 {
		t.resolverConfig.Timeout = 1
	}

	// Build up the list of all local domain suffixes. Prepend and append a '.' to the names to
	// make sure comparisons cannot mistakenly span labels. Also always store comparison data in
	// lowercase.

	dedupe := make(map[string]bool) // Eliminate duplicate domains
	domains := append(t.resolverConfig.Search, t.config.LocalDomains...)
	for _, domain := range domains {
		if len(domain) > 0 { // Not sure this is possible but I don't want a panic
			domain = strings.ToLower(domain)
			if domain[0] != '.' {
				domain = "." + domain
			}
			if domain[len(domain)-1] != '.' {
				domain += "."
			}
			if strings.Contains(domain, "..") { // Double dots makes a bogus name
				return errors.New(me + ": Double dots in local domain name: " + domain)
			}
			if !dedupe[domain] { // Not seen this before?
				dedupe[domain] = true
				t.domains = append(t.domains, domain)
			}
		}
	}

	return nil
}

// InBailiwick determines if this resolver should handle the query or not. It's a suffix
// match. E.g. if the domain list contains "lulu.example.net" and "jubjaw.example.com" then a qname
// of "feedme.lulu.example.net" matches.
//
// Domains are stored with a leading "." to ensure we only match on label boundaries. That is
// "feedmelulu.example.net" does not suffix match "lulu.example.net".
func (t *local) InBailiwick(qName string) bool {
	if strings.Index(qName, ".") == -1 { // If not a FQDN
		if len(t.domains) > 0 { // and we have at least one local domain
			return true // then we handle it
		}
		return false // A non FQDN is unlikely to resolve remotely, but what can we do?
	}

	// Normalize qName. Lowercase, prepend a leading "."  and append a trailing "."  as that's
	// what miekg/dns has done with the names in resolv.conf. It also makes it easier to do
	// suffix matches and exact matches in the same comparison loop.

	qName = "." + strings.ToLower(qName)
	if qName[len(qName)-1] != '.' { // len(qName) is GE 1 so -1 is always safe
		qName += "."
	}

	for _, d := range t.domains { // Is the qName one of us?
		if strings.HasSuffix(qName, d) {
			return true
		}
	}

	return false
}

// InBailiwickDomains returns a list of all the local domains handled by this resolver instance. The
// names have been previously normalized and deduped. All we do is remove the guard dots.
func (t *local) InBailiwickDomains() (ret []string) {
	for _, d := range t.domains {
		ret = append(ret, d[1:len(d)-1]) // Trim off leading and trailing guards
	}

	return
}

// Resolve more or less re-implements res_send(3). Iterate over the best servers until we get an
// acceptable response or run out of attempts or time.
//
// If the response indicates a TCP fallback (rcode=0, truncated=true) then re-exchange the same
// query with the same server using TCP. If the TCP query fails then return the original UDP
// response to the caller who can deal with TC=1 as they see fit. Maybe we should try another server
// in this case but they could all fail or this could be the last chance we have due to retry limits
// or timeouts. I guess it's a question of how aggressive to be in getting a good response. Arguably
// we should hold on to a TC=1 as a potential response unless we get something better.
func (t *local) Resolve(q *dns.Msg, qMeta *resolver.QueryMetaData) (*dns.Msg, *resolver.ResponseMetaData, error) {
	timeAvailable := time.Second * time.Duration(t.resolverConfig.Timeout) // How long have we got?
	var timeUsed time.Duration
	respMeta := &resolver.ResponseMetaData{TransportType: qMeta.TransportType}

	exchanger := t.config.NewDNSClientExchangerFunc("") // Start off with a default/UDP dns.Client
	respMeta.TransportDuration = 1                      // No transport for local resolver so pretend API takes a nanosecond

	maxAttempts := t.resolverConfig.Attempts
	if maxAttempts > t.bestServer.Len() { // No point trying a server more than once
		maxAttempts = t.bestServer.Len()
	}

	for attempts := 1; attempts <= maxAttempts; attempts++ {
		respMeta.ServerTries++
		server, bsix := t.bestServer.Best()
		respMeta.FinalServerUsed = server.Name()          // Set response metadata in
		respMeta.TransportType = resolver.DNSTransportUDP // happy anticipation of success.
		respMeta.QueryTries++
		r, rtt, err := exchanger.Exchange(q, server.Name())
		tcpFallback := false
		tcpSuperior := false
		if err == nil && r.Rcode == dns.RcodeSuccess && r.Truncated { // Fall back to TCP?
			tcpFallback = true
			tcpExchanger := t.config.NewDNSClientExchangerFunc("tcp")
			respMeta.QueryTries++
			tcpReply, tcpRtt, tcpErr := tcpExchanger.Exchange(q, server.Name())
			if tcpErr == nil && tcpReply.Rcode == dns.RcodeSuccess { // Superior to UDP?
				tcpSuperior = true // TCP reply is superior to the UDP reply, so prefer it
				r = tcpReply
				respMeta.TransportType = resolver.DNSTransportTCP // Report successful transport
			}
			rtt += tcpRtt // Treat as one big fat query for stats purposes
		}

		// We want to know three things about the query: 1) whether it was "successful" in
		// the bestServer sense; 2) whether the response was an interesting error worthy of
		// tracking in our stats and 3) whether the resolution loop should iterate and retry
		// or stop and return to the caller.
		//
		// Iteration on error depends on whether the error can be attributed to the query or
		// the server. If the former, iteration stops. If the latter, iteration
		// continues. In some cases our definition of a server-failure vs a query-failure
		// differs from the standard libc implementation. E.g. Not Implemented is considered
		// a per-server error as each server could be running a different implementation.

		var bsSuccess bool  // Best Server success
		var sfx sfxInt = -1 // Worthy stats index if GE zero
		var iterate bool    // Loop around and retry (within retry limits)

		switch {
		case err != nil: // packet exchange failed. Assume a network or server issue.
			bsSuccess = false // Tell bestServer to demote
			sfx = sfxExchangeError
			iterate = true // Iterate on a server issue

		case r.Rcode == dns.RcodeSuccess:
			bsSuccess = true
			iterate = false

		case r.Rcode == dns.RcodeFormatError: // Assume query is bogus so stop iterating
			bsSuccess = true
			sfx = sfxFormatError
			iterate = false

		case r.Rcode == dns.RcodeServerFailure: // Assume server-specific issue
			bsSuccess = false
			sfx = sfxServerFail
			iterate = true

		case r.Rcode == dns.RcodeNameError: // NXDomain is actually a good return!
			bsSuccess = true
			iterate = false

		case r.Rcode == dns.RcodeRefused: // Assume a server access control issue
			bsSuccess = false
			sfx = sfxRefused
			iterate = true

		case r.Rcode == dns.RcodeNotImplemented: // Assume server-specific
			bsSuccess = true
			sfx = sfxNotImplemented
			iterate = true

		default: // All other Rcodes are returned to the caller
			bsSuccess = true
			sfx = sfxOther
			iterate = false
		}

		// Switch has set bsSuccess, iterate and sfx

		timeUsed += rtt
		t.bestServer.Result(server, bsSuccess, time.Now(), rtt)
		if sfx == -1 {
			t.addServerSuccess(bsix, tcpFallback, tcpSuperior, rtt)
		} else {
			t.addServerFailure(bsix, tcpFallback, tcpSuperior, sfx)
		}
		if !iterate {
			t.addGeneralSuccess()
			respMeta.ResolutionDuration = timeUsed
			respMeta.PayloadSize = r.Len()
			return r, respMeta, nil
		}

		if timeUsed > timeAvailable { // Run out of time to iterate?
			t.addGeneralFailure(gfxTimeout)
			return nil, nil, fmt.Errorf(me+": Query timeout: %ds", t.resolverConfig.Timeout)
		}
	}

	t.addGeneralFailure(gfxMaxAttempts)
	return nil, nil, fmt.Errorf(me+":Query attempts exceeded: %d", t.resolverConfig.Attempts)
}
