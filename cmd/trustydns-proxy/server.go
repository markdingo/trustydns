package main

/*

This module is the core of the proxy server. It translates a traditional DNS query into a DoH query
and does the reverse with the response. The processing here is straightforward as most of the logic
is contained within the doh/resolver code.

The main area of interest for this module is truncation. A response from an upstream DoH server can
easily be larger than that allowed by our downstream client using UDP. This means we have to
truncate in some cases and set TC=1. It's also the case that a DoH response can come back with TC=1
which we must be sure to pass back to the client.

Under no circumstances do we ever clear TC=1 even though some other DNS proxies are known to do
this. Our view is that this is hiding information from the client and robbing it of the ability to
make fully informed choices. In that vein we also try and retain as much of the response as possible
if we need to truncate the message. The reason being that at least the client may have something to
work with if it's incapable of making a TCP re-query. In the most common case of an address record
lookup, there are highly likely to be some answers that fit in the Answer section.

When and how to truncate and what to do with a truncated response was meant to be clarified in
rfc2181 however it seems to only have muddied the waters.

In one breath, rfc2181 says "Where TC is set, the partial RRSet that would not completely fit may be
left in the response" which suggests leaving useful answers in the response. In the next breath it
says "When a DNS client receives a reply with TC set, it should ignore that response, and query
again" which suggests that there is no point sending a partial answer as it'll be discarded
anyway. Ugg.

Our view is that a client should be given as much information as possible and let it decide what to
do next. We should not be deciding for it even if we *think* we know how it'll respond and even if
we *think* such a response will be pointless.

Having said all that, TC=1 responses are rare events so spending too much time worrying about
corner-cases probably isn't productive.

*/

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/markdingo/trustydns/internal/concurrencytracker"
	"github.com/markdingo/trustydns/internal/dnsutil"
	"github.com/markdingo/trustydns/internal/resolver"

	"github.com/miekg/dns"
)

const ( // ser = Server ERror index into failureCounters
	serNoResponse = iota // iota resets to zero in each const() spec set
	serDNSWriteFailed
	serListSize
)

const ( // ev = EVent index into events array
	evInTruncated  = iota // DoH returned TC=1
	evOutTruncated        // We set TC=1
	evListSize
)

type events [evListSize]bool

type stats struct {
	successCount    int              // Queries that ran to completion without error
	totalLatency    time.Duration    // Duration of all successful queries
	eventCounters   [evListSize]int  // Events that occur during the course of a query
	failureCounters [serListSize]int // Errors that stop a query from progressing
}

type server struct {
	stdout        io.Writer
	remote        resolver.Resolver // Mandatory resolver - never nil
	local         resolver.Resolver // Optional resolver - may be nil
	listenAddress string
	transport     string // One of listenTransports
	server        *dns.Server
	cct           concurrencytracker.Counter // Track peak concurrent server requests

	mu sync.RWMutex // Protects everything below - everything above is read-only or self-protected
	stats
}

// start starts up the dns server and writes to errorChan at server exit. Use the server's
// NotifyStartedFunc capability to actually wait until the socket is opened. That way we don't have
// to fudge a setuid delay. Too bad net/http hasn't got a NotifyStartedFunc. Unfortunately it's all
// a bit messy as the error case of a socket that cannot be opened causes an early return of
// ListenAndServer and no call to the NotifyStartedFunc. Logically that makes sense, but it requires
// a bit of juggling to make sure we return to the caller in a consistent state.
func (t *server) start(errorChan chan error, wg *sync.WaitGroup) {
	var notifyWG sync.WaitGroup
	var once sync.Once

	notifyWG.Add(1)
	t.server = &dns.Server{Addr: t.listenAddress, Net: t.transport, Handler: t, NotifyStartedFunc: func() {
		once.Do(func() { notifyWG.Done() })
	}}

	wg.Add(1) // Add to caller's waitGroup
	go func() {
		errorChan <- t.server.ListenAndServe()
		once.Do(func() { notifyWG.Done() })
		wg.Done()
	}()
	notifyWG.Wait() // Wait for dns.Server notify before returning to say server is listening (or failed)
}

// ServeDNS is called once per query in a newly created go-routine.
func (t *server) ServeDNS(writer dns.ResponseWriter, query *dns.Msg) {
	var evs events // Track events for end-of-request call to addSuccessStats()

	t.cct.Add() // Track peak concurrency for reporting purposes
	defer t.cct.Done()

	// Default to remote resolver. Only use local resolver if we have a local resolver and the
	// qName is in their bailiwick.
	currResolver := t.remote
	inType := "Cr:"  // Client In to remote DoH resolver
	outType := "CO:" // Client Out
	if t.local != nil && len(query.Question) > 0 && t.local.InBailiwick(query.Question[0].Name) {
		inType = "Cl:" // Client In to local resolver
		currResolver = t.local
	}

	if cfg.logClientIn {
		fmt.Fprintln(t.stdout, inType+writer.RemoteAddr().String()+":"+dnsutil.CompactMsgString(query))
	}

	// Forward the request for resolution to either the local resolver or a remote DoH
	// server. Stub resolvers manage failures and timeouts themselves so there is no need for
	// any recovery or retry loops here. We can't sensible manage an error return to a DNS
	// response so the best bet is to simply let the client retry ... if it chooses to do so.

	startTime := time.Now() // Track latency
	resp, respMeta, err := currResolver.Resolve(query,
		&resolver.QueryMetaData{TransportType: resolver.DNSTransportType(t.transport)})
	duration := time.Now().Sub(startTime)
	if err != nil {
		t.addFailureStats(serNoResponse, evs)
		msg := err.Error()
		if cfg.logClientOut || (cfg.logTLSErrors && strings.Contains(msg, "x509: ")) {
			fmt.Fprintln(t.stdout, "CE:"+dnsutil.CompactMsgString(query), msg)
		}
		return
	}

	// Check for the need to truncate the response. The client's size limit comes from the
	// inbound DNS query OPT, not any residual or alternative OPT that may be present in the
	// response from DoH. We use our definition of truncated rather than msg.Truncate() (which
	// has changed over time) and we also preserve the Truncated flag if it's already set.

	evs[evInTruncated] = resp.Truncated
	if t.transport == consts.DNSUDPTransport && respMeta.PayloadSize > consts.DNSTruncateThreshold {
		limit := consts.DNSTruncateThreshold
		opt := query.IsEdns0()                        // Only use client's upper limit from query
		if opt != nil && int(opt.UDPSize()) > limit { // if present *and* GT system limit
			limit = int(opt.UDPSize())
		}
		if respMeta.PayloadSize > limit { // Only call Truncate() if we have to
			evs[evOutTruncated] = true
			preserveTruncated := resp.Truncated
			beforeCount := len(resp.Answer) + len(resp.Ns) + len(resp.Extra)
			resp.Truncate(limit)
			afterCount := len(resp.Answer) + len(resp.Ns) + len(resp.Extra)
			resp.Truncated = resp.Truncated || preserveTruncated || beforeCount != afterCount
		}
	}

	err = writer.WriteMsg(resp)
	if err != nil {
		t.addFailureStats(serDNSWriteFailed, evs)
		if cfg.logClientOut {
			fmt.Fprintln(t.stdout, "CE:"+err.Error())
		}
		return
	}

	t.addSuccessStats(duration, evs)
	if cfg.logClientOut {
		fmt.Fprintln(t.stdout, outType+dnsutil.CompactMsgString(resp),
			respMeta.QueryTries, respMeta.ServerTries, "F:"+respMeta.FinalServerUsed, duration)
	}
}

// stop performs an orderly shutdown of listen sockets.
func (t *server) stop() {
	if t.server != nil {
		t.server.Shutdown()
	}
}
