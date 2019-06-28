// Interface for resolving a dns.Msg
package resolver

import (
	"time"

	"github.com/miekg/dns"
)

type DNSTransportType string

const (
	DNSTransportUndefined DNSTransportType = ""
	DNSTransportHTTP                       = "http"
	DNSTransportUDP                        = "udp"
	DNSTransportTCP                        = "tcp"
)

// QueryMetaData is a primordial struct containing metadata about the query passed to Resolve(). It
// helps the function make fine-grained decisions about how to perform the resolution. For example
// whether the original query originated as a TCP query or is a re-query due to a previous
// truncation attempt. This structure is needed as DNS messages, unlike more recently protocols,
// have almost no ability to add meta data as needed. Compare with email and nttp headers.
//
// Primordial because there really isn't much to it at this stage - as you can see. It's mostly a
// place-holder in the event that we want to add more stuff later.
type QueryMetaData struct {
	TransportType DNSTransportType // Of the original inbound query
}

// ResponseMetaData returns metadata about the qhery made by Resolve(). It mostly contains
// statistical and trace meta-information.
type ResponseMetaData struct {
	TransportType DNSTransportType // Final transport used with the resultant query

	TransportDuration  time.Duration // Does not include ResolutionDuration
	ResolutionDuration time.Duration // Time taken caller actual resolver system
	// Total Resolution Duration = TransportDuration+ResolutionDuration

	PayloadSize     int
	QueryTries      int    // Number of resolution attempts were made
	ServerTries     int    // Number of different servers were tried
	FinalServerUsed string // Name of the last server attempted
}

type Resolver interface {
	// Return true if this resolver handles this qName
	InBailiwick(qName string) bool

	// Resolve() resolved the dns.Msg query. Returns resp+respMeta or error. queryMeta can be
	// nil.
	Resolve(query *dns.Msg, queryMeta *QueryMetaData) (resp *dns.Msg, respMeta *ResponseMetaData, err error)
}
