package doh

import (
	"net"

	"github.com/markdingo/trustydns/internal/bestserver"
)

// Config is passed to the New() constructor.
type Config struct {
	UseGetMethod    bool // Instead of the default POST
	GeneratePadding bool // RFC8467 query and response padding with zeroes

	ECSRedactResponse       bool       // If server-side synthesis/set remove ECS before returning to client
	ECSRemove               bool       // If ECS options are removed from inbound queries
	ECSRequestIPv4PrefixLen int        // Server-side synthesis if client address is IPv4 - 0=no synth
	ECSRequestIPv6PrefixLen int        // Server-side synthesis if client address is IPv6 - 0=no synth
	ECSSetCIDR              *net.IPNet // Set the ECS locally with this CIDR - cannot have ECSRequest* as well

	bestserver.LatencyConfig          // Latency Config and Server URLs are passed down
	ServerURLs               []string // to the DoH resolver.
}
