package main

import (
	"time"

	"github.com/markdingo/trustydns/internal/flagutil"
)

type config struct {
	gops              bool
	help              bool
	verbose           bool
	verifyClientCerts bool
	version           bool

	listenAddresses flagutil.StringValue // Addresses for inbound HTTP requests

	resolvConf     string
	statusInterval time.Duration
	requestTimeout time.Duration

	ecsRemove           bool // Remove inbound ECS
	ecsSet              bool
	ecsSetIPv4PrefixLen int
	ecsSetIPv6PrefixLen int

	logAll       bool // Turns on all other log options
	logClientIn  bool // Compact print of DNS query arriving from the HTTPS client
	logClientOut bool // Compact print of DNS response returned to the HTTPS client
	logHTTPIn    bool // Compact print of HTTP query arriving from the HTTPS client
	logHTTPOut   bool // Compact print of HTTP response returned to the HTTPS client
	logLocalIn   bool // Compact print of DNS response returned by the local resolver
	logLocalOut  bool // Compact print of DNS query sent to the local resolver
	logTLSErrors bool // Print Client TLS verification failures

	tlsServerCertFiles  flagutil.StringValue
	tlsServerKeyFiles   flagutil.StringValue
	tlsCAFiles          flagutil.StringValue // Non-system root CAs
	tlsUseSystemRootCAs bool                 // Do/Do not use system root CAs

	cpuprofile, memprofile string

	setuidName, setgidName, chrootDir string // Process constraint settings
}
