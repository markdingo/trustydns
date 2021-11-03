package main

import (
	"time"

	"github.com/markdingo/trustydns/internal/flagutil"
	"github.com/markdingo/trustydns/internal/resolver/doh"
)

type config struct {
	gops    bool
	help    bool
	tcp     bool // Listen on TCP
	udp     bool // Listen on UDP
	verbose bool
	version bool

	listenAddresses flagutil.StringValue // Listen address for inbound DNS queries

	localResolvConf string
	localDomains    flagutil.StringValue // In addition to those in resolv.conf
	statusInterval  time.Duration

	maximumRemoteConnections int
	requestTimeout           time.Duration
	ecsSet                   string

	logAll       bool // Turns on all other log options
	logClientIn  bool // Print the DNS query arriving from the client
	logClientOut bool // Print the DNS response returned to the client
	logTLSErrors bool // Print x509 errors returned from the DoH Resolver

	tlsClientCertFile   string // Connect to the DoH Server using these credentials
	tlsClientKeyFile    string
	tlsCAFiles          flagutil.StringValue // Non-system root CAs to validate DoH Servers
	tlsUseSystemRootCAs bool                 // Do/Do not use system root CAs to validate DoH Servers

	dohConfig doh.Config

	cpuprofile, memprofile string

	setuidName, setgidName, chrootDir string // Process constraint settings
}
