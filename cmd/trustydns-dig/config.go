package main

import (
	"time"

	"github.com/markdingo/trustydns/internal/flagutil"
	"github.com/markdingo/trustydns/internal/resolver/doh"
)

type config struct {
	help     bool
	parallel bool
	short    bool
	version  bool

	repeatCount    int
	requestTimeout time.Duration
	ecsSet         string

	tlsClientCertFile   string
	tlsClientKeyFile    string
	tlsCAFiles          flagutil.StringValue // Non-system root CAs
	tlsUseSystemRootCAs bool                 // Do/Do not use system root CAs

	dohConfig doh.Config
}
