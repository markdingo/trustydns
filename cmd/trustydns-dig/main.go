// Issue a DoH DNS query to a trustydns-server
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/markdingo/trustydns/internal/constants"
	"github.com/markdingo/trustydns/internal/resolver"
	"github.com/markdingo/trustydns/internal/resolver/doh"
	"github.com/markdingo/trustydns/internal/tlsutil"

	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// Program-wide variables
var (
	consts = constants.Get()
	cfg    *config

	stdout io.Writer
	stderr io.Writer

	flagSet *flag.FlagSet
)

//////////////////////////////////////////////////////////////////////

func fatal(args ...interface{}) int {
	fmt.Fprint(stderr, "Fatal: ", consts.DigProgramName, ": ")
	fmt.Fprintln(stderr, args...)

	return 1
}

//////////////////////////////////////////////////////////////////////
// main is a wrapper for mainExecute() so tests can call mainExecute()
//////////////////////////////////////////////////////////////////////

func mainInit(out io.Writer, err io.Writer) {
	cfg = &config{}
	stdout = out
	stderr = err
}

func main() {
	mainInit(os.Stdout, os.Stderr)
	os.Exit(mainExecute(os.Args))
}

func mainExecute(args []string) int {
	flagSet = flag.NewFlagSet(args[0], flag.ContinueOnError)
	flagSet.SetOutput(stderr)
	err := parseCommandLine(args)
	if err != nil {
		return 1 // Error already printed by the flag package
	}
	if cfg.help {
		usage(stdout)
		return 0
	}
	if cfg.version {
		fmt.Fprintln(stdout, consts.DigProgramName, "Version:", consts.Version)
		return 0
	}

	// Validate repeat count

	if cfg.repeatCount < 0 {
		return fatal("Repeat count (-r) must be GE zero, not", cfg.repeatCount)
	}

	// Validate ECS settings

	var ecsIPNet *net.IPNet
	if len(cfg.ecsSet) > 0 {
		var err error
		_, ecsIPNet, err = net.ParseCIDR(cfg.ecsSet)
		if err != nil {
			return fatal("--ecs-set", err)
		}
		if cfg.dohConfig.ECSRequestIPv4PrefixLen != 0 || cfg.dohConfig.ECSRequestIPv6PrefixLen != 0 {
			return fatal("Cannot have both --ecs-set and --ecs-request-* options set at the same time")
		}
	}

	if cfg.dohConfig.ECSRequestIPv4PrefixLen < 0 || cfg.dohConfig.ECSRequestIPv4PrefixLen > 32 {
		return fatal("--ecs-request-ipv4-prefixlen", cfg.dohConfig.ECSRequestIPv4PrefixLen,
			"must be between 0 and 32")
	}
	if cfg.dohConfig.ECSRequestIPv6PrefixLen < 0 || cfg.dohConfig.ECSRequestIPv6PrefixLen > 128 {
		return fatal("--ecs-request-ipv6-prefixlen", cfg.dohConfig.ECSRequestIPv6PrefixLen,
			"must be between 0 and 128")
	}

	remainingOptions := flagSet.NArg() // Track command line options
	optionIndex := 0

	// Validate DoH from command line: DoHServer qName [qType]

	if remainingOptions < 1 {
		return fatal("Require DoH Server URL on command line. Consider -h")
	}
	dohServerURL := flagSet.Arg(optionIndex)
	if len(dohServerURL) == 0 {
		return fatal("DoH Server URL cannot be an empty string")
	}
	optionIndex++
	remainingOptions--
	u, err := url.Parse(dohServerURL)
	if err != nil {
		return fatal(err)
	}
	if len(u.Scheme) == 0 && len(u.Host) == 0 && len(u.Path) > 0 { // A plain FQDN looks like this
		u.Host = u.Path
		u.Path = ""
	}
	if len(u.Host) == 0 {
		return fatal(dohServerURL, "does not contain a hostname")
	}
	if len(u.Scheme) == 0 {
		u.Scheme = "https"
	}
	dohServerURL = u.String() // Put possibly modified URL back into the config

	// Validate qName

	if remainingOptions < 1 {
		return fatal("Require qName on command line. Consider -h")
	}

	qName := dns.Fqdn(flagSet.Arg(optionIndex))
	optionIndex++
	remainingOptions--

	// Validate qType - if present

	qTypeString := dns.TypeToString[dns.TypeA] // Default to an "A" query
	if remainingOptions > 0 {
		qTypeString = strings.ToUpper(flagSet.Arg(optionIndex))
		optionIndex++
		remainingOptions--
	}
	qType, ok := dns.StringToType[qTypeString] // Does miekg know about this type?
	if !ok {
		return fatal("Unrecognized qType of", qTypeString)
	}

	// Make sure there is no residual goop on the command line

	if remainingOptions > 0 {
		return fatal("Don't know what to do with residual goop on command line:", flagSet.Arg(optionIndex))
	}

	// Create TLS configuration for constructing HTTPS transport. This is where we set up
	// verification of server certs and activate http2.

	client := &http.Client{Timeout: cfg.requestTimeout}
	tlsConfig, err := tlsutil.NewClientTLSConfig(cfg.tlsUseSystemRootCAs, cfg.tlsCAFiles.Args(),
		cfg.tlsClientCertFile, cfg.tlsClientKeyFile)
	if err != nil {
		return fatal(err)
	}

	tr := &http.Transport{TLSClientConfig: tlsConfig}
	if err := http2.ConfigureTransport(tr); err != nil { // Use latest http2 support - is this still needed?
		return fatal(err)
	}
	client.Transport = tr

	// Complete doh Config settings and construct the DoH resolver
	cfg.dohConfig.ECSSetCIDR = ecsIPNet
	cfg.dohConfig.ServerURLs = []string{dohServerURL}

	dohResolver, err := doh.New(cfg.dohConfig, client)
	if err != nil {
		return fatal(err)
	}

	// Verify that the remote resolver handles this FQDN
	if !dohResolver.InBailiwick(qName) {
		return fatal("qName cannot be resolved remotely. Is it a valid FQDN?", qName)
	}

	// Issue the query the requested number of times

	chOut := make(chan string, 1) // Queries write to a chan so we can parallelize
	chErr := make(chan string, 1) // and reap and print the outputs without interleaving.
	if cfg.parallel {
		for qx := 0; qx < cfg.repeatCount; qx++ {
			go doQuery(chOut, chErr, dohResolver, qName, qType, cfg.short)
		}
		for qx := 0; qx < cfg.repeatCount; qx++ {
			s := <-chOut
			fmt.Fprint(stdout, s)
			s = <-chErr
			fmt.Fprint(stderr, s)
		}
	} else {
		for qx := 0; qx < cfg.repeatCount; qx++ {
			doQuery(chOut, chErr, dohResolver, qName, qType, cfg.short)
			s := <-chOut
			fmt.Fprint(stdout, s)
			s = <-chErr
			fmt.Fprint(stderr, s)
		}
	}

	return 0
}

//////////////////////////////////////////////////////////////////////

func doQuery(chOut, chErr chan string, dohResolver resolver.Resolver, qName string, qType uint16, short bool) {
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	defer func() {
		chOut <- outBuf.String()
		chErr <- errBuf.String()
	}()
	query := &dns.Msg{}
	query.SetQuestion(dns.Fqdn(qName), qType)
	resp, respMeta, err := dohResolver.Resolve(query, nil)
	if err != nil {
		fmt.Fprintln(errBuf, "Error:", err)
		return
	}

	if short {
		for _, rr := range resp.Answer {
			fmt.Fprintln(outBuf, rr.String())
		}
	} else {
		fmt.Fprintln(outBuf, resp)

		fmt.Fprintf(outBuf, ";; Query Time: %s/%s\n",
			respMeta.TransportDuration.Truncate(time.Millisecond).String(),
			respMeta.ResolutionDuration.Truncate(time.Millisecond).String())
		fmt.Fprintf(outBuf, ";; Final Server: %s\n", respMeta.FinalServerUsed)
		fmt.Fprintf(outBuf, ";; Tries: %d(queries) %d(servers)\n", respMeta.QueryTries, respMeta.ServerTries)
		fmt.Fprintf(outBuf, ";; Payload Size: %d\n", respMeta.PayloadSize)
		fmt.Fprintln(outBuf)
	}
}
