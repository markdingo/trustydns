package main

import (
	"fmt"
	"io"
	"text/template"
	"time"
)

// The "flag" package is not tty aware so we've arbitrarily picked 100 columns as a conservative tty
// width for the usage output.

const usageMessageTemplate = `
NAME
          {{.ServerProgramName}} -- a DNS Over HTTPS server

SYNOPSIS
          {{.ServerProgramName}} [options]

DESCRIPTION
          {{.ServerProgramName}} is a DNS over HTTPS server based on {{.RFC}} (DoH). It accepts DNS
          queries serialized within an HTTP(s) request and resolves them locally. The intent is to
          provide secure and private DNS resolution particularly in the presence of unwanted DNS
          hijacking or snooping.

          The wildcard interface address and default HTTPS port are used if no listen addresses are
          specified.

INVOCATION
          The simplest invocation is:

              $ {{.ServerProgramName}}

          at which point you should be able to send DoH queries to the default listen address.

          When {{.ServerProgramName}} is invoked with a TLS Key File the listen connections accept
          HTTPS connections otherwise the listen connections accept HTTP connections. Normally HTTP
          will only be used for testing purposes and is not specified to work for DoH in general.

COMPANION PROXY
          {{.ProxyProgramName}} is a full-featured DoH proxy which is normally packaged with
          {{.ServerProgramName}}. While {{.ServerProgramName}} and {{.ProxyProgramName}} have a few feature extensions
          to enhance the DoH exchange, {{.ServerProgramName}} should nonetheless work with any {{.RFC}}
          compliant DoH client.

EDNS0 CLIENT SUBNET (ECS)
          Unfortunately {{.RFC}} is silent on ECS handling yet there are good arguments that ECS
          settings for topologically remote resolution and protecting client IP disclosure are
          crucial matters which should be used, or at least negotiated with a DoH server.

          Both {{.ProxyProgramName}} and {{.ServerProgramName}} collaborate to manipulate ECS to try
          and give the clent the best possible experience as well as let them control the level of
          disclosure implicit with ECS. See {{.ProxyProgramName}} for details on how it manages ECS
          requests from clients and how it optionally generates a HTTP header to request ECS
          synthesis by {{.ServerProgramName}}.

          ECS processing by {{.ServerProgramName}} is as follows:

          1. If --ecs-remove or --ecs-set is set or if there's an ECS synthesis request HTTP header
             then any existing ECS option is removed from the query.

          2. If the HTTP request contains an ECS synthesis header then an ECS option is created from
             the HTTPS client IP address using the prefix lengths supplied in the synthesis header.

          3. If no synthesis header is present and --ecs-set is set (either explicitly or due to
             presence of one of the --ecs-set-*-prefixlen options) then an ECS option is created
             from the HTTPS client IP address and the corresponding --ecs-set-*-prefixlen option.

ECS CAVEATS
          The EDNS0 CLIENT SUBNET option is documented as an "Informational" rather than a
          "Standards Track" RFC. In part this is because it is only of use to a relatively small
          subset of the DNS infrastructure - mostly those running GSLBs such as large content
          providers. As a consequence it is not widely implemented in authoritative servers, caches
          or forwarders.

          This means that in spite of your best efforts to synthesize an appropriate ECS option it
          may be ignored by the DNS infrastructure used by {{.ServerProgramName}} to resolve the
          query.

OPTIONS
          [-hjv]
          [-A listen Address[:port] ...]

          [-c resolv.conf for issuing DNS queries]
          [-i status-report-interval] [-t remote request timeout]

          [--ecs-remove] [--ecs-set]
          [--ecs-set-ipv4-prefixlen prefix-len]
          [--ecs-set-ipv6-prefixlen prefix-len]

          [--log-client-in] [--log-client-out]
          [--log-http-in] [--log-http-out]
          [--log-local-in] [--log-local-out]
          [--log-tls-errors]
          [--log-all]

          [--tls-cert TLS Server Certificate file] ...
          [--tls-key TLS Server Key file] ...
          [--tls-other-roots TLS Root Certificate file] ...
          [--tls-use-system-roots]

          [--gops] [--cpu-profile file] [--mem-profile file]

          [--user userName] [--group groupName] [--chroot directory]

          [--version]

`

//////////////////////////////////////////////////////////////////////

func usage(out io.Writer) {
	tmpl, err := template.New("usage").Parse(usageMessageTemplate)
	if err != nil {
		panic(err) // We've messed up our template
	}
	err = tmpl.Execute(out, consts)
	if err != nil {
		panic(err) // We've messed up our template
	}
	flagSet.SetOutput(out) // This is permanent so we assume an exit summarily
	flagSet.PrintDefaults()
	fmt.Fprintln(out, "\nVersion:", consts.Version)
}

// parseCommandLine sets up the flags-to-config mapping and parses the supplied command line
// arguments. It starts from scratch each time to make it eaiser for test wrappers to use.
func parseCommandLine(args []string) error {
	flagSet.BoolVar(&cfg.help, "h", false, "Print usage message to Stdout then exit(0)")
	flagSet.BoolVar(&cfg.verifyClientCerts, "j", false, "Verify Client Certificates")

	flagSet.Var(&cfg.listenAddresses, "A",
		"Listen `address` to accept DoH queries (default "+defaultListenAddress+")")

	flagSet.StringVar(&cfg.resolvConf, "c", "/etc/resolv.conf", "resolv.conf `file` for issuing DNS queries")
	flagSet.DurationVar(&cfg.statusInterval, "i", time.Minute*15, "Periodic Status Report `interval` (needs -v set)")
	flagSet.DurationVar(&cfg.requestTimeout, "t", time.Second*15, "Remote request `timeout`")
	flagSet.BoolVar(&cfg.verbose, "v", false, "Verbose status and stats - otherwise only errors are output")

	flagSet.BoolVar(&cfg.ecsRemove, "ecs-remove", false, "Remove any and all inbound ECS options and requests")
	flagSet.BoolVar(&cfg.ecsSet, "ecs-set", false, "Synthesize ECS from HTTPS Client IP")
	flagSet.IntVar(&cfg.ecsSetIPv4PrefixLen, "ecs-set-ipv4-prefixlen", 24,
		"ECS IPv4 Synthesis `Prefix-Length` - implies --ecs-set")
	flagSet.IntVar(&cfg.ecsSetIPv6PrefixLen, "ecs-set-ipv6-prefixlen", 64,
		"ECS IPv6 Synthesis `Prefix-Length` - implies --ecs-set")

	flagSet.BoolVar(&cfg.logAll, "log-all", false, "Turns on all other --log-* options")
	flagSet.BoolVar(&cfg.logClientIn, "log-client-in", false, "Compact print of inbound DNS query (from client)")
	flagSet.BoolVar(&cfg.logClientOut, "log-client-out", false, "Compact print of outbound DNS response (to client)")
	flagSet.BoolVar(&cfg.logHTTPIn, "log-http-in", false, "Compact print of inbound HTTP query")
	flagSet.BoolVar(&cfg.logHTTPOut, "log-http-out", false, "Compact print of outbound HTTP response")
	flagSet.BoolVar(&cfg.logLocalIn, "log-local-in", false, "Compact print of DNS response (from local resolver)")
	flagSet.BoolVar(&cfg.logLocalOut, "log-local-out", false, "Compact print of DNS query (to local resolver)")

	flagSet.BoolVar(&cfg.logTLSErrors, "log-tls-errors", false, "Print Client TLS verification failures")

	// TLS

	flagSet.Var(&cfg.tlsServerCertFiles, "tls-cert", "TLS Server Certificate `file`")
	flagSet.Var(&cfg.tlsServerKeyFiles, "tls-key", "TLS Server Key `file`")
	flagSet.Var(&cfg.tlsCAFiles, "tls-other-roots", "Non-system Root CA `file` used to validate HTTPS clients")
	flagSet.BoolVar(&cfg.tlsUseSystemRootCAs, "tls-use-system-roots", false,
		"Validate HTTPS clients with root CAs")

	// gops and go pprof settings

	flagSet.BoolVar(&cfg.gops, "gops", false, "Start github.com/google/gops agent")
	flagSet.StringVar(&cfg.cpuprofile, "cpu-profile", "", "write cpu profile to `file`")
	flagSet.StringVar(&cfg.memprofile, "mem-profile", "", "write mem profile to `file`")

	// Process Constraint parameters

	flagSet.StringVar(&cfg.setuidName, "user", "", "setuid `username` to constrain process after start-up (disabled for Linux)")
	flagSet.StringVar(&cfg.setgidName, "group", "", "setgid `groupname` to constrain process after start-up (disabled for Linux)")
	flagSet.StringVar(&cfg.chrootDir, "chroot", "", "chroot `directory` to constrain process after start-up")

	flagSet.BoolVar(&cfg.version, "version", false, "Print version and exit")

	return flagSet.Parse(args[1:])
}
