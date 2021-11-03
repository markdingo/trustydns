package main

import (
	"fmt"
	"io"
	"text/template"
	"time"

	"github.com/markdingo/trustydns/internal/bestserver"
)

// The "flag" package is not tty aware so we've arbitrarily picked 100 columns as a conservative tty
// width for the usage output.

const usageMessageTemplate = `
NAME
          {{.ProxyProgramName}} -- a DNS Over HTTPS proxy

SYNOPSIS
          {{.ProxyProgramName}} [options] DoH-server-URL...

DESCRIPTION
          {{.ProxyProgramName}} is a DNS over HTTPS proxy based on {{.RFC}} (DoH). It acts as a local
          resolver by accepting DNS queries and forwards them over HTTPS to a DoH server for
          resolution. The intent is to provide secure and private DNS resolution particularly in the
          presence of unwanted DNS hijacking or snooping.

          {{.ProxyProgramName}} is designed to be small and lightweight. Because it readily cross-compiles
          to every target system supported by https://golang.org, {{.ProxyProgramName}} is well suited to
          installation on a home-gateway or router in place of the default dns forwarder.
          Alternatively {{.ProxyProgramName}} can be installed at your office or home on a small server
          such as a Raspberry Pi.

          Split-horizon resolution is enabled by supplying a resolv.conf file containing local
          'domain' and 'search' names. Suffix-matched domains are forward for resolution to the
          local resolv.conf nameservers rather than to the DoH servers. Additional local-resolution
          names can be supplied on the command-line if you want to use a system generated
          resolv.conf or similar immutable file.

          The wildcard interface address and default DNS port are used if no listen addresses are
          specified. Queries are accepted on UDP and TCP.

          Over time all supplied DoH-server-URLs are used to resolve queries. A simplistic algorithm
          selects the "preferred" server based on minimum average latency resulting in most queries
          being directed to the "preferred" server.

RESOLUTION LOOPS
          Extreme care must be taken when creating a system-wide resolv.conf containing the listen
          address of this program *and* supplying a local resolv.conf to this program for
          split-horizon resolution. These two files *must not* refer to the same listen address
          otherwise local resolution simply calls this program which in turn calls local resolution
          which in turns calls this program which ... well, you get the idea, it results in an
          un-ending query loop.

          Unfortunately this sort of loop detection is very hard to detect as there is no easy way
          to add meta-data to a DNS query without making it something that might fail on a very
          pedantic/simple or old local resolver. One thought is to add a populated NSID with a
          unique ID, but strictly that makes the query invalid and a pedantic local resolver could
          rightly reject the query. Suggestions and ideas welcome.

COMPANION SERVER
          {{.ServerProgramName}} is a full-featured DoH server which is normally packaged with
          {{.ProxyProgramName}}. While {{.ProxyProgramName}} and {{.ServerProgramName}} have a few feature
          extensions to enhance the DoH exchange, {{.ProxyProgramName}} should nonetheless work with any
          {{.RFC}} compliant DoH server.

INVOCATION
          If you choose to deploy the companion server, then invocation will normally refer to your
          {{.ServerProgramName}} URL, eg:

              $ {{.ProxyProgramName}} https://{{.ServerProgramName}}.example.net/dns-query

          Alternatively if you choose not to deploy your own server and are happy to trust Moz://a
          and CloudFlare an invocation might be:

              $ {{.ProxyProgramName}} https://mozilla.cloudflare-dns.com/dns-query

          or if you prefer a DoH server from quad9.net, an invocation might be:

              $ {{.ProxyProgramName}} https://dns.quad9.net/dns-query

          There are other public DoH servers besides those run by Mozilla and Quad9. A fairly
          comprehensive list can be found at https://github.com/curl/curl/wiki/DNS-over-HTTPS.
          Regardless of which DoH services you use, once you've started {{.ProxyProgramName}} you should
          be able to issue DNS queries on the local system interface such as:

              $ dig @127.0.0.1 apple.com mx

          Assuming this query works you can update the client systems to refer to the configured
          listen address of {{.ProxyProgramName}} to start reaping the benefits of DoH. In many
          cases this might be via changes to your DHCP server.

EDNS0 CLIENT SUBNET (ECS)
          Unfortunately {{.RFC}} is silent on ECS handling yet there are good arguments that ECS
          settings for topologically remote resolution and protecting client IP disclosure are
          crucial matters which should be used, or at least negotiated with a DoH server.

          Ultimately DoH servers can choose to do whatever they want with ECS and there is nothing
          that can force a particular behavior. For that reason it's important that you pick your
          DoH servers carefully. Better yet consider deploying {{.ServerProgramName}} yourself and
          have the preferred behaviour under your complete control.

          Both {{.ProxyProgramName}} and {{.ServerProgramName}} collaborate to manipulate ECS to try and give
          the client the best possible experience as well as let them control the level of
          disclosure implicit with ECS. In that regard {{.ProxyProgramName}} does the following with
          IN/Queries:

          1. If --ecs-remove is set then any inbound ECS option is removed from the query.

          2. If --ecs-set is set and there is no ECS option present in the query (perhaps due to the
             earlier removal by --ecs-remove) then an ECS option is created with the supplied CIDR).

          3. If one of the --ecs-request-* options is set and there is no ECS option present in the
             query (perhap due to the earlier removal by --ecs-remove) then the 'SynthesizeECS' HTTP
             header is set for processing by {{.ServerProgramName}}. This option is mutually exclusive
             with --ecs-set.

             Zero values for the ecs-request-* options have a special meaning for {{.ServerProgramName}}.
             Zero indicates that no ECS option should be generated for the respective IP version.
             Each of the prefix length settings are independent of each other thus a zero for ipv4
             is valid with a non-zero value for ipv6 and vice versa.

          4. If an ECS option is synthesized due to --ecs-set or --ecs-request-* and the
             --ecs-redact-response option is also set then any ECS option is removed from the DNS
             query prior to returning to the client. The --ecs-redact-response option is useful if
             you don't want clients detecting the ECS synthesis or if the client DNS library has
             trouble consuming the ECS option in the DNS response. This option has no effect if the
             query arrives with a prepopulated ECS option.


          For maximum privacy of the client use {{.ServerProgramName}} as your DoH server and invoke
          {{.ProxyProgramName}} with:

               --ecs-remove --ecs-redact-response \
               --ecs-request-ipv4-prefixlen 0 --ecs-request-ipv6-prefixlen 0 \
               URL-to-{{.ServerProgramName}}

          this causes {{.ProxyProgramName}} to remove any ECS option that may be present in an
          IN/Query and requests that no ECS option be generated by {{.ServerProgramName}}. Note this
          is non-standard behaviour as standard conforming DoH servers are under no obligation to
          avoid generating an ECS option if they choose to do so.

          To reap the maximum benefits of ECS - that is, so that authoritative servers can generate
          locally relevant responses - use {{.ServerProgramName}} as your DoH server and invoke
          {{.ProxyProgramName}} with:

               --ecs-remove --ecs-request-ipv4-prefixlen 24 --ecs-request-ipv6-prefixlen 64 \
               URL-to-{{.ServerProgramName}}

          this causes {{.ServerProgramName}} to synthesize an ECS option based on the public IP of
          the system running {{.ProxyProgramName}}.

ECS CAVEATS
          The EDNS0 CLIENT SUBNET option is documented as an "Informational" rather than a
          "Standards Track" RFC. In part this is because it is only of use to a relatively small
          subset of the DNS infrastructure - mostly those running GSLBs such as large content
          providers. As a consequence it is not widely implemented in authoritative servers, caches
          or forwarders.

          This means that in spite of your best efforts to synthesize an appropriate ECS option it
          may be ignored by the DoH server or any DNS infrastructure used by the DoH server to
          resolve the query.

BEST SERVER
          The 'bestserver' options (all prefixed with --bs-) control the choice of DoH servers
          supplied on the command line. The 'bestserver' algorithm evaluates the DoH servers to
          select the server with the lowest latency and highest reliability as influenced by the
          --bs-* options.

          As a general rule you'll not want to change the defaults. If you do, the settings have the
          following meaning:

          --bs-reassess-after duration
          --bs-reassess-count count
               Reassessment of the best server occurs after 'duration' amount of time or 'count'
               calls to Result() since the last reassessment - whichever comes first. The outcome is
               that a new best server could be chosen if it has exhibited better performance than
               the current best server.

          --bs-reset-failed-after duration
               When a server is reported as failing it is not considered by the reassesment process
               until after this duration has transpired. The only exception is if all servers are
               failing in which case the best "failing" server is chosen as a last resort.

          --bs-sample-others-every rate
               To gather performance results about all servers so as to be able to evaluate a new
               best server, the Best() method periodically returns each of the non-failing servers
               to the caller. This option defines the rate at which these non-best servers are
               returned and thus sampled. For every 'rate' calls to Result() the subsequent call to
               Best() will return a non-best, non-failing server.

          --bs-weight-for-latest percent
               The percentage weight given to the latency supplied in the Result() call when
               calculating the the current latency average. The closer this number is to 100, the
               more emphasis is placed in the latest latency reports. The closer this number is to
               zero, the more emphasis is placed on historical latency reports.The formula is:

               latency = 'percent' * Result(Latency) + (100 - 'percent') * latency

OPTIONS
          [-ghpv]
          [-A listen Address[:port] ...] [--tcp] [--udp]

          [-c resolv.conf path with local domains] [-e localdomain ...]
          [-i status-report-interval] [-r maximum remote concurrency]
          [-t remote request timeout]

          [--bs-reassess-after duration]                       **best server
          [--bs-reassess-count count]                             controls**
          [--bs-reset-failed-after duration]
          [--bs-sample-others-every rate]
          [--bs-weight-for-latest percent]

          [--ecs-remove]
            [                                                  **Either**
                [--ecs-request-ipv4-prefixlen prefix-len]
                [--ecs-request-ipv6-prefixlen prefix-len]
                [--ecs-redact-response]
              |                                                **Or**
                [--ecs-set CIDR]
                [--ecs-redact-response]
            ]

          [--log-client-in] [--log-client-out] [--log-tls-errors]
          [--log-all]

          [--tls-cert TLS Client Certificate file]
          [--tls-key TLS Client Key file]
          [--tls-other-roots TLS Root Certificate file...]
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
	flagSet.SetOutput(out)
	flagSet.PrintDefaults()
	fmt.Fprintln(out, "\nVersion:", consts.Version)
}

// parseCommandLine sets up the flags-to-config mapping and parses the supplied command line
// arguments. It starts from scratch each time to make it easier for test wrappers to use.
func parseCommandLine(args []string) error {
	flagSet.BoolVar(&cfg.dohConfig.UseGetMethod, "g", false, "Use HTTP GET with the 'dns' query parameter (instead of POST)")
	flagSet.BoolVar(&cfg.help, "h", false, "Print usage message to Stdout then exit(0)")
	flagSet.BoolVar(&cfg.dohConfig.GeneratePadding, "p", false, "Add RFC8467 recommended padding to queries (breaks some resolvers)")
	flagSet.BoolVar(&cfg.verbose, "v", false, "Verbose status and stats - otherwise only errors are output")

	flagSet.Var(&cfg.listenAddresses, "A",
		"Listen `address` for inbound DNS queries (default :"+consts.DNSDefaultPort+")")

	flagSet.BoolVar(&cfg.tcp, "tcp", true, "Listen for TCP DNS Queries")
	flagSet.BoolVar(&cfg.udp, "udp", true, "Listen for UDP DNS Queries")

	flagSet.StringVar(&cfg.localResolvConf, "c", "",
		"`path` to resolv.conf with split-horizon domains and local resolver IPs")
	flagSet.Var(&cfg.localDomains, "e", "A `domain` to consider local along with those in resolv.conf (-c)")
	flagSet.DurationVar(&cfg.statusInterval, "i", time.Minute*15, "Periodic Status Report `interval`")
	flagSet.IntVar(&cfg.maximumRemoteConnections, "r", 10, "Maximum `concurrent` connections per DoH server")
	flagSet.DurationVar(&cfg.requestTimeout, "t", time.Second*15, "Remote request `timeout`")

	// bestserver options

	flagSet.DurationVar(&cfg.dohConfig.LatencyConfig.ReassessAfter, "bs-reassess-after",
		bestserver.DefaultLatencyConfig.ReassessAfter,
		"Reassess after `duration`")
	flagSet.IntVar(&cfg.dohConfig.LatencyConfig.ReassessCount, "bs-reassess-count",
		bestserver.DefaultLatencyConfig.ReassessCount,
		"Reassess after `count` requests")
	flagSet.DurationVar(&cfg.dohConfig.LatencyConfig.ResetFailedAfter, "bs-reset-failed-after",
		bestserver.DefaultLatencyConfig.ResetFailedAfter,
		"Reset failed servers to initial state after this `duration`")
	flagSet.IntVar(&cfg.dohConfig.LatencyConfig.SampleOthersEvery, "bs-sample-others-every",
		bestserver.DefaultLatencyConfig.SampleOthersEvery,
		"Try other servers every `sample` Result() calls")
	flagSet.IntVar(&cfg.dohConfig.LatencyConfig.WeightForLatest, "bs-weight-for-latest",
		bestserver.DefaultLatencyConfig.WeightForLatest,
		"Weight Result(Latency) by `percent`")

	// ECS options

	flagSet.BoolVar(&cfg.dohConfig.ECSRedactResponse, "ecs-redact-response", false,
		"Remove synthesized response ECS")
	flagSet.BoolVar(&cfg.dohConfig.ECSRemove, "ecs-remove", false, "Remove ECS from inbound query")
	flagSet.IntVar(&cfg.dohConfig.ECSRequestIPv4PrefixLen, "ecs-request-ipv4-prefixlen", 0,
		"Server-side IPv4 ECS synthesis `Prefix-Length` (normally 24 when used)")
	flagSet.IntVar(&cfg.dohConfig.ECSRequestIPv6PrefixLen, "ecs-request-ipv6-prefixlen", 0,
		"Server-side IPv6 ECS synthesis `Prefix-Length` (normally 64 when used)")
	flagSet.StringVar(&cfg.ecsSet, "ecs-set", "", "`CIDR` to set ECS IP Address and Prefix Length")

	flagSet.BoolVar(&cfg.logAll, "log-all", false, "Turns on all other --log-* options")
	flagSet.BoolVar(&cfg.logClientIn, "log-client-in", false, "Compact print of query arriving from client")
	flagSet.BoolVar(&cfg.logClientOut, "log-client-out", false, "Compact print of response returned to client")
	flagSet.BoolVar(&cfg.logTLSErrors, "log-tls-errors", false, "Print crypto/x509 errors from HTTPS request")

	// TLS

	flagSet.StringVar(&cfg.tlsClientCertFile, "tls-cert", "", "TLS Client Certificate `file`")
	flagSet.StringVar(&cfg.tlsClientKeyFile, "tls-key", "", "TLS Client Key `file`")
	flagSet.Var(&cfg.tlsCAFiles, "tls-other-roots", "Non-system Root CA `file` used to validate HTTPS endpoints")
	flagSet.BoolVar(&cfg.tlsUseSystemRootCAs, "tls-use-system-roots", true,
		"Validate HTTPS endpoints with root CAs")

	// gops go pprof settings

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
