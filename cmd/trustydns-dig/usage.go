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
          {{.DigProgramName}} -- a DNS Over HTTPS query program

SYNOPSIS
          {{.DigProgramName}} [options] DoH-server-URL FQDN [DNS-qType]

DESCRIPTION
          {{.DigProgramName}} issues DNS over HTTPS queries to {{.ServerProgramName}}. Some options generate
          specific request features that are unlikely to be available in normal DoH servers.
          Only qClass=IN is supported. If a DNS-Type is not supplied then qType=A is used.

          The primary purpose of {{.DigProgramName}} is to issue queries exactly as they are issued
          by {{.ProxyProgramName}} and thus test the feature exchange between it and the {{.ServerProgramName}}.
          In fact {{.DigProgramName}} purposely uses the same packages as {{.ProxyProgramName}}.

          **********
          Production Use Alert: {{.DigProgramName}} is a diagnostic program which will almost certainly
          change with each new package release. Please do not rely on its current behaviour
          or output format and definitely do not use it in a shell script.
          **********

EXAMPLES
          When using an instance of {{.ServerProgramName}}:

            $ {{.DigProgramName}} \
              --ecs-request-ipv4-prefixlen 24 --ecs-request-ipv6-prefixlen 64 \
              https://trustydns-server.example.net/dns-query yahoo.com MX

          When using a third-party DoH server from, say, Mozilla or quad9:

            $ {{.DigProgramName}} https://mozilla.cloudflare-dns.com/dns-query yahoo.com MX
            $ {{.DigProgramName}} --ecs-set 17.0.0.0/18 https://dns.quad9.net/dns-query yahoo.com

OPTIONS
          [-ghp] [--short]

          [-r repeat count] [-t remote request timeout]

          [--ecs-remove]
            [                                                  **Either**
                 [--ecs-request-ipv4-prefixlen prefix-len]
                 [--ecs-request-ipv6-prefixlen prefix-len]
              |                                                **Or**
                 [--ecs-set CIDR]
            ]

          [--padding]
          [--tls-cert TLS Client Certificate file]
          [--tls-key TLS Client Key file]
          [--tls-other-roots TLS Root Certificate file...]
          [--tls-use-system-roots]
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
// arguments. It starts from scratch each time to make it eaiser for test wrappers to use.
func parseCommandLine(args []string) error {
	flagSet.BoolVar(&cfg.dohConfig.UseGetMethod, "g", false, "Use HTTP GET with the 'dns' query parameter (instead of POST)")
	flagSet.BoolVar(&cfg.help, "h", false, "Print usage message to Stdout then exit(0)")
	flagSet.BoolVar(&cfg.parallel, "p", false, "Issue all queries in parallel")
	flagSet.IntVar(&cfg.repeatCount, "r", 1, "`Number` of times to issue the query (GE zero)")

	flagSet.BoolVar(&cfg.short, "short", false, "Generate short output showing only Answer RRs")

	flagSet.DurationVar(&cfg.requestTimeout, "t", time.Second*15, "Remote request `timeout`")

	flagSet.BoolVar(&cfg.dohConfig.ECSRemove, "ecs-remove", false, "Remove inbound ECS")
	flagSet.IntVar(&cfg.dohConfig.ECSRequestIPv4PrefixLen, "ecs-request-ipv4-prefixlen", 0,
		"Server-side IPv4 ECS synthesis `Prefix-Length` (normally 24 when used)")
	flagSet.IntVar(&cfg.dohConfig.ECSRequestIPv6PrefixLen, "ecs-request-ipv6-prefixlen", 0,
		"Server-side IPv6 ECS synthesis `Prefix-Length` (normally 64 when used)")
	flagSet.StringVar(&cfg.ecsSet, "ecs-set", "", "`CIDR` to set ECS IP Address and Prefix Length")

	flagSet.BoolVar(&cfg.dohConfig.GeneratePadding, "padding", true, "Add RFC8467 recommended padding to queries")

	flagSet.StringVar(&cfg.tlsClientCertFile, "tls-cert", "", "TLS Client Certificate `file`")
	flagSet.StringVar(&cfg.tlsClientKeyFile, "tls-key", "", "TLS Client Key `file`")
	flagSet.Var(&cfg.tlsCAFiles, "tls-other-roots", "Non-system Root CA `file` used to validate HTTPS endpoint")
	flagSet.BoolVar(&cfg.tlsUseSystemRootCAs, "tls-use-system-roots", true,
		"Validate HTTPS endpoints with root CAs")

	flagSet.BoolVar(&cfg.version, "version", false, "Print version and exit")

	return flagSet.Parse(args[1:])
}
