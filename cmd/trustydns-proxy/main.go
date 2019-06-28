// listen for inbound DNS queries and forward to a DoH server for resolution
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/markdingo/trustydns/internal/constants"
	"github.com/markdingo/trustydns/internal/osutil"
	"github.com/markdingo/trustydns/internal/reporter"
	"github.com/markdingo/trustydns/internal/resolver"
	"github.com/markdingo/trustydns/internal/resolver/doh"
	"github.com/markdingo/trustydns/internal/resolver/local"
	"github.com/markdingo/trustydns/internal/tlsutil"

	"golang.org/x/net/http2"
)

// Program-wide variables
var (
	consts           = constants.Get()
	cfg              *config
	listenTransports = []string{}

	stdout io.Writer // All I/O goes via these writers
	stderr io.Writer

	startTime                = time.Now()
	mainStarted, mainStopped bool // Record state transitions thru main (used by tests)
	stopChannel              chan os.Signal
	flagSet                  *flag.FlagSet
)

//////////////////////////////////////////////////////////////////////

func fatal(args ...interface{}) int {
	fmt.Fprint(stderr, "Fatal: ", consts.ProxyProgramName, ": ")
	fmt.Fprintln(stderr, args...)

	return 1
}

func stopMain() {
	stopChannel <- syscall.SIGINT
}

//////////////////////////////////////////////////////////////////////
// main wrappers make it easy for test programs
//////////////////////////////////////////////////////////////////////

// mainInit resets everything such that mainExecute() can be called multiple times in one program
// execution. stopChannel is buffered as the reader may disappear if there is a fatal error and
// multiple writers my try and write to the channel and we don't want those writers to stall
// forever.
func mainInit(out io.Writer, err io.Writer) {
	cfg = &config{}
	listenTransports = []string{}
	stdout = out
	stderr = err
	mainStarted = false
	mainStopped = false
	stopChannel = make(chan os.Signal, 4) // All reasonable signals cause us to quit or stats report
	signal.Notify(stopChannel, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGUSR1)
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
		fmt.Fprintln(stdout, consts.ProxyProgramName, "Version:", consts.Version)
		return 0
	}

	if cfg.logAll {
		cfg.logClientIn = true
		cfg.logClientOut = true
		cfg.logTLSErrors = true
	}

	// Validate transport settings

	if cfg.udp {
		listenTransports = append(listenTransports, consts.DNSUDPTransport)
	}
	if cfg.tcp {
		listenTransports = append(listenTransports, consts.DNSTCPTransport)
	}
	if len(listenTransports) == 0 {
		return fatal("Must have one of --tcp or --udp set")
	}

	// Validate ECS settings. These settings are also validated by the DoH resolver, but we
	// check them here as well as we can generate a more meaningful error message that equates
	// back the the command-line options whereas the DoH resolver really has no clue as to where
	// its config values came from and thus produces somewhat generic error messages.

	if cfg.dohConfig.UseGetMethod { // No ECS synthesis is possible with GET due to possible bogus caching
		if len(cfg.ecsSet) > 0 ||
			cfg.dohConfig.ECSRequestIPv4PrefixLen > 0 || cfg.dohConfig.ECSRequestIPv6PrefixLen > 0 {
			return fatal("Cannot have any ECS synthesis options when using HTTP GET")
		}
	}

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

	// Validate server URLs

	for _, dohURL := range flagSet.Args() {
		u, err := url.Parse(dohURL)
		if err != nil {
			return fatal(err)
		}
		if len(u.Scheme) == 0 && len(u.Host) == 0 && len(u.Path) > 0 { // A plain FQDN looks like this
			u.Host = u.Path
			u.Path = ""
		}
		if len(u.Host) == 0 {
			return fatal(dohURL, "does not contain a hostname")
		}
		if len(u.Scheme) == 0 {
			u.Scheme = "https"
		}
		cfg.dohConfig.ServerURLs = append(cfg.dohConfig.ServerURLs, u.String())
	}

	if len(cfg.dohConfig.ServerURLs) == 0 {
		return fatal("Must supply at least one DoH server URL on the command line")
	}

	if cfg.maximumRemoteConnections < 1 {
		return fatal("Minimum remote concurrency must be greater than zero (-r)")
	}

	var reporters []reporter.Reporter // Keep track of all reportable routines
	var servers []*server             // Keep track of all servers so we can shut then down

	// localResolver handles split-horizon domains

	if len(cfg.localResolvConf) == 0 && cfg.localDomains.NArg() > 0 {
		return fatal("Local Domains (-e) cannot be resolved without a resolv.conf (-c)")
	}

	var localResolver resolver.Resolver
	var localDomains []string
	if len(cfg.localResolvConf) > 0 {
		lr, err := local.New(local.Config{
			ResolvConfPath: cfg.localResolvConf, LocalDomains: cfg.localDomains.Args()})
		if err != nil {
			return fatal(err)
		}
		reporters = append(reporters, lr)
		localResolver = lr                     // Hold on to the interface
		localDomains = lr.InBailiwickDomains() // Capture while we access to the struct
		sort.Strings(localDomains)
	}

	// Create TLS configuration for constructing HTTPS transport. This is where we set up
	// verification of server certs and activate http2. Though maybe the latter is no longer
	// needed since regular net/http is meant to be http2 aware now (or soon!)

	client := &http.Client{Timeout: cfg.requestTimeout}
	tlsConfig, err := tlsutil.NewClientTLSConfig(cfg.tlsUseSystemRootCAs, cfg.tlsCAFiles.Args(),
		cfg.tlsClientCertFile, cfg.tlsClientKeyFile)
	if err != nil {
		return fatal(err)
	}

	tr := &http.Transport{TLSClientConfig: tlsConfig, MaxConnsPerHost: cfg.maximumRemoteConnections}
	if err := http2.ConfigureTransport(tr); err != nil { // Use latest http2 support - is this still needed?
		return fatal(err)
	}
	client.Transport = tr

	// Complete doh Config settings and construct the DoH resolver

	cfg.dohConfig.ECSSetCIDR = ecsIPNet
	remoteResolver, err := doh.New(cfg.dohConfig, client)
	if err != nil {
		return fatal(err)
	}
	reporters = append(reporters, remoteResolver)

	if cfg.listenAddresses.NArg() == 0 { // Use wildcard if none supplied
		cfg.listenAddresses.Set("")
	}

	// Start CPU profiling now that most error checking is complete

	if len(cfg.cpuprofile) > 0 {
		f, err := os.Create(cfg.cpuprofile)
		if err != nil {
			return fatal(err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			return fatal(err)
		}
		defer pprof.StopCPUProfile()
	}

	// Memory profile is triggered at the end of the program but we open the output file and
	// hold it open prior to any possible chroot/setuid/setgid action.

	var memProfileFile *os.File
	if len(cfg.memprofile) > 0 {
		memProfileFile, err = os.Create(cfg.memprofile)
		if err != nil {
			return fatal(err)
		}
		defer memProfileFile.Close()
	}

	// Start servers to accept queries and call the inBailiwick resolver.

	if cfg.verbose {
		fmt.Fprintln(stdout,
			consts.ProxyProgramName, consts.Version, "Starting:", cfg.dohConfig.ServerURLs)
		if len(cfg.localResolvConf) > 0 {
			fmt.Fprintln(stdout, "Local Resolution:", cfg.localResolvConf)
			fmt.Fprintln(stdout, "Local Domains:", strings.Join(localDomains, ", "))
		}

	}

	errorChannel := make(chan error, cfg.listenAddresses.NArg()*len(listenTransports))
	wg := &sync.WaitGroup{} // Wait on all servers

	for _, addr := range cfg.listenAddresses.Args() {
		ip := net.ParseIP(addr) // We have to wrap unadorned ipv6 addresses so we can append port
		if ip != nil && ip.To16() != nil {
			addr = "[" + addr + "]" // It's naked, so wrap it
		}

		// If addr is neither v4addr:port, [v6addr]:port or host:port, append the default port
		if !(strings.LastIndex(addr, ":") > strings.LastIndex(addr, "]")) {
			addr = fmt.Sprintf("%s:%s", addr, consts.DNSDefaultPort)
		}

		for _, transport := range listenTransports {
			s := &server{local: localResolver, remote: remoteResolver,
				listenAddress: addr, transport: transport}
			s.start(errorChannel, wg)
			if cfg.verbose {
				fmt.Fprintln(stdout, "Starting", s.Name())
			}

			reporters = append(reporters, s)
			servers = append(servers, s)
		}
	}

	// Constrain the process via setuid/setgid/chroot. This is a no-op call if all parameters
	// are empty strings. Unlike the HTTP side of things we don't have to delay here as the
	// dns.Start only returns once the privileged sockets have been opened.

	err = osutil.Constrain(cfg.setuidName, cfg.setgidName, cfg.chrootDir)
	if err != nil {
		return fatal(err)
	}
	if cfg.verbose {
		fmt.Fprintf(stdout, "Constraints: %s\n", osutil.ConstraintReport())
	}

	// Loop forever giving periodic status reports and checking for a termination event.

	mainStarted = true // Tell testers that we're up and running
	nextStatusIn := nextInterval(time.Now(), cfg.statusInterval)

Running:
	for {
		select {
		case s := <-stopChannel:
			if s == syscall.SIGUSR1 {
				statusReport("User1", false, reporters)
				break
			}
			if cfg.verbose {
				fmt.Fprintln(stdout, "\nSignal", s)
			}
			break Running // All signals bar USR1 cause loop exit

		case err := <-errorChannel:
			return fatal(err) // No cleanup if we got a server startup error

		case <-time.After(nextStatusIn):
			if cfg.verbose {
				statusReport("Status", true, reporters)
			}
			nextStatusIn = nextInterval(time.Now(), cfg.statusInterval)
		}
	}

	for _, s := range servers {
		s.stop()
	}

	mainStopped = true
	wg.Wait() // Wait for all servers to shut down

	if cfg.verbose {
		statusReport("Status", true, reporters) // One last report prior to exiting
		fmt.Fprintln(stdout, consts.ProxyProgramName, consts.Version, "Exiting after", uptime())
	}

	// Memory profile is written at the end of the program

	if memProfileFile != nil {
		runtime.GC() // get up-to-date statistics
		err := pprof.WriteHeapProfile(memProfileFile)
		if err != nil {
			return fatal(err)
		}
	}

	return 0
}

// nextInterval calculates the duration to the modulo interval next time. If now is 00:01:17 and
// interval is 30s then return is 13s which is the duration to the next modulo of 00:01:30.
func nextInterval(now time.Time, interval time.Duration) time.Duration {
	return now.Truncate(interval).Add(interval).Sub(now)
}

// upTime calculates how long this server has been running and returns print-friendly and
// granularity-appropriate representation of that duration.
func uptime() string {
	return time.Now().Sub(startTime).Truncate(time.Second).String()
}

// statusReport prints stats about the server and all known reporters
func statusReport(what string, resetCounters bool, reporters []reporter.Reporter) {
	fmt.Fprintln(stdout, "Status Up:", consts.ProxyProgramName, consts.Version, uptime())
	for _, r := range reporters {
		reps := strings.Split(r.Report(resetCounters), "\n")
		for _, s := range reps {
			if len(s) > 0 {
				fmt.Fprintf(stdout, "%s %s: %s\n", what, r.Name(), s)
			}
		}
	}
}
