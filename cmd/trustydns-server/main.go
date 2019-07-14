// Listen for inbound DNS Over HTTPS queries and resolve with the local resolver
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/markdingo/trustydns/internal/constants"
	"github.com/markdingo/trustydns/internal/osutil"
	"github.com/markdingo/trustydns/internal/reporter"
	"github.com/markdingo/trustydns/internal/resolver/local"
	"github.com/markdingo/trustydns/internal/tlsutil"
)

// Program-wide variables
var (
	consts               = constants.Get()
	cfg                  *config
	defaultListenAddress = ":" + consts.HTTPSDefaultPort

	stdout io.Writer // All I/O goes via these writers
	stderr io.Writer

	startTime   = time.Now()
	stopChannel chan os.Signal
	flagSet     *flag.FlagSet
)

//////////////////////////////////////////////////////////////////////

func fatal(args ...interface{}) int {
	fmt.Fprint(stderr, "Fatal: ", consts.ServerProgramName, ": ")
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
	stdout = out
	stderr = err
	mainState(initial)
	stopChannel = make(chan os.Signal, 4) // All reasonable signals cause us to quit or stats report
	osutil.SignalNotify(stopChannel)
}

func main() {
	mainInit(os.Stdout, os.Stderr)
	os.Exit(mainExecute(os.Args))
}

func mainExecute(args []string) int {
	defer mainState(stopped) // Tell testers we've stopped even on error returns
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
		fmt.Fprintln(stdout, consts.ServerProgramName, "Version:", consts.Version)
		return 0
	}

	if flagSet.NArg() > 0 {
		return fatal("Unexpected parameters on the command line", strings.Join(flagSet.Args(), " "))
	}

	if cfg.logAll {
		cfg.logClientIn = true
		cfg.logClientOut = true
		cfg.logHTTPOut = true
		cfg.logHTTPIn = true
		cfg.logLocalOut = true
		cfg.logLocalIn = true
		cfg.logTLSErrors = true
	}

	// Validate ECS settings

	// We need to know if either of the prefixlen values have been set and thus we should set
	// --ecs-set if it's not already set. We can't just look at the value as that could easily
	// be the default which is only meaningful if ecs-set is exlicitly set.

	flagSet.Visit(func(f *flag.Flag) {
		if f.Name == "ecs-set-ipv4-prefixlen" || f.Name == "ecs-set-ipv6-prefixlen" {
			cfg.ecsSet = true
		}
	})

	if cfg.ecsSet {
		if cfg.ecsSetIPv4PrefixLen < 0 || cfg.ecsSetIPv4PrefixLen > 32 {
			return fatal("--ecs-set-ipv4-prefixlen", cfg.ecsSetIPv4PrefixLen,
				"must be between 0 and 32")
		}
		if cfg.ecsSetIPv6PrefixLen < 0 || cfg.ecsSetIPv6PrefixLen > 128 {
			return fatal("--ecs-set-ipv6-prefixlen", cfg.ecsSetIPv6PrefixLen,
				"must be between 0 and 128")
		}
	}

	var reporters []reporter.Reporter // Track of all reportables for periodic reporting
	var servers []*server             // Track of all servers so we can shut then down

	// Validate local resolver configuration

	if len(cfg.resolvConf) == 0 {
		return fatal("Must supplied a resolv.conf file with -c")
	}
	resolver, err := local.New(local.Config{ResolvConfPath: cfg.resolvConf})
	if err != nil {
		return fatal(err)
	}
	reporters = append(reporters, resolver)

	// Create a TLS configuration for constructing HTTPS transport. This is where we load in our
	// cert/key files and possibly enable verification of client certs.

	tlsConfig, err := tlsutil.NewServerTLSConfig(cfg.tlsUseSystemRootCAs, cfg.tlsCAFiles.Args(),
		cfg.tlsServerCertFiles.Args(), cfg.tlsServerKeyFiles.Args())
	if err != nil {
		return fatal(err)
	}

	if cfg.listenAddresses.NArg() == 0 { // Use wildcard if none supplied
		cfg.listenAddresses.Set(defaultListenAddress)
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

	// Start a server for each listen address

	if cfg.verbose {
		fmt.Fprintln(stdout, consts.ServerProgramName, consts.Version, "Starting")
		for cn := range tlsConfig.NameToCertificate { // Print CNs associated with certs loaded
			fmt.Fprintln(stdout, "Accepting TLS CN:", cn)
		}
		fmt.Fprintln(stdout, "Local resolution:", cfg.resolvConf)
	}

	errorChannel := make(chan error, cfg.listenAddresses.NArg())
	wg := &sync.WaitGroup{} // Wait on all servers

	for _, addr := range cfg.listenAddresses.Args() {
		ip := net.ParseIP(addr) // We have to wrap unadorned ipv6 addresses so we can append port
		if ip != nil && ip.To16() != nil {
			addr = "[" + addr + "]" // It's naked, so wrap it
		}

		// If addr is neither v4addr:port, [v6addr]:port or host:port, append the default port
		if !(strings.LastIndex(addr, ":") > strings.LastIndex(addr, "]")) {
			addr += ":" + consts.HTTPSDefaultPort
		}

		s := &server{stdout: stdout, local: resolver, listenAddress: addr}
		s.start(tlsConfig, errorChannel, wg)
		if cfg.verbose {
			fmt.Fprintln(stdout, "Listening:", s.listenName())
		}
		reporters = append(reporters, s)
		reporters = append(reporters, s.connTrk)
		servers = append(servers, s)
	}

	// Constrain the process via setuid/setgid/chroot. This is a no-op call if all parameters
	// are empty strings.
	//
	// The bizarrity is that we have no way of knowing for sure when the servers that we just
	// started actually get around to opening their sockets and thus no longer require the
	// privileges we started with. The problem is that if we win the resource race and constrain
	// the process too soon then the servers fail. This would all be moot if the servers gave us
	// an easy way of knowing when they have opened their sockets, but they don't. Our only
	// recourse is to wait an absurdly large amount of time after starting to be confident that
	// all servers have started.
	//
	// This waiting period is a risk as an attacker who is watching for restart can attack in
	// the first few seconds prior to out constraint call, but what else can we do?
	//
	// Rather than stall the main go-routine which needs to select for errors and signals and so
	// on, we delegate the Constrain call to a go-routine.
	//
	// Note that this is not a problem with DNS listening as miekg/dns.Server offers a notify
	// function which is called once the socket has been opened.

	go func(setuidName, setgidName, chrootDir string, verbose bool, stdout io.Writer) {
		time.Sleep(3 * time.Second) // Hopefully absurdly large but also not too huge a security window
		err := osutil.Constrain(setuidName, setgidName, chrootDir)
		if err != nil {
			errorChannel <- err // Force main go-routine to exit
			return
		}
		if verbose {
			fmt.Fprintf(stdout, "Constraints: %s\n", osutil.ConstraintReport())
		}
	}(cfg.setuidName, cfg.setgidName, cfg.chrootDir, cfg.verbose, stdout)

	// Loop forever giving periodic status reports and checking for a termination event.

	mainState(started) // Tell testers we're up and running
	nextStatusIn := nextInterval(time.Now(), cfg.statusInterval)

Running:
	for {
		select {
		case s := <-stopChannel:
			if osutil.IsSignalUSR1(s) {
				statusReport("User1", false, reporters)
				break
			}
			if cfg.verbose {
				fmt.Fprintln(stdout, "\nSignal", s)
			}
			break Running // All signals bar USR1 cause loop exit

		case err := <-errorChannel:
			return fatal(err) // No cleanup if we get a server startup error

		case <-time.After(nextStatusIn):
			if cfg.verbose {
				statusReport("Status", true, reporters)
			}
			nextStatusIn = nextInterval(time.Now(), cfg.statusInterval)
		}
	}

	// Shutting down

	for _, s := range servers {
		s.stop()
	}
	mainState(stopped) // Tell testers we've stopped accepting requests
	wg.Wait()          // Wait for all servers to completely shut down

	if cfg.verbose {
		statusReport("Status", true, reporters) // One last report prior to exiting
		fmt.Fprintln(stdout, consts.ServerProgramName, consts.Version, "Exiting after", uptime())
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

// nextInterval calculates the duration to now+modulo interval. If now is 00:01:17 and the interval
// is 15m then the returned duration is 13m43s which is the distance to the 00:15:00. The idea is to
// provide a wait/sleep value which gets the caller to the next interval tick-over.
func nextInterval(now time.Time, interval time.Duration) time.Duration {
	return now.Truncate(interval).Add(interval).Sub(now)
}

// upTime calculates how long this server has been running and returns log-friendly and
// granularity-appropriate representation of that duration.
func uptime() string {
	return time.Now().Sub(startTime).Truncate(time.Second).String()
}

// statusReport prints stats about the server and all known reporters
func statusReport(what string, resetCounters bool, reporters []reporter.Reporter) {
	fmt.Fprintln(stdout, "Status Up:", consts.ServerProgramName, consts.Version, uptime())
	for _, r := range reporters {
		reps := strings.Split(r.Report(resetCounters), "\n")
		for _, s := range reps {
			if len(s) > 0 {
				fmt.Fprintf(stdout, "%s %s: %s\n", what, r.Name(), s)
			}
		}
	}
}
