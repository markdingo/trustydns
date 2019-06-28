package doh

import (
	"fmt"
	"time"
)

// addSuccessStats tracks successful resolutions.
func (t *remote) addSuccessStats(bsIX int, total, server time.Duration, ecsRemoved, ecsSet, ecsRequest, ecsReturned bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	bs := t.bsList[bsIX]

	bs.success++
	bs.totalLatency += total
	bs.serverLatency += server

	if ecsRemoved {
		bs.ecsRemoved++
	}
	if ecsSet {
		bs.ecsSet++
	}
	if ecsRequest {
		bs.ecsRequest++
	}
	if ecsReturned {
		bs.ecsReturned++
	}
}

// addGeneralFailure tracks failed resolution attempts that are not server specific.
func (t *remote) addGeneralFailure(dgx dgxInt) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.failures[dgx]++
}

// addServerFailure tracks failed resolution attempts that can be related to a specific server.
func (t *remote) addServerFailure(bsIX int, dex dexInt) {
	t.mu.Lock()
	defer t.mu.Unlock()

	bs := t.bsList[bsIX]

	bs.failures[dex]++
}

func (t *remote) Name() string {
	return "DoH Resolver"
}

/*

Report returns a multi-line string showing stats suitable for printing to a log file. Reset counters
if resetCounters is true.

Output:

Totals: req=305 ok=301 errs=2 (4/0)
        ^       ^      ^       ^ ^
        |       |      |       | |
        |       |      |       | +--RFFU Error
        |       |      |       +--DNSPackError
        |       |      +--Total Error Requests
        |       +--Total Good requests
        +---Total Requests

Server: ok=301 tl=0.254 rl=0.235 errs=5 (0/0/4/0/0/1) (ecs 0/0/305/64) URL
        ^      ^        ^        ^       ^ ^ ^ ^ ^ ^  ^    ^ ^ ^   ^   ^
        |      |        |        |       | | | | | |  |    | | |   |   |
        |      |        |        |       | | | | | |  |    | | |   |   +-- Server URL
        |      |        |        |       | | | | | |  |    | | |   +--ecsReturned
        |      |        |        |       | | | | | |  |    | | +--ecsRequest
        |      |        |        |       | | | | | |  |    | +--ecsSet
        |      |        |        |       | | | | | |  |    +--ecsRemoved
        |      |        |        |       | | | | | |  +--EDNS Client Subnet stats
        |      |        |        |       | | | | | +--UnpackDNSResponse
        |      |        |        |       | | | | +--ContentType
        |      |        |        |       | | | +--ResponseReadAll
        |      |        |        |       | | +--NonStatusOk
        |      |        |        |       | +--DoRequest
        |      |        |        |       +--CreateHTTPRequest
        |      |        |        +--Per-Server Errors
        |      |        +--Remote server Latency
        |      +--Total query Latency
        +--Good Requests

*/
func (t *remote) Report(resetCounters bool) string {
	if resetCounters {
		t.mu.Lock()
		defer t.mu.Unlock()
	} else {
		t.mu.RLock()
		defer t.mu.RUnlock()
	}

	// Create the best server reports first as that lets us calculate the summary stats for the
	// main report as we pass thru the individual server stats.

	bestReport := ""
	ok := 0
	errs := 0
	for _, bs := range t.bsList {
		bsErrs := 0
		ok += bs.success
		for _, v := range bs.failures {
			bsErrs += v
		}
		errs += bsErrs
		var tl, rl float64
		if bs.success > 0 {
			tl = bs.totalLatency.Seconds() / float64(bs.success)
			rl = bs.serverLatency.Seconds() / float64(bs.success)
		}
		bestReport += fmt.Sprintf("Server: ok=%d tl=%0.3f rl=%0.3f errs=%d (%s) (ecs %d/%d/%d/%d) %s\n",
			bs.success, tl, rl, bsErrs, formatCounters("%d", "/", bs.failures[:]),
			bs.ecsRemoved, bs.ecsSet, bs.ecsRequest, bs.ecsReturned, bs.name)
		if resetCounters {
			bs.resetCounters()
		}
	}
	for _, v := range t.failures {
		errs += v
	}
	mainReport := fmt.Sprintf("Totals: req=%d ok=%d errs=%d (%s)\n",
		ok+errs, ok, errs,
		formatCounters("%d", "/", t.failures[:]))

	if resetCounters {
		t.resetCounters()
	}

	return mainReport + bestReport
}

// formatCounters returns a nice %d/%d/%d format from an array of ints. This is less error-prone
// than hard-coding one big ol' Sprintf string but obviously slower which is irrelevant here.
func formatCounters(vfmt string, delim string, vals []int) string {
	res := ""
	for ix, v := range vals {
		if ix > 0 {
			res += delim
		}
		res += fmt.Sprintf(vfmt, v)
	}

	return res
}
