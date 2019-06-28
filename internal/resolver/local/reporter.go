package local

import (
	"fmt"
	"time"
)

// addGeneralSuccess tracks successful resolution attempts that are not server specific. There is a
// maximum of one of these calls per Resolve() call.
func (t *local) addGeneralSuccess() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.success++
}

// addGeneralFailure tracks failed resolution attempts that are not server specific. There is a
// maximum of one of these calls per Resolve() call.
func (t *local) addGeneralFailure(gfx gfxInt) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.failures[gfx]++
}

// addServerSuccess tracks successful responses from servers. That simply means the server is
// responding and is suited for other queries. It does not mean a particular query is
// successful. There can be multiple of these call per Resolve() call.
func (t *local) addServerSuccess(bsix int, tcpFallback, tcpSuperior bool, latency time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.totalLatency += latency
	bs := t.bsList[bsix]
	bs.success++
	if tcpFallback {
		bs.events[evxTCPFallback]++
	}
	if tcpSuperior {
		bs.events[evxTCPSuperior]++
	}
	bs.latency += latency
}

// addServerFailure tracks failed resolution attempts that are server-specific. There can be
// multiple of these calls per Resolve() call since it can iterate after certain server-specific
// errors.
func (t *local) addServerFailure(bsix int, tcpFallback, tcpSuperior bool, sfx sfxInt) {
	t.mu.Lock()
	defer t.mu.Unlock()

	bs := t.bsList[bsix]
	bs.failures[sfx]++
	if tcpFallback {
		bs.events[evxTCPFallback]++
	}
	if tcpSuperior {
		bs.events[evxTCPSuperior]++
	}
}

func (t *local) Name() string {
	return "Local Resolver"
}

/*
Report returns a multi-line string showing stats suitable for printing to a log file. Zero counters
if resetCounters is true.

Totals: req=1273 ok=1273 errs=0 (0/0)
        ^        ^       ^       ^ ^
        |        |       |       | |
        |        |       |       | +--Retry count exceeded
        |        |       |       +--Timeout limit exceeded
        |        |       +--Total bad requests
        |        +--Total good requests
        +--Total requests

Server: req=1273 ok=1273 al=0.003 errs=0 (0/0/0/0/0/0) (ev 0/0) 127.0.0.1:53
        ^        ^       ^        ^       ^ ^ ^ ^ ^ ^   ^  ^ ^  ^
        |        |       |        |       | | | | | |   |  | |  |
        |        |       |        |       | | | | | |   |  | |  +--Server
        |        |       |        |       | | | | | |   |  | +--RFFU
        |        |       |        |       | | | | | |   |  +--TCP fallback
        |        |       |        |       | | | | | |   +--Event counters
        |        |       |        |       | | | | | +--Other rcodes
        |        |       |        |       | | | | +--Not implemented (Rcode)
        |        |       |        |       | | | +--Refused (Rcode)
        |        |       |        |       | | +--Server fail (Rcode)
        |        |       |        |       | +--Format error (Rcode)
        |        |       |        |       +--Exchange error
        |        |       |        +--Total bad requests
        |        |       +--Average latency
        |        +--Good requests
        +---Total requests
*/
func (t *local) Report(resetCounters bool) string {
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
	errs := 0
	for _, v := range t.failures {
		errs += v
	}
	for _, bs := range t.bsList {
		bsErrs := 0
		for _, v := range bs.failures {
			bsErrs += v
		}
		var al float64
		if bs.success > 0 {
			al = bs.latency.Seconds() / float64(bs.success)
		}
		bestReport += fmt.Sprintf("Server: req=%d ok=%d al=%0.3f errs=%d (%s) (ev %s) %s\n",
			bs.success+bsErrs, bs.success, al, bsErrs, formatCounters("%d", "/", bs.failures[:]),
			formatCounters("%d", "/", bs.events[:]), bs.name)
		if resetCounters {
			bs.resetCounters()
		}
	}

	mainReport := fmt.Sprintf("Totals: req=%d ok=%d errs=%d (%s)\n",
		t.success+errs, t.success, errs, formatCounters("%d", "/", t.failures[:]))

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
