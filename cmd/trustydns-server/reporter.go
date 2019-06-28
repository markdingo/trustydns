package main

import (
	"fmt"
	"time"
)

// addSuccessStats bumps the success counter as well as total duration which are used to generate
// reports. All event settings for the request are transferred to counters.
func (t *server) addSuccessStats(latency time.Duration, evs events) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.successCount++
	t.totalLatency += latency
	for ix := 0; ix < len(evs); ix++ {
		if evs[ix] {
			t.eventCounters[ix]++
		}
	}
}

// addFailureStats bumps the failure counter
func (t *server) addFailureStats(ix serFailureIndex, evs events) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.failureCounters[ix]++
	for ix := 0; ix < len(evs); ix++ {
		if evs[ix] {
			t.eventCounters[ix]++
		}
	}
}

func (t *server) Name() string {
	return "Listener"
}

func (t *server) listenName() string {
	s := "("
	if cfg.tlsServerKeyFiles.NArg() > 0 {
		s += "HTTPS on "
	} else {
		s += "HTTP on "
	}
	s += t.listenAddress + ")"

	return s
}

/*

Reporter Output:
                            Error Counters
req=1 ok=0 (0/0/120/120/0/120) al=0.000 errs=1 (0/1/0/0/0/0/0/0/0/0/0/0) Concurrency=1 listenName
    ^    ^  ^ ^ ^   ^   ^ ^       ^          ^  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^              ^
    |    |  | | |   |   | |       |          |  | | | | | | | | | | | |              |
    |    |  | | |   |   | |       |          |  | | | | | | | | | | | |              +--Peak inbound HTTP
    |    |  | | |   |   | |       |          |  | | | | | | | | | | | +--QueryParamMissing
    |    |  | | |   |   | |       |          |  | | | | | | | | | | +--LocalResolutionFailed
    |    |  | | |   |   | |       |          |  | | | | | | | | | +--HTTPWriterFailed
    |    |  | | |   |   | |       |          |  | | | | | | | | +--FailureListSize
    |    |  | | |   |   | |       |          |  | | | | | | | +--ECSSynthesisFailed
    |    |  | | |   |   | |       |          |  | | | | | | +--DNSUnpackRequestFailed
    |    |  | | |   |   | |       |          |  | | | | | +--DNSPackResponseFailed
    |    |  | | |   |   | |       |          |  | | | | +--ClientTLSBad
    |    |  | | |   |   | |       |          |  | | | +--BodyReadError
    |    |  | | |   |   | |       |          |  | | +--BadQueryParamDecode
    |    |  | | |   |   | |       |          |  | +--BadPrefixLengths
    |    |  | | |   |   | |       |          |  +--BadContentType
    |    |  | | |   |   | |       |          +--Total Bad Requests
    |    |  | | |   |   | |       +--Average resolution latency
    |    |  | | |   |   | +--evPadding
    |    |  | | |   |   +--evECSv6Synth
    |    |  | | |   +--evECSv4Synth
    |    |  | | +--evEDNS0Removed
    |    |  | +--evTsig
    |    |  +--evGet
    |    +--Good Requests
    +--Total Requests

*/

func (t *server) Report(resetCounters bool) string {
	if resetCounters {
		t.mu.Lock()
		defer t.mu.Unlock()
	} else {
		t.mu.RLock()
		defer t.mu.RUnlock()
	}

	errs := 0
	for _, v := range t.failureCounters {
		errs += v
	}
	req := t.successCount + errs

	var al float64
	if t.successCount > 0 {
		al = t.totalLatency.Seconds() / float64(t.successCount)
	}
	s := fmt.Sprintf("req=%d ok=%d (%s) al=%0.3f errs=%d (%s) Concurrency=%d %s\n",
		req, t.successCount, formatCounters("%d", "/", t.eventCounters[:]), al,
		errs, formatCounters("%d", "/", t.failureCounters[:]),
		t.ccTrk.Peak(resetCounters), t.listenName())

	if resetCounters {
		t.stats = stats{}
	}

	return s
}

// formatCounters returns a nice %d/%d/%d format for an array of ints. This is less error-prone than
// hard-coding one big ol' Sprintf string but obviously slower. Not relevant in this context.
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
