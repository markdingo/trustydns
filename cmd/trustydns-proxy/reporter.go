package main

import (
	"fmt"
	"time"
)

//////////////////////////////////////////////////////////////////////
// reporter implementation
//////////////////////////////////////////////////////////////////////

// addSuccessStats transfers successful ServerDNS query stats to longer-term server stats.
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

// addFailureStats transfers stats from a failed ServerDNS query to longer-term server stats.
func (t *server) addFailureStats(ix int, evs events) {
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
	return "Server: (on " + t.listenAddress + "/" + t.transport + ")"
}

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

	s := fmt.Sprintf("req=%d ok=%d (%s) al=%0.3f errs=%d (%s) Concurrency=%d",
		req, t.successCount, formatCounters("%d", "/", t.eventCounters[:]), al,
		errs, formatCounters("%d", "/", t.failureCounters[:]),
		t.cct.Peak(resetCounters))

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
