package doh

import (
	"strings"
	"testing"
	"time"
)

const (
	expect0 = `Totals: req=0 ok=0 errs=0 (0/0)
Server: ok=0 tl=0.000 rl=0.000 errs=0 (0/0/0/0/0/0) (ecs 0/0/0/0) http://localhost
`
	expect1 = `Totals: req=17 ok=5 errs=12 (1/0)
Server: ok=5 tl=0.380 rl=0.280 errs=11 (2/3/1/1/3/1) (ecs 1/2/3/4) http://localhost
`
)

func TestReporter(t *testing.T) {
	res, _ := New(Config{ServerURLs: []string{"http://localhost"}}, nil)
	nm := res.Name()
	if !strings.Contains(nm, "Resolver") {
		t.Error("reporter Name() does not contain the word 'Resolver'", nm)
	}

	st := res.Report(false)
	if st != expect0 {
		t.Error("Expected:", expect0, "Got:", st)
	}

	res.addSuccessStats(0, time.Millisecond*200, time.Millisecond*100, false, false, false, false)
	res.addSuccessStats(0, time.Millisecond*300, time.Millisecond*200, false, false, false, true)
	res.addSuccessStats(0, time.Millisecond*400, time.Millisecond*300, false, false, true, true)
	res.addSuccessStats(0, time.Millisecond*500, time.Millisecond*400, false, true, true, true)
	res.addSuccessStats(0, time.Millisecond*500, time.Millisecond*400, true, true, true, true)
	// 200+300+400+500+500 / 5 = 380 = Total Latency
	// 100+200+300+400+400 / 5 = 280 = Remote Latency (if reported by remote end)
	res.addGeneralFailure(dgxPackDNSQuery) // A whole bunch of distinquishible error counts
	res.addServerFailure(0, dexCreateHTTPRequest)
	res.addServerFailure(0, dexCreateHTTPRequest)
	res.addServerFailure(0, dexDoRequest)
	res.addServerFailure(0, dexDoRequest)
	res.addServerFailure(0, dexDoRequest)
	res.addServerFailure(0, dexNonStatusOk)
	res.addServerFailure(0, dexResponseReadAll)
	res.addServerFailure(0, dexContentType)
	res.addServerFailure(0, dexContentType)
	res.addServerFailure(0, dexContentType)
	res.addServerFailure(0, dexUnpackDNSResponse)
	st = res.Report(true)
	if st != expect1 {
		t.Error("Expected:", expect1, "Got:", st)
	}

	// Test that the previous resetCounters=true works
	st = res.Report(false)
	if st != expect0 {
		t.Error("resetCounters did not reset. Expected:", expect0, "Got:", st)
	}

}
