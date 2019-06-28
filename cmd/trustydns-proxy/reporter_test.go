package main

import (
	"strings"
	"testing"
	"time"
)

const (
	expect1 = "req=5 ok=2 (0/0) al=0.450 errs=3 (1/2) Concurrency=0"
	expect2 = "req=5 ok=2 (1/1) al=0.450 errs=3 (1/2) Concurrency=0"
)

func TestReporter(t *testing.T) {
	var evs events
	s := &server{listenAddress: "127.0.0.1", transport: "udp"}
	name := s.Name()
	if !strings.Contains(name, "127.0.0.1/udp") {
		t.Error("Name does not contain IP address", name)
	}

	rep1 := s.Report(false)
	s.addSuccessStats(time.Millisecond*300, evs)
	rep2 := s.Report(true)
	if rep2 == rep1 {
		t.Error("Report should changed with counter updates", rep1, rep2)
	}
	rep2 = s.Report(false)
	if rep2 != rep1 {
		t.Error("Reset Counters report should equal initial report", rep1, rep2)
	}

	s.addSuccessStats(time.Millisecond*400, evs)
	s.addSuccessStats(time.Millisecond*500, evs) // (400+500) / 2 = 0.450ms average latency
	s.addFailureStats(serNoResponse, evs)
	s.addFailureStats(serDNSWriteFailed, evs)
	evs[evInTruncated] = true
	evs[evOutTruncated] = true
	s.addFailureStats(serDNSWriteFailed, evs)
	rep1 = s.Report(false)
	rep2 = s.Report(false)

	if rep1 != rep2 {
		t.Error("Report should not have reset", rep1, rep2)
	}
	if rep1 != expect2 {
		t.Error("Report should not have changed. Expected:", expect2, "Got:", rep1)
	}
}
