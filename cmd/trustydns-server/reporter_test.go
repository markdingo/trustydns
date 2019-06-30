package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

const expect1 = "req=14 ok=2 (0/0/0/0/0/0) al=0.750 errs=12 (1/1/1/1/1/1/1/1/1/1/1/1) Concurrency=0"

func TestReporter(t *testing.T) {
	mainInit(os.Stdout, os.Stderr) // Make sure cfg is initialized
	s := &server{stdout: stdout, listenAddress: "127.0.0.1"}
	name := s.Name()
	if !strings.Contains(name, "Listener") {
		t.Error("Name does not contain 'Listener'", name)
	}
	rep1 := s.Report(false)
	if !strings.Contains(rep1, "127.0.0.1") {
		t.Error("Report does not contain IP address 127.0.0.1", rep1)
	}

	var evs events
	s.addSuccessStats(time.Second, evs)
	rep2 := s.Report(true)
	if rep2 == rep1 {
		t.Error("Report should changed with counter updates", rep1, rep2)
	}
	rep2 = s.Report(false)
	if rep2 != rep1 {
		t.Error("Reset Counters report should equal initial report", rep1, rep2)
	}
	s.addSuccessStats(time.Second, evs)
	s.addSuccessStats(time.Millisecond*500, evs) // ok=2, al=1.5/2 = 0.750
	s.addFailureStats(serBadContentType, evs)
	s.addFailureStats(serBadMethod, evs)
	s.addFailureStats(serBadPrefixLengths, evs)
	s.addFailureStats(serBadQueryParamDecode, evs)
	s.addFailureStats(serBodyReadError, evs)
	s.addFailureStats(serClientTLSBad, evs)
	s.addFailureStats(serDNSPackResponseFailed, evs)
	s.addFailureStats(serDNSUnpackRequestFailed, evs)
	s.addFailureStats(serECSSynthesisFailed, evs)
	s.addFailureStats(serHTTPWriterFailed, evs)
	s.addFailureStats(serLocalResolutionFailed, evs)
	s.addFailureStats(serQueryParamMissing, evs) // errs=12

	rep1 = s.Report(false)
	rep2 = s.Report(false)

	if rep1 != rep2 {
		t.Error("Report should not have reset", rep1, rep2)
	}
	if !strings.Contains(rep1, expect1) {
		t.Error("Report should not have changed. Expected:", expect1, "Got:", rep1)
	}
}
