package local

import (
	"strings"
	"testing"
	"time"
)

const (
	zero1 = `Totals: req=0 ok=0 errs=0 (0/0)
Server: req=0 ok=0 al=0.000 errs=0 (0/0/0/0/0/0) (ev 0/0) 127.0.0.127:53
Server: req=0 ok=0 al=0.000 errs=0 (0/0/0/0/0/0) (ev 0/0) [::127]:53`

	all1 = `Totals: req=5 ok=2 errs=3 (1/2)
Server: req=8 ok=2 al=1.500 errs=6 (1/1/1/1/1/1) (ev 2/2) 127.0.0.127:53
Server: req=1 ok=0 al=0.000 errs=1 (0/0/1/0/0/0) (ev 1/0) [::127]:53`
)

func TestReporter(t *testing.T) {
	res, _ := New(Config{ResolvConfPath: "testdata/two.resolv.conf"})
	nm := res.Name()
	if !strings.Contains(nm, "Resolver") {
		t.Error("Name() does not contain the word 'Resolver'", nm)
	}

	st := res.Report(false)
	if !strings.Contains(st, zero1) {
		t.Error("Report() not returning Zeroes. Want:\n", zero1, "\ngot\n", st)
	}

	res.addServerSuccess(0, true, false, time.Second) // Report successful server responses
	res.addGeneralSuccess()
	res.addServerSuccess(0, false, true, time.Second*2) // (1+2)/2 - 1.5s latency
	res.addGeneralSuccess()

	res.addServerFailure(0, true, false, sfxExchangeError) // Report all possible errors to force
	res.addServerFailure(0, false, true, sfxFormatError)   // every counter to tick over from zero
	res.addServerFailure(0, false, false, sfxServerFail)
	res.addServerFailure(0, false, false, sfxRefused)
	res.addServerFailure(0, false, false, sfxNotImplemented)
	res.addServerFailure(0, false, false, sfxOther)

	res.addServerFailure(1, true, false, sfxServerFail)

	res.addGeneralFailure(gfxTimeout) // Report all possible general failures
	res.addGeneralFailure(gfxMaxAttempts)
	res.addGeneralFailure(gfxMaxAttempts)
	st = res.Report(true)
	if !strings.Contains(st, all1) {
		t.Error("Report() not returning all counters. Want:\n", all1, "\ngot\n", st)
	}

	// Test that the reset flag works

	st = res.Report(false) // Previous Report() reset counters so now we should be back to the zero
	if !strings.Contains(st, zero1) {
		t.Error("reporter Report(true) did not appear to reset counters. Got:", st)
	}
}
