package bestserver

import (
	"strings"
	"testing"
	"time"
)

var (
	first  = &defaultServer{name: "a"}
	second = &defaultServer{name: "b"}
	third  = &defaultServer{name: "c"}
	fourth = &defaultServer{name: "d"}
)

// newTestLatency returns the actual latency struct rather than Manager so tests can peak inside to
// see how some of the tests affect internal data.
func newTestLatency(config LatencyConfig, servers []Server) (*latency, error) {
	t, err := NewLatency(config, servers)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func TestLatencyNew(t *testing.T) {
	lConfig := LatencyConfig{ReassessCount: 5, ResetFailedAfter: time.Second * 5}
	servers := []Server{first, second, third}

	bs, err := NewLatency(lConfig, servers)
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}
	s, _ := bs.Best()
	if s == nil {
		t.Error("Expected a Server to be returned, not nil")
	}

	bs, err = NewLatency(LatencyConfig{}, []Server{})
	if bs != nil {
		t.Error("Did not expect a good construction with zero servers")
	}
	if err == nil {
		t.Error("Expected an error with zero servers")
	}
	if err != nil && !strings.Contains(err.Error(), "No server") {
		t.Error("Expected 'no servers' error, not", err.Error())
	}
}

func TestLatencyReport(t *testing.T) {
	servers := []Server{first, second, third}
	bs, err := NewLatency(LatencyConfig{}, servers)
	if err != nil {
		t.Fatal("Did not expect an error constructing test", err.Error())
	}
	for ix, s := range servers {
		if !bs.Result(s, false, time.Now(), 0) {
			t.Error("Result() does not recognize server #", ix)
		}
	}
	if bs.Result(fourth, false, time.Now(), 0) {
		t.Error("Result() recognizes invalid fourth server")
	}
}

var (
	tt = []struct { // All these construction test cases are meant to fail
		lc        LatencyConfig
		servers   []string
		errorText string
	}{
		{LatencyConfig{ReassessCount: -1}, []string{"a"}, "ReassessCount"},
		{LatencyConfig{ReassessAfter: -1}, []string{"a"}, "ReassessAfter"},
		{LatencyConfig{WeightForLatest: -1}, []string{"a"}, "WeightForLatest"},
		{LatencyConfig{ResetFailedAfter: -1}, []string{"a"}, "ResetFailedAfter"},
		{LatencyConfig{SampleOthersEvery: -1}, []string{"a"}, "SampleOthersEvery"},
	}
)

func TestLatencyNewFailures(t *testing.T) {
	for tx, tc := range tt {
		servers := ServersFromNames(tc.servers)
		bs, err := NewLatency(tc.lc, servers)
		if bs != nil {
			t.Error(tx, "Constructed a new bestserver when error expected", bs)
		}
		if err == nil {
			t.Error(tx, "Expected error return from New")
			continue
		}
		if !strings.Contains(err.Error(), tc.errorText) {
			t.Error(tx, "Expected text '"+tc.errorText+"' in error:", err)
		}
	}
}

// Test that all over-rides don't get replaced with defaults
func TestLatencyNewOverrides(t *testing.T) {
	bs, err := newTestLatency(LatencyConfig{
		ReassessCount:    4,
		ReassessAfter:    time.Second * 2,
		WeightForLatest:  3,
		ResetFailedAfter: time.Second * 5,
	}, []Server{&defaultServer{name: "a"}})
	if err != nil {
		t.Error("Unexpected error return from New test setup", err)
	}
	if bs.ReassessCount != 4 {
		t.Error("Config override of ReassessCount was discarded", bs.LatencyConfig)
	}
	if bs.ReassessAfter != time.Second*2 {
		t.Error("Config override of ReassessAfter was discarded", bs.LatencyConfig)
	}
	if bs.WeightForLatest != 3 {
		t.Error("Config override of WeightForLatest was discarded", bs.LatencyConfig)
	}
	if bs.ResetFailedAfter != time.Second*5 {
		t.Error("Config override of ResetFailedAfter was discarded", bs.LatencyConfig)
	}
}

// This that first cab is chosen when there is only one server
func TestLatencyShortList(t *testing.T) {
	bs, err := newTestLatency(LatencyConfig{}, []Server{first})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}

	for ix := 0; ix < DefaultLatencyConfig.ReassessCount+2; ix++ {
		best, _ := bs.Best()
		if !bs.Result(best, true, time.Now(), 0) {
			t.Error("List of one caused internal failure")
		}
	}
	if bs.reassessRationale != algOnlyOne {
		t.Error("Expected algOnlyOne, not", bs.reassessRationale)
	}

	bs, err = newTestLatency(LatencyConfig{}, []Server{first, second})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}

	for ix := 0; ix < DefaultLatencyConfig.ReassessCount+2; ix++ {
		best, _ := bs.Best()
		if !bs.Result(best, true, time.Now(), 0) {
			t.Error("List of one caused internal failure")
		}
	}
	if bs.reassessRationale != algFirstCab {
		t.Error("Expected algFirstCab, not", bs.reassessRationale)
	}
}

// Test that all servers get offered as Best() over time so that they can be sampled. At 5% of
// the time spread across the non-prefferred servers that should mean that for 100 samples
// with a four servers, ech server should get at least one chance.
func TestLatencySampling(t *testing.T) {
	bs, err := NewLatency(LatencyConfig{}, []Server{first, second, third, fourth})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}

	var now time.Time
	sMap := make(map[Server]int)
	sMap[first] = 0
	sMap[second] = 0
	sMap[third] = 0
	sMap[fourth] = 0

	for ix := 0; ix <= 100; ix++ { // 5% = 5*4 samples /4 = 5 samples per server
		s, _ := bs.Best()
		sMap[s]++
		bs.Result(s, true, now, time.Millisecond)
	}

	for k, v := range sMap {
		if v < 1 {
			t.Error("Server", k, "should have been offered as a sample at least once")
		}
	}
}

// Test that reassessment occurs after ReassessCount
func TestLatencyReassessCount(t *testing.T) {
	bs, err := newTestLatency(LatencyConfig{ReassessCount: 5}, []Server{first, second, third})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}

	var now time.Time
	gotZero := false
	for ix := 0; ix < 6; ix++ {
		best, _ := bs.Best()
		bs.Result(best, true, now, time.Millisecond)
		if bs.assessCount == 0 {
			gotZero = true
		}
	}
	if !gotZero {
		t.Error("Result() did not trigger a reassess over ReassessCount Results")
	}
}

// Test that reassessment occurs after ReassessAfter
func TestLatencyReassessAfter(t *testing.T) {
	bs, err := newTestLatency(LatencyConfig{ReassessAfter: time.Second}, []Server{first, second, third})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}

	var now time.Time
	gotZero := false
	for ix := 0; ix < 6; ix++ {
		now = now.Add(time.Second)
		best, _ := bs.Best()
		bs.Result(best, true, now, time.Millisecond)
		if bs.assessCount == 0 {
			gotZero = true
		}
	}
	if !gotZero {
		t.Error("Result() did not trigger a reassess over ReassessAfter time")
	}
}

func TestLatencyFailure(t *testing.T) {
	bs, err := NewLatency(LatencyConfig{}, []Server{first, second, third})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}
	s, _ := bs.Best()
	now := time.Unix(1, 0)
	bs.Result(s, false, now, 0) // Report first as failure
	s, _ = bs.Best()
	if s != second {
		t.Error("Failure report should have trigger new best", s)
	}
	bs.Result(s, false, now, 0) // Report second as failure
	s, _ = bs.Best()
	if s != third {
		t.Error("Failure report should have trigger new best", s)
	}
	bs.Result(s, false, now, 0) // Report third as failure. Should just go to best+1 = first
	s, _ = bs.Best()
	if s != first {
		t.Error("Failure report should have trigger new best", s)
	}

	// They have all failed now so best server is just going to
	// cycle thru failed servers one by one forever until one gets
	// a good status return.

	for ix := 0; ix < 20; ix++ {
		bs.Result(s, false, now, 0) // Report third as failure. Should just go to best+1 = first
		s1, _ := bs.Best()
		if s1 == s { // Did it change?
			t.Error("All failures should cycle thru each time, not", s)
			break
		}
		s = s1
	}
}

// Test that the first server starts out as the best
func TestLatencyFirstGood(t *testing.T) {
	bs, err := NewLatency(LatencyConfig{}, []Server{first, second, third, fourth})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}

	best, _ := bs.Best()
	bs.Result(best, false, time.Now(), 0) // First starts out as best
	s, _ := bs.Best()
	if s != second {
		t.Error("Expected second to be next cab off the rank, but", s)
	}
}

// Test that the server with the lowest latency wins
func TestLatencyFastest(t *testing.T) {
	bs, err := NewLatency(LatencyConfig{}, []Server{first, second, third, fourth})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}
	now := time.Unix(1, 0)
	bs.Result(first, true, now, time.Millisecond*20)
	bs.Result(second, true, now, time.Millisecond*90)
	bs.Result(third, true, now, time.Millisecond*70)
	bs.Result(fourth, true, now, time.Millisecond*80)
	bs.Result(first, false, now, time.Millisecond*20) // Removing first as 'best' should force reassess
	s, _ := bs.Best()
	if s != third {
		t.Error("Expected best to be fastest (third) but got", s)
	}
}

// Test that the weighted average is in fact a weighted average
func TestLatencyweightedAverage(t *testing.T) {
	bs, err := newTestLatency(LatencyConfig{}, []Server{first, second, third, fourth})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}

	now := time.Unix(1, 0)
	for ix := 50; ix < 100; ix++ {
		bs.Result(second, true, now, time.Duration(ix)) // Report increasing latency
	}

	stats := bs.serverStats(second)
	if stats.weightedAverage <= 50 || stats.weightedAverage >= 100 { // Should  be a little under 100
		t.Error("Expected weighted average to be between 50 and 100, not", stats.weightedAverage)
	}
}

// Test that the returned stats match what's happening via the official interfaces
func TestLatencyStats(t *testing.T) {
	bs, err := newTestLatency(LatencyConfig{}, []Server{first, second, third})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}
	stats := bs.serverStats(nil) // Should not panic, should return all zeroes
	if !stats.lastStatusTime.IsZero() || stats.lastStatusWasFailure || stats.weightedAverage > 0 {
		t.Error("Expected all zeros from bogus Status()", stats)
	}

	bs.Result(first, true, time.Now(), time.Second)
	stats = bs.serverStats(first)
	if stats.lastStatusTime.IsZero() || stats.lastStatusWasFailure || stats.weightedAverage == 0 {
		t.Error("Expected time, success and avg from Status(first)", stats)
	}
}

func TestLatencyServers(t *testing.T) {
	bs, err := NewLatency(LatencyConfig{}, []Server{first, second, third})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}

	servers := bs.Servers()
	if len(servers) != 3 {
		t.Fatal("Expected three servers to be returned, not", servers)
	}
	if servers[0] != first || servers[1] != second || servers[2] != third { // Order is not guaranteed, but it is for now
		t.Error("Server names not as expected", servers)
	}
}

func TestLatencyInterface(t *testing.T) {
	bs, err := NewLatency(LatencyConfig{}, []Server{first, second, third})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}

	var iface Manager
	iface = bs
	_ = iface
}

// serverStats is a helper routine which takes a copy of the current statistics for a given server.
func (t *latency) serverStats(server Server) (stats latencyServerStats) {
	t.lock()
	defer t.unlock()

	ix, ok := t.serverToIndex[server]
	if !ok { // Caller screwed up so do nothing
		return
	}

	stats = t.stats[ix] // Take copy under lock protection

	return
}

func TestLatencyReassessOneOnly(t *testing.T) {
	now := time.Now()
	bs, err := NewLatency(LatencyConfig{}, []Server{first})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}

	best, _ := bs.Best()
	bs.Result(best, false, now, 0) // Ultimately calls reassessBest()
	if bs.reassessRationale != algOnlyOne {
		t.Error("reassessBest() should have short-circuited with a single server", bs.reassessRationale)
	}
}

func TestLatencyReassessRehab(t *testing.T) {
	now := time.Now()
	bs, err := NewLatency(LatencyConfig{}, []Server{first, second})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}
	best, _ := bs.Best() // Should be 'first'
	if best != first {   // So let's check
		t.Fatal("Setup of best is not first", best)
	}
	bs.Result(best, false, now, 0) // Set Best (first} to failed and awaiting rehabilitation
	if !bs.stats[0].lastStatusWasFailure {
		t.Fatal("Last was Failure should be true for first")
	}
	now = now.Add(bs.ResetFailedAfter + time.Second)
	best, _ = bs.Best()
	bs.Result(best, false, now, 0) // Force reassessBest() which should rehabilitate first
	if bs.stats[0].lastStatusWasFailure {
		t.Fatal("Last was Failure should have been reset by rehab")
	}
}

func TestLatencySecondCab(t *testing.T) {
	now := time.Now()
	bs, err := NewLatency(LatencyConfig{}, []Server{first, second, third})
	if err != nil {
		t.Fatal("Unexpected error when setting up for test", err)
	}

	bs.Result(third, true, now, time.Second) // Third now has a legit weighted average
	bs.Result(first, false, now, 0)          // Should cause reasssess
	best, _ := bs.Best()
	if best != third {
		t.Error("Reassess should have preferred third over second due to real data", best)
	}
	if bs.reassessRationale != algSecondCab {
		t.Error("Got right answer for wrong reason", bs.reassessRationale)
	}
}
