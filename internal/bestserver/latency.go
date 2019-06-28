package bestserver

import (
	"fmt"
	"time"
)

// LatencyConfig defines all the public parameters that the calling application can set. They
// control reassessment rate, the frequency at which sampling of servers occurs and how much
// influence the latest latency has on the overall "weight" of the server.
type LatencyConfig struct {
	ReassessAfter     time.Duration // Reassess 'best' server after this duration or
	ReassessCount     int           // this many Result() calls
	ResetFailedAfter  time.Duration // Reset server stats to zero if failed this long ago
	SampleOthersEvery int           // Result() samples another server once every SampleOthersEvery calls
	WeightForLatest   int           // Percent weight for latest Result() latency (range: 0-100)
}

var (
	DefaultLatencyConfig = LatencyConfig{
		ReassessCount:     1061,
		ReassessAfter:     time.Second * 61,
		WeightForLatest:   67,
		ResetFailedAfter:  time.Minute * 3,
		SampleOthersEvery: 20, // 1 in 20 = 5%
	}
)

type reassessAlgorithm int // Rationale for selecting the new 'best' server
const (
	algNone      reassessAlgorithm = iota // No reason
	algOnlyOne                            // Server lists only has one entry so not many choices!
	algFirstCab                           // "First cab off the rank" the good one following the current one
	algSecondCab                          // Second cab off the rank with performance data
	algFastest                            // Lowest weighted average latency
	algAllBad                             // No good servers were find, just use next one
)

type latencyServerStats struct {
	lastStatusTime       time.Time
	lastStatusWasFailure bool
	weightedAverage      time.Duration
}

type latency struct {
	LatencyConfig
	baseManager

	stats []latencyServerStats

	assessCount       int               // Modulo counter of calls to assess()
	sampleCount       int               // Counter to tell when we reach sample rate
	sampleIndex       int               // Iterate over servers to sample performance
	saveBestIndex     int               // The source of truth for the bestIndex
	bestExpires       time.Time         // When to reassess 'best'
	reassessRationale reassessAlgorithm // Record why 'best' server was chosen
}

func NewLatency(config LatencyConfig, servers []Server) (*latency, error) {
	t := &latency{}
	err := t.baseManager.init(LatencyAlgorithm, servers)
	if err != nil {
		return nil, err
	}

	// Validate latency config params

	t.LatencyConfig = config

	if t.ReassessAfter < 0 {
		return nil, fmt.Errorf("ReassessAfter is  negative: %d", t.ReassessAfter)
	}
	if t.ReassessCount < 0 {
		return nil, fmt.Errorf("ReassessCount is negative: %d", t.ReassessCount)
	}
	if t.WeightForLatest < 0 || t.WeightForLatest > 100 {
		return nil, fmt.Errorf("WeightForLatest is not in range 0-100: %d", t.WeightForLatest)
	}
	if t.ResetFailedAfter < 0 {
		return nil, fmt.Errorf("ResetFailedAfter is negative: %d", t.ResetFailedAfter)
	}
	if t.SampleOthersEvery < 0 {
		return nil, fmt.Errorf("SampleOthersEvery is negative: %d", t.SampleOthersEvery)
	}

	// Set config defaults

	if t.ReassessAfter == 0 {
		t.ReassessAfter = DefaultLatencyConfig.ReassessAfter
	}
	if t.ReassessCount == 0 {
		t.ReassessCount = DefaultLatencyConfig.ReassessCount
	}
	if t.WeightForLatest == 0 {
		t.WeightForLatest = DefaultLatencyConfig.WeightForLatest
	}
	if t.ResetFailedAfter == 0 {
		t.ResetFailedAfter = DefaultLatencyConfig.ResetFailedAfter
	}
	if t.SampleOthersEvery == 0 {
		t.SampleOthersEvery = DefaultLatencyConfig.SampleOthersEvery
	}

	t.stats = make([]latencyServerStats, t.serverCount)

	return t, nil
}

func (t *latency) Result(server Server, success bool, now time.Time, latency time.Duration) bool {
	t.lock()
	defer t.unlock()

	ix, found := t.serverToIndex[server]
	if !found {
		return false
	}

	stats := &t.stats[ix]
	stats.lastStatusWasFailure = !success
	stats.lastStatusTime = now
	if success { // Latency updates are only meaningful with success as failure could have been a timeout!
		if stats.weightedAverage == 0 { // If no previous history, use current as complete average
			stats.weightedAverage = latency
		} else {
			current := latency * time.Duration(t.WeightForLatest)
			historic := stats.weightedAverage * time.Duration(100-t.WeightForLatest)
			stats.weightedAverage = (current + historic) / 100
		}
	}

	t.assess(now, ix, success)

	return true
}

// assess checks the latest report and if reporting on the 'best' and it's been a failure or reached
// one of the "reassess" thresholds search for a new 'best' server.
//
// A reassessment is only performed if this Result() is about the 'best' server because if its about
// a non-'best' server then essentially the caller is out-of-date.
//
// This method periodically and temporarily changes the 'best' server to one of the non-'best'
// "sample" servers to ensure we opportunistically collect the latency of all servers over time.
func (t *latency) assess(now time.Time, ix int, success bool) {
	t.assessCount++
	if ix == t.bestIndex {
		if !success || t.assessCount >= t.ReassessCount || now.After(t.bestExpires) {
			t.reassessBest(now)
			t.saveBestIndex = t.bestIndex
			t.assessCount = 0
		}
	}

	// Is it time to sample one of the other servers to gather performance data?

	// This sampling process is a bit hit and miss as it all depends on whether the next caller
	// calls Best() or Result(). E.g. if there is an in-flight query that finishes fractionally
	// after the sample is activated, then the 'best' will revert back to the real one without
	// the sample server ever getting a chance to be returned by Best(). Similarly multiple
	// Best() calls prior to a Result() call means the sample server gets used multiple times
	// instead of just once as intend. Nothing much can be done about that without breaking the
	// rule that Best() always returns the same result until a Result() call is made. (I guess
	// we could count Best() calls and use that to indicate if reversion should occur but that
	// only fixed the "missed" sample not the over-sample.) In any event, the net result should
	// be that over time the right number of samples do occur, it just may not seem that way on
	// a busy system in the microscopic view.

	t.sampleCount++
	if t.sampleCount < t.SampleOthersEvery {
		t.bestIndex = t.saveBestIndex // Not sampling so ensure reversion to real 'best'
		return                        // and we're done
	}

	t.sampleIndex = (t.sampleIndex + 1) % t.serverCount // move to next sample in sequence but
	if !t.stats[t.sampleIndex].lastStatusWasFailure {   // only sample if it's not failing
		t.bestIndex = t.sampleIndex
		t.sampleCount = 0 // Only reset if sample server is good, otherwise try next call
	}

}

// reassessBest searches for the server with the lowest weighted average latency.  Also rehabilitate
// servers that have been sidelined for sufficient time.
func (t *latency) reassessBest(now time.Time) {
	t.reassessRationale = algNone
	if t.serverCount == 1 { // Premature optimization or common case?
		t.reassessRationale = algOnlyOne
		return
	}
	newBest := -1                           // This is set to the new 'best', if one is found
	for ix := 0; ix < t.serverCount; ix++ { // Iterate over all servers
		stats := &t.stats[ix]
		switch {
		case stats.lastStatusWasFailure: // Time to rehabilitate a failed server?
			if stats.lastStatusTime.Add(t.ResetFailedAfter).Before(now) {
				*stats = latencyServerStats{} // Reset everything we know about this server
			}

		case newBest == -1: // First good alternative, start with that as a tentative 'best'
			t.reassessRationale = algFirstCab
			newBest = ix // Tentative 'best'
			stats = &t.stats[newBest]

		case stats.weightedAverage == 0: // Ignore servers with unknown latency

		case t.stats[newBest].weightedAverage == 0: // Replace first cab with a known server
			t.reassessRationale = algSecondCab
			newBest = ix
			stats = &t.stats[newBest]

		case stats.weightedAverage < t.stats[newBest].weightedAverage: // Prefer fastest
			t.reassessRationale = algFastest
			newBest = ix // Tentative 'best'
			stats = &t.stats[newBest]
		}
	}

	if newBest == -1 { // If no joy in finding a new 'best' then simply...
		newBest = (t.bestIndex + 1) % t.serverCount // ...move on to the next one after the current
		t.reassessRationale = algAllBad
	}

	t.bestIndex = newBest
	t.bestExpires = now.Add(t.ReassessAfter)
}
