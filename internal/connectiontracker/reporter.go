package connectiontracker

import (
	"fmt"
	"time"
)

// Name implements the reporter interface
func (t *Tracker) Name() string {
	return "Conn Track"
}

// Name Report implements the reporter interface
func (t *Tracker) Report(resetCounters bool) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	errs := 0
	for _, v := range t.errors {
		errs += v
	}
	report := fmt.Sprintf("curr=%d pk=%d sess=%d errs=%d (%s) connFor=%0.1fs activeFor=%0.1fs %s",
		len(t.connMap), t.peakConns, t.peakSessions, errs, formatCounters("%d", "/", t.errors[:]),
		t.connFor.Round(time.Millisecond*100).Seconds(), t.activeFor.Round(time.Millisecond*100).Seconds(),
		t.name)
	if resetCounters {
		t.trackerStats = trackerStats{}
		for _, v := range t.connMap {
			v.resetCounters()
		}
	}

	return report
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
