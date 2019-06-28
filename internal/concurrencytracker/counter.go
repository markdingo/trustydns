/*
concurrencytracker keeps track of how many concurrent requests are active. The purpose is simply
to provide the ability to report peak concurrency over a reporting period. Typically usage:

 var ct concurrencytrack.Counter

 func ServeSomething() {
   cct.Add()
   defer cct.Done()
   ... do some work
 }

and in some reporting function

 fmt.Println("Peak Concurrency",  cct.Peak(true))
*/
package concurrencytracker

import (
	"sync"
)

type Counter struct {
	sync.Mutex
	current int // Count of pending Done() calls
	peak    int // Max 'current' has ever reached
}

// Add increments 'current' and if a new peak has been reached, the peak value is updated. Return
// true if the peak has increased as a result of this call.
func (t *Counter) Add() (increased bool) {
	t.Lock()
	defer t.Unlock() // A tad silly to defer for a tiny func, but "idioms aint idioms for nuthin', Sol!"
	t.current++
	if t.current > t.peak {
		t.peak = t.current
		increased = true
	}

	return
}

// Done decrements 'current'. Done() must only be called after an Add() call, otherwise a panic
// ensues.
func (t *Counter) Done() {
	t.Lock()
	defer t.Unlock()
	if t.current == 0 {
		panic("concurrencytracker.Done() lacks matching .Add()") // Someone goofed
	}
	t.current--
}

// Peak returns the peak concurrency count and optionally resets the peak value to the current
// concurrency value. Note that the current counter is *not* reset by this call. In fact that value
// is never rest. The reset occurs *after* the return value is set so the impact of the reset is not
// visible until a subsequent call to Peak().
func (t *Counter) Peak(resetCounters bool) (peak int) {
	t.Lock()
	defer t.Unlock()
	peak = t.peak
	if resetCounters {
		t.peak = t.current
	}

	return
}
