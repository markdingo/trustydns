/*
Package connectiontracker track connections for statistical purposes - ostensibly for inbound HTTP2
connections - but it is a generic package that should apply to other connections. The goal is to
determine occupancy and concurrency on a per-listen-address basis and within a given connection for
those connections which support sessions.

connectiontracker presents a reporter interface so its output can be periodically logged.

Typically usage is to create a connectiontracker for a given listen or connect address then call it
via the http.Server.ConnState function or moral equivalent, i.e:

	ct := connectiontracker.New("Name")
	s := http.Server{ConnState: func(c net.Conn, state ConnState) {
	                                 ct.ConnState(c.RemoteAddr().String(), time.Now(), state)
	                             }

	... time passes and requests occur
	fmt.Println(ct.Report(true))

If you are running a system in which connections can have multiple sessions such as HTTP2 then you
should also call SessionAdd/SessionDone when sessions transition from active to closed. This is
normally at the beginning of the request handler, such as:

	ct.SessionAdd(http.Request.RemoteAddr)
	defer ct.SessionDone(http.Request.RemoteAddr)

The connection and session key can be any string you like so long as it is consistent and accurately
reflects a unique connection endpoint. Normally it's a remote address/port and by virtue of the fact
that a connectiontracker is associated with a server having a unique listen address the remote
address/port/listen-address tuple makes the key appropriately unique.
*/
package connectiontracker

import (
	"net/http"
	"sync"
	"time"
)

type connectionStats struct {
	connStart       time.Time     // When connection was first established
	activeStart     time.Time     // Last transition to active
	activeFor       time.Duration // Sum of active periods
	currentSessions int
	peakSessions    int
}

type connection struct {
	connectionStats
}

func (t *connection) resetCounters() {
}

type errIx int

const (
	errNoConnInMap         errIx = iota // Connection not present for state change
	errNoConnForSession                 // No Connection found for session
	errDanglingConn                     // New when already active
	errNegativeConcurrency              // More Idle than Active transitions
	errConnsLost                        // Close/hijack and concurrency greater than zero
	errUnknownState                     // We must be old relative to net/http
	errArSize
)

type trackerStats struct {
	peakConns    int
	peakSessions int
	connFor      time.Duration // Total connections existence time (can easily be GT elapse)
	activeFor    time.Duration // Total connections active time
	errors       [errArSize]int
}

type Tracker struct {
	name string
	mu   sync.Mutex

	connMap map[string]*connection // Indexed by address of connection
	trackerStats
}

// New constructs a tracker object - in particular the map used to track each connection key
func New(name string) *Tracker {
	t := &Tracker{name: name}
	t.connMap = make(map[string]*connection)

	return t
}

// ConnState is called when a connection transitions to a new state. The key can be anything so long
// as it is unique per-connection though normally it will be the net.Conn.RemoteAddr() provided by
// http. So long as it's unique for a given connection tho, it's all good.
//
// ConnState checks that the new state makes sense for the connection and if it does, the connection
// is updated and true is returned. If the new state doesn't make sense, the transition and internal
// state are reconciled and false is returned. Reconciliation favours the current state over the
// previous to avoid dangling connections.
//
// ConnState does not fastidiously check that all state transitions make sense, it merely checks
// those which need to be correct for it to perform its function. This is a statistics gathering
// function after all, not a logic validation monster; besideswhich this function does not really
// know which transitions are legal in most cases.
func (t *Tracker) ConnState(key string, now time.Time, state http.ConnState) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	cs, ok := t.connMap[key]
	if state == http.StateNew { // All other states must have a pre-existing connection
		cs := &connection{} // Always create a new and possibly over-write any dangling
		cs.connStart = now  // connection.
		t.connMap[key] = cs
		if ok { // Dangling connection? Report it
			t.errors[errDanglingConn]++
		}
		cc := len(t.connMap)
		if cc > t.peakConns {
			t.peakConns = cc
		}
		return !ok
	}

	if !ok { // If it's not a pre-existing connection then record the error and exit
		t.errors[errNoConnInMap]++
		return false
	}

	switch state {
	case http.StateActive:
		cs.activeStart = now
		return true

	case http.StateIdle:
		if !cs.activeStart.IsZero() {
			cs.activeFor += now.Sub(cs.activeStart)
			cs.activeStart = time.Time{}
		}
		return true

	case http.StateHijacked, http.StateClosed:
		t.connFor += now.Sub(cs.connStart)
		if !cs.activeStart.IsZero() { // Capture last active period
			cs.activeFor += now.Sub(cs.activeStart)
		}
		t.activeFor += cs.activeFor

		delete(t.connMap, key)
		if cs.currentSessions > 0 { // Assuming this is an error for now, but it may not be
			t.errors[errConnsLost]++
			return false
		}
		if cs.peakSessions > t.peakSessions {
			t.peakSessions = cs.peakSessions
		}
		return true
	}

	t.errors[errUnknownState]++
	return false
}

// SessionAdd increments a session counter within a connection. Not all connections support multiple
// sessions, but some such as HTTP2, do. Return false if the connection key is not know.
func (t *Tracker) SessionAdd(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	cs, ok := t.connMap[key]
	if !ok {
		t.errors[errNoConnForSession]++
		return false
	}

	cs.currentSessions++
	if cs.currentSessions > cs.peakSessions {
		cs.peakSessions = cs.currentSessions
	}

	return true
}

// SessionDone undoes SessionAdd.
func (t *Tracker) SessionDone(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	cs, ok := t.connMap[key]
	if !ok {
		t.errors[errNoConnForSession]++
		return false
	}

	if cs.currentSessions <= 0 {
		t.errors[errNegativeConcurrency]++
		return false

	}
	cs.currentSessions--

	return true
}
