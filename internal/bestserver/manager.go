package bestserver

import (
	"time"
)

// Server is the interface used to create a bestserver collection. It is returned by Best() and
// passed in to Result(). The underlying struct is supplied by the caller when they created a
// bestserver collection with one of the New* functions. This struct can be either one created by
// the caller or the default struct used by our NewFromNames() helper method. The application will
// normally supply its own if it wants to track other things related to the server, such as stats or
// server IP address or similar.
type Server interface {
	Name() string
}

// Manager is the public interface for bestserver.
type Manager interface {
	// Algorithm returns the name of the implementation
	Algorithm() string

	// Best returns the current best server (and its index into the Server
	// List) as determined by the underlying algorithm in use. It always
	// returns valid values. The returned index is an index to the server
	// list as originally supplied when this collection was created.
	Best() (Server, int)

	// Result updates internal statistics and *may* assess whether there is a
	// better choice for the current 'best' server.
	//
	// The Server passed into Result() must be exactly the value returned by
	// Best() as it is used as an index into a map. Result() requires the
	// Server parameter to be supplied rather than rely on the existing
	// "best" server as the "best" Server may have change between the two
	// calls by the action of another go-routine.
	//
	// Return false if Server is not part of this collection
	Result(server Server, success bool, now time.Time, latency time.Duration) bool

	// Servers returns a slice of all Servers in the order originally created.
	Servers() []Server

	// Len returns the count of servers
	Len() int
}
