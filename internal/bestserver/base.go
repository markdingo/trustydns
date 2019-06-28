package bestserver

import (
	"errors"
	"sync"
)

type algorithm string

const (
	LatencyAlgorithm     algorithm = "latency"     // Pick the fastest most reliable server
	TraditionalAlgorithm           = "traditional" // Pick until fails - just as res_send() does
)

// baseManager implements most of the Manager interface and provides helper routines that assist in
// implementations meeting the Manager interface. Algorithms are encouraged to compose themselves
// with baseManager as a way of providing most of the interface, though of course they are not
// obliged to do so.
type baseManager struct {
	algType       algorithm    // Set by Algorithm
	mu            sync.RWMutex // Protects everything below here as well as implementation vars
	servers       []Server
	serverCount   int            // Cache of len(servers)
	serverToIndex map[Server]int // Converts Server back to array index
	bestIndex     int            // Index of current 'best' server
}

// lock is a wrapper to encapsulate locking on behalf of all bestserver
// implementations. Implementations must call lock|rlock/unlock to protect their
// data structures from concurrent access.
func (t *baseManager) lock() {
	t.mu.Lock()
}

// unlock is a wrapper to encapsulate locking on behalf of all implementations.
func (t *baseManager) unlock() {
	t.mu.Unlock()
}

// rlock is a wrapper to encapsulate locking on behalf of all implementations.
func (t *baseManager) rlock() {
	t.mu.RLock()
}

// rlock is a wrapper to encapsulate locking on behalf of all implementations.
func (t *baseManager) runlock() {
	t.mu.RUnlock()
}

// init is called by the algorithm constructor to initialize the server variables.
func (t *baseManager) init(algType algorithm, servers []Server) error {
	if len(servers) == 0 {
		return errors.New("bestserver:No servers in list")
	}
	t.algType = algType
	t.servers = servers
	t.serverCount = len(t.servers)

	t.serverToIndex = make(map[Server]int)
	for ix, s := range t.servers {
		if _, ok := t.serverToIndex[s]; ok {
			return errors.New("bestserver.New: Duplicate Server in list: " + s.Name())
		}
		t.serverToIndex[s] = ix
	}

	return nil
}

func (t *baseManager) Algorithm() string {
	return string(t.algType)
}

func (t *baseManager) Best() (Server, int) {
	t.rlock()
	defer t.runlock()

	return t.servers[t.bestIndex], t.bestIndex
}

func (t *baseManager) Servers() []Server {
	servers := make([]Server, len(t.servers))
	copy(servers, t.servers)

	return servers
}

func (t *baseManager) Len() int {
	return len(t.servers)
}

// defaultServer is the internal struct used to hold the server names provided to the NewFromNames()
// constructor.
type defaultServer struct {
	name string
}

// Name returns the name of the server returned by Best()
func (t *defaultServer) Name() string {
	return t.name
}

// ServersFromNames is a helper function to construct a Server list for a string list. The order of
// the returned list is the same as that of the supplied names.
func ServersFromNames(names []string) []Server {
	servers := make([]Server, 0, len(names))
	for _, n := range names {
		servers = append(servers, &defaultServer{name: n})
	}

	return servers
}
