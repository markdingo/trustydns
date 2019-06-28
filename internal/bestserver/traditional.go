package bestserver

import (
	"time"
)

// TraditionalConfig defines all the public parameters that the calling application can
// set. Currently this is just a place-holder for the API. But easier to add a field to an empty
// struct than to add an additional parameter to an API in widespread use.
type TraditionalConfig struct {
}

var (
	defaultTraditionalConfig = TraditionalConfig{}
)

type traditional struct {
	TraditionalConfig
	baseManager
}

func NewTraditional(config TraditionalConfig, servers []Server) (*traditional, error) {
	t := &traditional{}
	err := t.baseManager.init(TraditionalAlgorithm, servers)
	if err != nil {
		return nil, err
	}

	return t, err
}

func (t *traditional) Result(server Server, success bool, now time.Time, latency time.Duration) bool {
	t.lock()
	defer t.unlock()

	ix, found := t.serverToIndex[server]
	if !found {
		return false
	}

	if success {
		return true
	}

	if ix == t.bestIndex { // If 'best' failed, move to next server.
		t.bestIndex = (t.bestIndex + 1) % t.serverCount
	}

	return true
}
