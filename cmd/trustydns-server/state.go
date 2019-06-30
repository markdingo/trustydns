// Manage main state transitions for unit tests. Not used in production code path.
package main

import (
	"sync"
)

type mainStateType int

const (
	Initial mainStateType = iota // Never been started
	Started                      // Running
	Stopped                      // Previously started, now stopped
)

var (
	stateMutex sync.Mutex
	state      mainStateType = Initial
)

func mainState(newState mainStateType) {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	state = newState

}

func isMain(wantedState mainStateType) bool {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	return state == wantedState
}
