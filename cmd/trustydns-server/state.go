// Manage main state transitions for unit tests. Not used in production code path.
package main

import (
	"sync"
)

type mainStateType int

const (
	initial mainStateType = iota // Never been started
	started                      // Running
	stopped                      // Previously started, now stopped
)

var (
	stateMutex sync.Mutex
	state      mainStateType = initial
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
