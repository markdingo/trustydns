//go:build unix || !windows
// +build unix !windows

package osutil

import (
	"os"
	"os/signal"
	"syscall"
)

// SignalNotify sends all the main Unix signals to the supplied channel. A noop on Windows.
func SignalNotify(c chan os.Signal) {
	signal.Notify(c, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGUSR1)
}

// IsSignalUSR1 returns true if the supplied signal is SIGUSR1. A noop on Windows.
func IsSignalUSR1(s os.Signal) bool {
	return s == syscall.SIGUSR1
}
