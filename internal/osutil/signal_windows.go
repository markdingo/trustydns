//go:build windows || !unix
// +build windows !unix

package osutil

import (
	"os"
)

func SignalNotify(c chan os.Signal) {
}

func IsSignalUSR1(s os.Signal) bool {
	return false
}
