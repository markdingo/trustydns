// +build windows !unix

package osutil

import (
	"os"
)

// SignalNotify sends all the main Unix signals to the supplied channel
func SignalNotify(c chan os.Signal) {
}

func IsSignalUSR1(s os.Signal) bool {
	return false
}
