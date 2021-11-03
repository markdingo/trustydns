//go:build !linux || unix
// +build !linux unix

package osutil

const (
	setuidAllowed = true
	setgidAllowed = true
)
