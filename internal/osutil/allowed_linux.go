//go:build linux
// +build linux

// setuid/setgid don't work on Linux via Go because Linux has a nutty arrangement whereby each thread
// has its own uid/gid. Perhaps because threads are processes in Linux? Anyway, it's been broken
// since at least 2011 and hasn't been fixed in the intervening 8+ years.
//
// This is an amazing pain as Go is predominantly used for developing servers such as this one which
// typically require root privileges to open network sockets. Best security practise has long been
// for network daemons to subsequently setuid/setgid/chroot to minimize the capabilities of a
// network break-in. At least this still works on all other Unixen I know of. Maybe that tells you
// something.
//
// For more details see: https://github.com/golang/go/issues/1435

package osutil

const (
	setuidAllowed = false
	setgidAllowed = false
)
