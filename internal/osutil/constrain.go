// osutil is a helper package to abstract OS interactions. In particular constraining a process via
// chroot, setsid and setgid. Most of this functionality is disabled for Linux.

package osutil

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/user"
	"strconv"
	"strings"
)

const (
	me = "osutil.Constrain: "
)

// Constrain downgrades the abilities of the process by changing to a nominated uid/gid which
// presumably has less power and chroots to a directory that presumably has very little in it or
// below it.
//
// The order of operations is important. The symbolic user and group names are converted to uid and
// gid first while we have access to /etc/passwd (or the moral equivalent) then chroot is performed
// while we presumably have the power to access that directly. After that we eliminate supplementary
// groups as part of setting the group while we have a powerful uid and then we finally issue setuid
// that should make this whole sequence irreversible.
//
// Each step is optional if the corresponding parameter is an empty string.
//
// An error is returned if the downgrade could not be completed.
//
// Arguable we should also consider setsid and closing all un-needed file descriptors, but this is a
// reasonable start for this application. It is also the case that apparently everyone re-writes
// this function and most get it wrong, so I may have too...
func Constrain(userName, groupName, chrootDir string) error {

	// Step 1: Convert symbolic names to ids

	uid := -1
	gid := -1
	if len(userName) > 0 {
		u, err := user.Lookup(userName)
		if err != nil {
			return fmt.Errorf(me+"Lookup failed: %s", err.Error())
		}
		uid, err = strconv.Atoi(u.Uid)
		if err != nil {
			return fmt.Errorf(me+"Could not convert UID %s to an int: %s",
				u.Uid, err.Error())
		}
	}

	if len(groupName) > 0 {
		g, err := user.LookupGroup(groupName)
		if err != nil {
			return fmt.Errorf(me+"Could not look up group: %s: %s", groupName, err.Error())
		}
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return fmt.Errorf(me+"Could not convert GID %s to an int: %s",
				g.Gid, err.Error())
		}
	}

	// Step 2: chdir/chroot. Must be root to do this, but let Chroot() do the checking.

	if len(chrootDir) > 0 {
		err := os.Chdir(chrootDir)
		if err != nil {
			return fmt.Errorf(me+"Could not cd to %s: %s", chrootDir, err.Error())
		}

		err = unix.Chroot(chrootDir)
		if err != nil {
			return fmt.Errorf(me+"Could not chroot to %s: %s", chrootDir, err.Error())
		}

		err = os.Chdir("/")
		if err != nil {
			return fmt.Errorf(me+"Could not cd to /: %s", err.Error())
		}
	}

	// Step 3: setgid. This includes removing all supplementary groups.

	if gid != -1 {
		if setgidAllowed {
			err := unix.Setgroups([]int{})
			if err != nil {
				return fmt.Errorf(me+"Could not clear group list: %s", err.Error())
			}
			err = unix.Setgid(gid)
			if err != nil {
				return fmt.Errorf(me+"Could not setgid to %d/%s: %s",
					gid, groupName, err.Error())
			}
		} else {
			fmt.Println("WARNING: Go setgid() disabled for Linux. This process remains priviledged.")
		}
	}

	// The final piece of the puzzle. Step 4: setuid

	if uid != -1 {
		if setuidAllowed {
			err := unix.Setuid(uid)
			if err != nil {
				return fmt.Errorf(me+"Could not setuid to %d/%s: %s",
					uid, userName, err.Error())
			}
		} else {
			fmt.Println("WARNING: Go setuid() disabled for Linux. This process remains priviledged.")
		}
	}

	return nil
}

// ConstraintReport returns a printable string showing the uid/gid/cwd of the process. Normally
// called after Constrain() to "prove" that the process has been downgraded.
func ConstraintReport() string {
	uid := os.Getuid()
	gid := os.Getgid()
	cwd, _ := os.Getwd()
	gList, _ := os.Getgroups()
	gStr := make([]string, 0, len(gList))
	for _, g := range gList {
		gStr = append(gStr, fmt.Sprintf("%d", g))
	}

	_ = gList
	s := fmt.Sprintf("uid=%d gid=%d (%s) cwd=%s", uid, gid, strings.Join(gStr, ","), cwd)

	return s
}
