//go:build windows || !unix
// +build windows !unix

package osutil

const (
	me = "osutil.Constrain: "
)

func Constrain(userName, groupName, chrootDir string) error {
	return nil
}

func ConstraintReport() string {
	return "uid=windows gid=windows cwd=?"
}
