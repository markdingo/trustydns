package osutil

import (
	"os"
	"strings"
	"testing"
)

// This function is virtually impossible to test within the Go test framework as a single successful
// test means no others can possibly run as we've thrown away all our rights. All we can do is test
// a few of the error paths and you'll have to have faith that the successful code paths have been
// tested...
func TestConstrain(t *testing.T) {
	if os.Getuid() != 0 {
		t.Log("Warning: Cannot even partially test osutil.Constrain() as we're not running as root")
	}
	err := Constrain("bogusUser", "", "")
	if err == nil {
		t.Error("Expected Error Return with bogusUser")
	} else {
		if !strings.Contains(err.Error(), "unknown user") {
			t.Error("Did not get unknown user in ", err)
		}
	}

	err = Constrain("", "bogusGroup", "")
	if err == nil {
		t.Error("Expected Error Return with bogusGroup")
	} else {
		if !strings.Contains(err.Error(), "unknown group") {
			t.Error("Did not get unknown group in ", err)
		}
	}
}

// This is a pretty lame test
func TestReport(t *testing.T) {
	rep := ConstraintReport()
	if !strings.Contains(rep, "uid=") {
		t.Error("ConstraintReport is really bruk", rep)
	}
}
