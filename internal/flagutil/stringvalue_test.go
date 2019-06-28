package flagutil

import (
	"testing"
)

func TestStringValue(t *testing.T) {
	var ms StringValue
	l := ms.NArg()
	if l != 0 {
		t.Error("Expected length=0 at initial state, not", l)
	}
	s := ms.String()
	if s != "" {
		t.Error("String() at initial state should be empty, not", s)
	}

	err := ms.Set("a")
	if err != nil {
		t.Error("Unexpected an error return from Set", err)
	}

	l = ms.NArg()
	if l != 1 {
		t.Error("Expected length=1 after one set, not", l)
	}
	ms.Set("b")

	s = ms.String()
	if s != "a b" {
		t.Error("String should be 'a b', not", s)
	}

	ss := ms.Args()
	if len(ss) != 2 || ss[0] != "a" || ss[1] != "b" {
		t.Error("Returned array should be [a, b], not", ss)
	}

	ss[0] = "A"
	ss = append(ss, "c")

	ss = ms.Args()
	if len(ss) != 2 || ss[0] != "a" || ss[1] != "b" {
		t.Error("Second returned array should be [a, b], not", ss)
	}
}
