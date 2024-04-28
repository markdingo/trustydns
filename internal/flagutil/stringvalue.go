// Package flagutil provides additional support around the flag package. At the moment that consists
// solely of the StringValue struct which conforms to the flag.Value method for multiple occurrence
// flags containing string values. Conceivably an IPValue struct would be pretty useful too as well
// as, e.g. a CIDRValue.
//
// The reason for providing StringValue is so that commands can offer a flag to set multiple values
// such as:
//
// $command -A something -A somethingelse -A evenmore
// ...
//
// Usage is as documented in the flags package:
//
//		var ms flagutil.StringValue
//	     flagSet.Var(&ms, "someopt", "Short description of opt")
//	     args := ms.Args() // Return an array of strings
//
// or
//
//	flag.Var(&ms, "someopt", "Short description of opt")
//	args := ms.Args() // Return an array of strings
package flagutil

import (
	"strings"
)

// StringValue is the type provided to flag.Var()
type StringValue struct {
	strings []string
}

// Set appends a string to the internal array - it is called by the flag package for each occurrence
// of the corresponding option on the command line. Part of the flag.Value interface.
func (t *StringValue) Set(s string) error {
	t.strings = append(t.strings, s)

	return nil
}

// String returns a space separated string of all the arguments provided by Set. Part of the
// flag.Value interface.
func (t *StringValue) String() string {
	return strings.Join(t.strings, " ")
}

// Args returns a copy of the array of strings returned by Set. You can safely modify this
// array without fear of changing the internal data.
func (t *StringValue) Args() []string {
	return append([]string{}, t.strings...)
}

// NArg returns the number of strings created by Set
func (t *StringValue) NArg() int {
	return len(t.strings)
}
