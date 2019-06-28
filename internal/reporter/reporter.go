/*
Package reporter defines a simple interface for structs to produce a printable report about
themselves which are typically statistically oriented.

The string returned by Report() should be one or more lines separated by newlines suitable for
printing to a log file. The caller will normally split multiple lines up and prefix them with some
other logging data, such as timestamps and source. Empty lines are ignored and the final trailing
newline should not be present thus most single line reporters should not bother with a newline as
the caller is likely to go: fmt.Println(you.Report()) or similar.
*/
package reporter

// Reporter is the sole package interface
type Reporter interface {

	// Name returns the name of the reportable struct. This is normally used
	// as a prefix for reportable output.
	Name() string

	// Report returns one or more printable set of lines separated by
	// newlines. If 'resetCounters' is true, then any internal values used
	// to produce the report should be reset to zero *after* the report is
	// produced. Implementation needs to manage concurrent access as
	// Report() may be called by multiple go-routines - albeit unlikely.
	Report(resetCounters bool) string
}
