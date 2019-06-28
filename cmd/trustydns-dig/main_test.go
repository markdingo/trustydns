package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

type testCase struct {
	args   []string
	stdout []string
	stderr string
}

var mainTestCases = []testCase{
	{[]string{"http://localhost:63080", "example.net"}, []string{}, "connection refused"},
	{[]string{"-r", "2", "http://localhost:63080", "example.net"}, []string{}, "connection refused"},
	{[]string{"-p", "-r", "2", "http://localhost:63080", "example.net"}, []string{}, "connection refused"},
	{[]string{"-g", "http://localhost:63080", "example.net"}, []string{}, "connection refused"},
	{[]string{"--ecs-set", "10.0.120.0/24", "http://localhost:63080", "example.net"}, []string{},
		"connection refused"},

	{[]string{"localhost", "example.net"}, []string{}, "connection refused"},

	{[]string{"-t", "xx", "http://localhost:63080", "example.net"}, []string{}, "invalid value"},
	{[]string{"--tls-cert", "/dev/null", "http://localhost:63080", "example.net"}, []string{},
		"key file missing"},

	// These tests may or may not work depending on whether the public server is accessible

	{[]string{"https://mozilla.cloudflare-dns.com/dns-query", "swcdn.g.aaplimg.com"},
		[]string{"Query Time", "17.", "status: NOERROR"}, ""},
	{[]string{"--short", "https://mozilla.cloudflare-dns.com/dns-query", "swcdn.g.aaplimg.com"},
		[]string{"swcdn.g.aaplimg.com", "IN", "17."}, ""},
}

func TestMain(t *testing.T) {
	for tx, tc := range mainTestCases {
		runTest(t, tx, tc)
	}
}

// This function is used by usage_test.go as well
func runTest(t *testing.T, tx int, tc testCase) {
	t.Run(fmt.Sprintf("%d", tx), func(t *testing.T) {
		args := append([]string{"trustydns-dig"}, tc.args...)
		out := &bytes.Buffer{}
		err := &bytes.Buffer{}
		mainInit(out, err)
		ec := mainExecute(args)

		outStr := out.String()
		errStr := err.String()

		if ec != 0 && len(tc.stderr) == 0 {
			t.Error("Unexpected non-zero exit code", ec, outStr, errStr)
		}

		if len(errStr) > 0 && len(tc.stderr) == 0 {
			t.Error("Did not expect stderr:", errStr)
		}
		if len(tc.stderr) > 0 && !strings.Contains(errStr, tc.stderr) {
			t.Error("Stderr expected:\n", tc.stderr, "Got:\n", errStr, args)
		}
		for _, o := range tc.stdout {
			if !strings.Contains(outStr, o) {
				t.Error("Stdout expected:\n", o, "Got:\n", outStr, args)
			}
		}
	})
}
