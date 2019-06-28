package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

//////////////////////////////////////////////////////////////////////

type usageTestCase struct {
	expectToRun bool     // waitForExecute should not return an error if this is true
	args        []string // ARGV - not counting command
	stdout      []string // Expected stdout strings
	stderr      string   // Expected stderr string
}

var usageTestCases = []usageTestCase{
	{false, []string{"--version"}, []string{"trustydns-proxy", "Version:"}, ""},
	{false, []string{"-h"}, []string{"NAME", "SYNOPSIS", "OPTIONS", "Version: v"}, ""},
	{false, []string{}, []string{}, "Fatal: trustydns-proxy: Must supply at least one DoH server URL on the command line"},
	{false, []string{"-badopt"}, []string{}, "flag provided but not defined"},
	{false, []string{"-v", "-A", "255.254.253.252", "http://localhost:63080"}, []string{"Starting:"},
		"assign requested address"},

	// -e local domains without resolv.conf
	{false, []string{"-e", "example.net", "http://localhost"}, []string{}, "Local Domains"},

	// Bad ecs-set
	{false, []string{"--ecs-set", "10.0.120.XXX/24", "http://localhost:63080"}, []string{}, "invalid CIDR"},
	{false, []string{"--ecs-set", "10.0.120.0/24", "--ecs-request-ipv4-prefixlen", "24",
		"http://localhost"}, []string{}, "Cannot have both --ecs-set and --ecs-request"},
	{false, []string{"--ecs-set", "10.0.120.0/24", "--ecs-request-ipv6-prefixlen", "66",
		"http://localhost"}, []string{}, "Cannot have both --ecs-set and --ecs-request"},
	{false, []string{"--ecs-request-ipv6-prefixlen", "200", "http://localhost:63080"}, []string{},
		"must be between 0 and 128"},
	{false, []string{"--ecs-request-ipv4-prefixlen", "200", "http://localhost:63080"}, []string{},
		"must be between 0 and 32"},
	{false, []string{"--ecs-request-ipv6-prefixlen", "-2", "http://localhost:63080"}, []string{},
		"must be between 0 and 128"},
	{false, []string{"--ecs-request-ipv4-prefixlen", "-1", "http://localhost:63080"}, []string{},
		"must be between 0 and 32"},

	// Transport
	{false, []string{"--udp=false", "--tcp=false", "http://localhost:63080"}, []string{},
		"Must have one of"},

	// ECS with GET
	{false, []string{"-g", "--ecs-set", "10.0.120.0/24", "http://localhost:63080"}, []string{}, "any ECS synthesis"},

	// Test URL mangling code paths
	{false, []string{"http://"}, []string{}, "does not contain a hostname"},
	{false, []string{"://localhost/xxx"}, []string{}, "missing protocol scheme"},

	// Bad options
	{false, []string{"-t", "xxs", "http://localhost"}, []string{}, "invalid value"},
	{false, []string{"-i", "xxs", "http://localhost"}, []string{}, "invalid value"},
	{false, []string{"-r", "0", "http://localhost:63080"}, []string{}, "Minumum remote concurrency"},

	// Bad local resolver config
	{false, []string{"-c", "testdata/emptyfile", "http://localhost"}, []string{}, "No servers"},

	// tls
	{false, []string{"--tls-cert", "testdata/emptyfile", "http://localhost"}, []string{}, "key file missing"},
	{false, []string{"--tls-key", "testdata/emptyfile", "http://localhost"}, []string{}, "cert file missing"},
}

func TestUsage(t *testing.T) {
	for tx, tc := range usageTestCases {
		t.Run(fmt.Sprintf("%d", tx), func(t *testing.T) {
			args := append([]string{"trustydns-proxy"}, tc.args...)
			out := &bytes.Buffer{}
			err := &bytes.Buffer{}
			mainInit(out, err)
			done := make(chan error)
			go func() {
				done <- waitForMainExecute(t, time.Millisecond*200)
			}()
			ec := mainExecute(args)
			e := <-done // Get waitForExecute results
			outStr := out.String()
			errStr := err.String()

			if e != nil && tc.expectToRun {
				t.Fatal("Expected to run, but", e, errStr, outStr)
			}
			if ec == 0 && len(tc.stderr) > 0 {
				t.Error("Expected error exit from Execute() with stderr", tc.stderr)
			}

			if len(errStr) > 0 && len(tc.stderr) == 0 {
				t.Error("Did not expect a fatal error:", errStr)
			}
			if !strings.Contains(errStr, tc.stderr) {
				t.Error("Stderr expected:", tc.stderr, "Got:", errStr)
			}

			for _, o := range tc.stdout {
				if !strings.Contains(outStr, o) {
					t.Error("Stdout expected:", o, "Got:", outStr)
				}
			}
		})
	}
}
