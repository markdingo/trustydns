package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

type testUsageCase struct {
	expectToRun bool     // waitForExecute should not return an error if this is true
	args        []string // ARGV - not counting command
	stdout      []string // Expected stdout strings
	stderr      string   // Expected stderr string
}

var testUsageCases = []testUsageCase{
	{false, []string{"--version"}, []string{"trustydns-server", "Version:"}, ""},
	{false, []string{"-h"}, []string{"NAME", "SYNOPSIS", "OPTIONS", "Version: v"}, ""},
	{false, []string{"-badopt"}, []string{}, "flag provided but not defined"},
	{false, []string{"-v", "-A", "255.254.253.252"}, []string{"Starting"},
		"assign requested address"},
	{false, []string{"Command", "line", "goop"}, []string{}, "Unexpected parameters"},

	// Bad ecs-set values
	{false, []string{"--ecs-set-ipv4-prefixlen", "200"}, []string{}, "must be between 0 and 32"},
	{false, []string{"--ecs-set-ipv6-prefixlen", "200"}, []string{}, "must be between 0 and 128"},
	{false, []string{"--ecs-set-ipv4-prefixlen", "-1"}, []string{}, "must be between 0 and 32"},
	{false, []string{"--ecs-set-ipv6-prefixlen", "-2"}, []string{}, "must be between 0 and 128"},

	// Bad local resolver config
	{false, []string{"-c", ""}, []string{}, "Must supplied a resolv.conf"},
	{false, []string{"-c", "testdata/emptyfile"}, []string{}, "No servers"},

	// tls
	{false, []string{"--tls-cert", "testdata/nosuchfile"}, []string{}, "Certificate file count"},
	{false, []string{"--tls-key", "testdata/nosuchfile"}, []string{}, "key file count"},
}

func TestUsage(t *testing.T) {
	for tx, tc := range testUsageCases {
		t.Run(fmt.Sprintf("%d", tx), func(t *testing.T) {
			args := append([]string{"trustydns-server"}, tc.args...)
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
