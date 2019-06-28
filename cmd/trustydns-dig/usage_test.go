package main

import (
	"testing"
)

var usageTestCases = []testCase{
	{[]string{}, []string{}, "Fatal: trustydns-dig: Require DoH Server URL on command line. Consider -h"},
	{[]string{"-h"}, []string{"NAME", "SYNOPSIS", "OPTIONS", "Version: v"}, ""},
	{[]string{"--version"}, []string{"Version: v"}, ""},
	{[]string{"-badopt"}, []string{}, "flag provided but not defined"},

	{[]string{"--ecs-set", "10.0.120.XXX/24", "http://localhost:63080", "example.net"}, []string{},
		"invalid CIDR address"},
	{[]string{"--ecs-set", "10.0.120.0/24", "--ecs-request-ipv4-prefixlen", "24",
		"http://localhost:63080", "example.net"}, []string{},
		"Cannot have both --ecs-set and --ecs-request"},

	{[]string{"--ecs-set", "10.0.120.0/24", "--ecs-request-ipv6-prefixlen", "66",
		"http://localhost:63080", "example.net"}, []string{},
		"Cannot have both --ecs-set and --ecs-request"},
	{[]string{"--ecs-request-ipv6-prefixlen", "200",
		"http://localhost:63080", "example.net"}, []string{},
		"must be between 0 and 128"},
	{[]string{"--ecs-request-ipv4-prefixlen", "200",
		"http://localhost:63080", "example.net"}, []string{},
		"must be between 0 and 32"},

	{[]string{"", "example.net"}, []string{}, "URL cannot be an empty string"},
	{[]string{"htts://localhost", "example.net"}, []string{}, "unsupported"},
	{[]string{"http://", "example.net"}, []string{}, "does not contain a hostname"},
	{[]string{"httpX://localhost/xxx", "example.net"}, []string{}, "unsupported protocol scheme"},
	{[]string{"://localhost/xxx", "example.net"}, []string{}, "missing protocol scheme"},
	{[]string{"http://localhost:63080"}, []string{}, "Require qName on command"},
	{[]string{"http://localhost:63080", "example.net", "BADTYPE"}, []string{}, "Unrecognized qType"},
	{[]string{"http://localhost:63080", "example.net", "AAAA", "goop"}, []string{}, "know what to do"},

	{[]string{"-t", "xx", "http://localhost:63080", "example.net"}, []string{}, "invalid value"},
	{[]string{"--tls-cert", "/dev/null", "http://localhost:63080", "example.net"}, []string{},
		"key file missing"},
	{[]string{"--tls-key", "/dev/null", "http://localhost:63080", "example.net"}, []string{},
		"cert file missing"},

	{[]string{"http://localhost:63080", "example.."}, []string{}, "Is it a valid FQDN"},

	{[]string{"-r", "-1", "http://localhost:63080", "example.net"}, []string{}, "Repeat count"},
}

func TestUsage(t *testing.T) {
	for tx, tc := range usageTestCases {
		runTest(t, tx, tc)
	}
}
