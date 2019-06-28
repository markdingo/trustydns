package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

type mainTestCase struct {
	description string
	needsRoot   bool          // Only run if we're setuid 0
	willRunFor  time.Duration // trustydns-server should run for this amount of time before being terminated
	args        []string      // ARGV - not counting command
	stdout      []string      // Expected stdout strings
	stderr      string        // Expected stderr string
}

// The -A 255.... arguments are present to cause mainExecute() to fail when it starts *after*
// exercising the code coverage area intended. Yeah a bit of a hack, but the go testing framework is
// not well suited to running command-line tests that involve running then killing.

var mainTestCases = []mainTestCase{
	{"ecs-set",
		false, 100 * time.Millisecond, []string{"-A", "127.0.0.1:63081", "-v", "--ecs-set"},
		[]string{"Starting", "Exiting"}, ""},
	{"ecs-*prefixlen",
		false, 100 * time.Millisecond, []string{"-A", "127.0.0.1:63082", "-v",
			"--ecs-remove", "--ecs-set", "--ecs-set-ipv4-prefixlen", "20", "--ecs-set-ipv6-prefixlen", "56"},
		[]string{"Starting", "Exiting"}, ""},

	{"Good tls files",
		false, 100 * time.Millisecond, []string{"-v", "-A", "127.0.0.1:63081",
			"--tls-cert", "testdata/server.cert", "--tls-key", "testdata/server.key"},
		[]string{"Starting", "Exiting"}, ""},

	{"Good local resolver config",
		false, 100 * time.Millisecond, []string{"-v", "-A", "127.0.0.1:63081", "-c", "testdata/resolv.conf"},
		[]string{"Starting", "Exiting"}, ""},

	{"Good profile files",
		false, 100 * time.Millisecond, []string{"--cpu-profile", "testdata/cpu",
			"--mem-profile", "testdata/mem", "-v", "-A", "127.0.0.1:63081", "-c", "testdata/resolv.conf"},
		[]string{"Starting", "Exiting"}, ""},

	{"Logging",
		false, 100 * time.Millisecond,
		[]string{"-v", "--log-all", "-A", "127.0.0.1:63081", "-c", "testdata/resolv.conf"},
		[]string{"Starting", "Exiting"}, ""},

	{"Wildcard listen address - may not work on some systems",
		true, time.Millisecond, []string{}, []string{}, ""},

	{"Status report",
		false, 2 * time.Second, []string{"-v", "-i", "1s", "-A", "127.0.0.1:63081"},
		[]string{"Listening: (HTTP on"}, ""},
}

func TestMain(t *testing.T) {
	uid := os.Getuid()
	for tx, tc := range mainTestCases {
		t.Run(fmt.Sprintf("%d %s", tx, tc.description), func(t *testing.T) {
			if tc.needsRoot && uid != 0 {
				t.Skip("Skipping setuid=0 test as not running as root")
				return
			}

			args := append([]string{"trustydns-server"}, tc.args...)
			out := &bytes.Buffer{}
			err := &bytes.Buffer{}
			mainInit(out, err)
			done := make(chan error)
			go func() {
				done <- waitForMainExecute(t, tc.willRunFor)
			}()
			ec := mainExecute(args)
			e := <-done // Get waitForMainExecute results
			if e != nil {
				t.Fatal(e)
			}
			if ec == 0 && tc.willRunFor == 0 {
				t.Error("Non-zero Exit code expected")
			}
			if ec != 0 && tc.willRunFor > 0 {
				t.Error("Zero Exit code expected, not:", ec)
			}

			outStr := out.String()
			errStr := err.String()
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

// waitForMainExecute is a helper routine which makes sure that main mainExecute() function starts up and
// terminates as expected. If not, t.Fatal()
func waitForMainExecute(t *testing.T, howLong time.Duration) error {
	for ix := 0; ix < 10; ix++ { // Wait for up to one second for main to get running
		if mainStarted {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}
	if !mainStarted {
		return fmt.Errorf("mainStarted did not get set after a second for %s", t.Name())
	}
	time.Sleep(howLong)          // Give it the designated time to complete
	stopMain()                   // Then ask it to finished up
	for ix := 0; ix < 10; ix++ { // Wait for up to two seconds for main to terminate
		if mainStopped {
			break
		}
		time.Sleep(time.Millisecond * 200)
	}
	if !mainStopped {
		return fmt.Errorf("mainStopped did not get set two seconds after stopMain() call for %s", t.Name())
	}

	return nil
}

func TestNextInterval(t *testing.T) {
	tt := []struct {
		now      time.Time
		interval time.Duration
		nextIn   time.Duration
	}{
		// mod(01:01:01, minute)++ -> 01:02:00 needs 59s
		{time.Date(2019, 5, 7, 1, 1, 1, 0, time.UTC), time.Minute, time.Second * 59},
		// mod(01:13:58, 15m)++ -> 01:15:00 needs 1m2s
		{time.Date(2019, 5, 7, 1, 13, 58, 0, time.UTC), time.Minute * 15, time.Minute + time.Second*2},
		// mod(01:01:01, hour)++ -> 02:00:00 needs 58m59s
		{time.Date(2019, 5, 7, 1, 1, 1, 0, time.UTC), time.Hour, time.Minute*58 + time.Second*59},
	}

	for tx, tc := range tt {
		t.Run(fmt.Sprintf("%d", tx), func(t *testing.T) {
			nextIn := nextInterval(tc.now, tc.interval)
			if nextIn != tc.nextIn {
				t.Error("nextIn NE:now", tc.now, "Int", tc.interval, "Want", tc.nextIn, "Got", nextIn)
			}
		})
	}
}

// Test that SIGUSR1 causes a stats report
func TestUSR1(t *testing.T) {
	out := &bytes.Buffer{}
	err := &bytes.Buffer{}
	args := []string{"trustydns-server", "-A", "127.0.0.1:60443"}
	mainInit(out, err) // Start up quietly
	go func() {
		stopChannel <- syscall.SIGUSR1
		time.Sleep(time.Millisecond * 200) // Give it time to process
		stopMain()
	}()
	ec := mainExecute(args)
	outStr := out.String()
	errStr := err.String()
	if ec != 0 {
		t.Error("Expected zero exit return, not", ec, errStr)
	}
	if !strings.Contains(outStr, "User1 Listener:") {
		t.Error("Expected 'User1 Listener:', got", outStr)
	}
}
