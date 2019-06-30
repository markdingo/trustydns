package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// We use a bytes.Buffer as stdout, stderr which is shared across multiple go-routines so we need to
// protected it from concurrent access. This is test-only code but -race doesn't know that.
type mutexBytesBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (t *mutexBytesBuffer) Write(p []byte) (n int, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.buffer.Write(p)
}

func (t *mutexBytesBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.buffer.String()
}

//////////////////////////////////////////////////////////////////////

type mainTestCase struct {
	description string
	needsRoot   bool          // Only run if we're setuid 0
	willRunFor  time.Duration // trustydns-proxy should run for this amount of time before being terminated
	args        []string      // ARGV - not counting command
	stdout      []string      // Expected stdout strings
	stderr      string        // Expected stderr string
}

// The -A 255.... arguments are present to cause mainExecute() to fail when it starts *after*
// exercising the code coverage area intended.

var mainTestCases = []mainTestCase{
	{"ecs-set",
		false, 100 * time.Millisecond, []string{"-A", "127.0.0.1:63081", "-v",
			"--ecs-set", "10.0.120.0/24", "http://localhost:63080"}, []string{"Starting"}, ""},

	{"ecs-request-prefix",
		false, 100 * time.Millisecond, []string{"-A", "127.0.0.1:63082", "-v",
			"--ecs-request-ipv4-prefixlen", "20", "--ecs-request-ipv6-prefixlen", "56",
			"http://localhost:63080"}, []string{"Starting"}, ""},

	{"URL mangling", // Silently runs with a mangled URL
		false, 100 * time.Millisecond, []string{"-A", "127.0.0.1:63083", "localhost"}, []string{}, ""},

	{"URL syntax", // Silently runs with a dodgy (but legal) URL
		false, 100 * time.Millisecond, []string{"-A", "127.0.0.1:63084", "///localhost"}, []string{}, ""},

	{"Good URL with scheme",
		false, 100 * time.Millisecond, []string{"-A", "127.0.0.1:63085", "-v", "http://localhost"},
		[]string{"Starting", "Exiting"}, ""},

	{"Good URL No Scheme",
		false, 100 * time.Millisecond, []string{"-g", "-v", "-A", "127.0.0.1:63086", "localhost"},
		[]string{"Starting", "Exiting"}, ""},

	{"Good local resolver config",
		false, 100 * time.Millisecond, []string{"-v", "-A", "127.0.0.1:63087",
			"-c", "testdata/resolv.conf", "http://localhost"},
		[]string{"Starting", "Exiting"}, ""},

	{"log-all",
		false, 100 * time.Millisecond,
		[]string{"-v", "--log-all", "-A", "127.0.0.1:63088",
			"-c", "testdata/resolv.conf", "http://localhost"},
		[]string{"Starting", "Exiting"}, ""},

	{"Wildcard listen address",
		true, 100 * time.Millisecond, []string{"http://localhost"}, []string{}, ""},

	{"Status report",
		false, 2 * time.Second, []string{"-v", "-i", "1s", "-A", "127.0.0.1:63089", "http://localhost"},
		[]string{"Status Server:"}, ""},

	{"CPU Profile",
		false, 100 * time.Millisecond, []string{"-A", "127.0.0.1:63090", "--cpu-profile", "testdata/cpu",
			"http://localhost"}, []string{}, ""},
	{"Mem Profile",
		false, 100 * time.Millisecond, []string{"-A", "127.0.0.1:63091", "--mem-profile", "testdata/mem",
			"http://localhost"}, []string{}, ""},
}

// TestMain tests legitimate usage invocations
func TestMain(t *testing.T) {
	uid := os.Getuid()
	for _, tc := range mainTestCases {
		t.Run(tc.description, func(t *testing.T) {
			if tc.needsRoot && uid != 0 {
				t.Skip("Skipping setuid=0 test as not running as root")
				return
			}
			args := append([]string{"trustydns-proxy"}, tc.args...)
			out := &mutexBytesBuffer{}
			err := &mutexBytesBuffer{}
			mainInit(out, err)
			done := make(chan error)
			go func() {
				done <- waitForMainExecute(t, tc.willRunFor)
			}()
			ec := mainExecute(args)
			e := <-done // Get waitForMainExecute results
			if e != nil {
				t.Log("wfmeO:", out.String())
				t.Log("wfmeE:", err.String())
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
	out := &mutexBytesBuffer{}
	err := &mutexBytesBuffer{}
	args := []string{"trustydns-proxy", "-A", "127.0.0.1:5356", "http://localhost"}
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
	if !strings.Contains(outStr, "User1 Server") {
		t.Error("Expected User1 Server", outStr)
	}
}

// waitForMainExecute is a helper routine which makes sure that main mainExecute() function starts up and
// terminates as expected. If not, t.Fatal()
func waitForMainExecute(t *testing.T, howLong time.Duration) error {
	for ix := 0; ix < 10; ix++ { // Wait for up to two seconds for main to get running
		if isMain(Started) {
			break
		}
		time.Sleep(time.Millisecond * 200)
	}
	if !isMain(Started) {
		return fmt.Errorf("mainStarted did not get set after two seconds")
	}
	time.Sleep(howLong)          // Give it the designated time to complete
	stopMain()                   // Then ask it to finished up
	for ix := 0; ix < 10; ix++ { // Wait for up to two seconds for main to terminate
		if isMain(Stopped) {
			break
		}
		time.Sleep(time.Millisecond * 200)
	}
	if !isMain(Stopped) {
		return fmt.Errorf("mainStopped did not get set two seconds after stopMain() call for %s", t.Name())
	}

	return nil
}
