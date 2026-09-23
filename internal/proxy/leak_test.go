package proxy

import (
	"runtime"
	"strings"
	"time"
)

// A stdlib goroutine-leak check (goleak would be a new dependency). After all
// tests, every goroutine whose stack runs code from go-sdk or this package
// must have ended. Runtime and testing goroutines are ignored because they do
// not match. The calling goroutine (TestMain) is skipped.

// leakMarkers identify goroutines the proxy is responsible for.
var leakMarkers = []string{
	"github.com/modelcontextprotocol/go-sdk/",
	"github.com/joshscott13/netguard/internal/proxy.",
	"os/exec.(*Cmd).",
}

// leakedGoroutines returns the stacks of live goroutines that match
// leakMarkers, other than the caller's.
func leakedGoroutines() []string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	stacks := strings.Split(string(buf), "\n\n")
	var leaks []string
	for _, s := range stacks[1:] { // stacks[0] is the calling goroutine
		for _, m := range leakMarkers {
			if strings.Contains(s, m) {
				leaks = append(leaks, s)
				break
			}
		}
	}
	return leaks
}

// waitForLeaks polls until no proxy goroutine is left or d has passed, and
// returns what is still running.
func waitForLeaks(d time.Duration) []string {
	deadline := time.Now().Add(d)
	for {
		leaks := leakedGoroutines()
		if len(leaks) == 0 || time.Now().After(deadline) {
			return leaks
		}
		time.Sleep(20 * time.Millisecond)
	}
}
