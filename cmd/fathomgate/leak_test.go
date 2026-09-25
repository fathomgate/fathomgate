// SPDX-License-Identifier: Apache-2.0

package main

import (
	"runtime"
	"strings"
	"time"
)

// A stdlib goroutine-leak check, as internal/proxy's (goleak would be a new
// dependency). After all tests, no goroutine may still run code from
// go-sdk, internal/proxy, an HTTP server or this command: the listener's
// server, its shutdown hook and the proxy it closes must all have ended.
// Runtime and testing goroutines do not match. The calling goroutine
// (TestMain) is skipped.

// leakMarkers identify goroutines serve is responsible for. Functions of
// package main appear as "main." at the start of a stack line.
var leakMarkers = []string{
	"github.com/modelcontextprotocol/go-sdk/",
	"github.com/fathomgate/fathomgate/internal/proxy.",
	"net/http.(*Server)",
	"net/http.(*conn).serve",
	"os/exec.(*Cmd).",
	"\nmain.",
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

// waitForLeaks polls until no such goroutine is left or d has passed, and
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
