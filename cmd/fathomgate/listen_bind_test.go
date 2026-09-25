// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Tests of the fixes to the post-merge security review of PR #109 (T0.52)
// in cmd/fathomgate/listen.go: both loopback families bound (H1) and the
// first request's header timeout (L1).

// requireBothLoopbacksEnv, set to 1, turns the skip of a test that needs
// both loopback families into a failure. CI sets it in every Go job, so the
// H1 regression tests cannot pass there by skipping (security review of
// PR #112), as FATHOMGATE_REQUIRE_PRIVILEGED_TESTS does for the Windows
// DACL tests.
const requireBothLoopbacksEnv = "FATHOMGATE_REQUIRE_BOTH_LOOPBACKS"

// loopbackMissing reports the first loopback family this host cannot bind,
// or "" when it has both.
func loopbackMissing() string {
	for _, a := range []string{"127.0.0.1:0", "[::1]:0"} {
		l, err := net.Listen("tcp", a)
		if err != nil {
			return a + " (" + err.Error() + ")"
		}
		_ = l.Close()
	}
	return ""
}

// needBothLoopbacks skips the test on a host that cannot bind both
// 127.0.0.1 and [::1], or fails it when requireBothLoopbacksEnv is 1.
func needBothLoopbacks(t *testing.T) {
	t.Helper()
	if m := loopbackMissing(); m != "" {
		if os.Getenv(requireBothLoopbacksEnv) == "1" {
			t.Fatalf("this host cannot bind %s, and %s=1 requires both loopback families", m, requireBothLoopbacksEnv)
		}
		t.Skipf("this host cannot bind %s; the test needs both loopback families (set %s=1 to fail instead)", m, requireBothLoopbacksEnv)
	}
}

// loopbackFamilies is how many listeners bindLoopback gives on this host:
// 2, or 1 without IPv6 loopback. With requireBothLoopbacksEnv set to 1 a
// missing family fails the test.
func loopbackFamilies(t *testing.T) int {
	t.Helper()
	if m := loopbackMissing(); m != "" {
		if os.Getenv(requireBothLoopbacksEnv) == "1" {
			t.Fatalf("this host cannot bind %s, and %s=1 requires both loopback families", m, requireBothLoopbacksEnv)
		}
		return 1
	}
	return 2
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// portOf is the port of a listener.
func portOf(t *testing.T, l net.Listener) uint16 {
	t.Helper()
	ap, err := netip.ParseAddrPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return ap.Port()
}

// TestBindLoopbackHoldsBothFamilies is the regression test for H1: with the
// listener up on either family (or localhost), binding the other family's
// loopback on the same port fails, as does binding the same one again.
func TestBindLoopbackHoldsBothFamilies(t *testing.T) {
	t.Parallel()
	needBothLoopbacks(t)
	for _, tc := range []struct{ flag, first, second string }{
		{"localhost:0", "127.0.0.1", "::1"},
		{"127.0.0.1:0", "127.0.0.1", "::1"},
		{"[::1]:0", "::1", "127.0.0.1"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			t.Parallel()
			a, err := parseListenAddr(tc.flag)
			if err != nil {
				t.Fatal(err)
			}
			lns, err := bindLoopback(a, listenTCP, holdWildcards, discardLogger())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				for _, l := range lns {
					_ = l.Close()
				}
			}()
			if len(lns) != 2 {
				t.Fatalf("%d listeners, want 2", len(lns))
			}
			port := portOf(t, lns[0])
			for i, want := range []string{tc.first, tc.second} {
				if got := netip.MustParseAddrPort(lns[i].Addr().String()); got.Addr().String() != want || got.Port() != port {
					t.Fatalf("listener %d on %s, want %s port %d", i, got, want, port)
				}
			}
			for _, host := range []string{"127.0.0.1", "::1"} {
				addr := netip.AddrPortFrom(netip.MustParseAddr(host), port).String()
				if l, err := net.Listen("tcp", addr); err == nil {
					_ = l.Close()
					t.Errorf("%s could be bound while fathomgate listens on it", addr)
				}
			}
		})
	}
}

// squatAttempts bounds how many squatter ports a test tries before it
// gives up on finding one whose other family's address is free.
//
// A test that makes a squatter hold one loopback family on an OS-chosen
// port, then points bindLoopback or serve at that port, needs the other
// family's address on it to be free. The OS picked the port as free for
// the squatter's family only; any other socket, of a test running in
// parallel in this binary, of another package's test binary (go test ./...
// runs them side by side) or of any other program on the host, may already
// hold the other family's address on it, or take it at any moment. macOS
// hands out ephemeral ports in sequence per family, so a port just picked
// for [::1] is often the next one picked for 127.0.0.1. Such a collision
// says nothing about fathomgate: the test sees it (the first bind fails,
// before the refusal under test is reached) and tries a new port.
const squatAttempts = 50

// bindRecorder gives bindLoopback listenTCP and a holdFunc that record
// every socket they bind, so a test can check that bindLoopback released
// each one. The listeners are returned unwrapped. It sees only the sockets
// bound through the listenFunc and holdFunc it injects, nothing else.
type bindRecorder struct {
	mu    sync.Mutex
	binds []recordedBind
	holds []*recordedHold
}

// recordedBind is one call of bindRecorder.listen.
type recordedBind struct {
	addr string
	l    net.Listener // nil when the bind failed
	err  error
}

// recordedHold is what one successful call of the recorded holdFunc held.
type recordedHold struct {
	c      io.Closer
	mu     sync.Mutex
	closes int
	err    error
}

// Close closes what the holdFunc held and records the call and its error.
func (h *recordedHold) Close() error {
	err := h.c.Close()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closes++
	h.err = errors.Join(h.err, err)
	return err
}

func (r *bindRecorder) listen(network, address string) (net.Listener, error) {
	l, err := listenTCP(network, address)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.binds = append(r.binds, recordedBind{addr: address, l: l, err: err})
	return l, err
}

// hold wraps h (nil stays nil) so that what it holds is recorded.
func (r *bindRecorder) hold(h holdFunc) holdFunc {
	if h == nil {
		return nil
	}
	return func(port uint16) (io.Closer, error) {
		c, err := h(port)
		if err != nil || c == nil {
			return c, err
		}
		rh := &recordedHold{c: c}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.holds = append(r.holds, rh)
		return rh, nil
	}
}

// recorded is a copy of the binds so far.
func (r *bindRecorder) recorded() []recordedBind {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedBind(nil), r.binds...)
}

// socketClosed reports whether l's socket is closed. Go's Close returns
// only after the close system call (poll.FD.Close waits for it), so a
// closed descriptor is a socket the OS has released: a listening socket
// with no connections leaves no TIME_WAIT behind.
func socketClosed(t *testing.T, l net.Listener) bool {
	t.Helper()
	sc, ok := l.(syscall.Conn)
	if !ok {
		t.Fatalf("listener is %T, want a syscall.Conn", l)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	err = rc.Control(func(uintptr) {})
	if err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("%s: %v, want nil or net.ErrClosed", l.Addr(), err)
	}
	return err != nil
}

// checkReleased fails t unless every socket bound through r is closed:
// each listener's descriptor, and each hold, closed once without error.
//
// It stands in for binding the address again after the refusal, which
// cannot tell a socket fathomgate leaked from one another test bound on
// the freed port in between (squatAttempts), and so failed at random on
// macOS and Linux. This asks the sockets fathomgate bound themselves.
func (r *bindRecorder) checkReleased(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.binds {
		if b.l != nil && !socketClosed(t, b.l) {
			t.Errorf("%s is still bound: bindLoopback did not close it", b.addr)
		}
	}
	for i, h := range r.holds {
		h.mu.Lock()
		if h.closes != 1 || h.err != nil {
			t.Errorf("hold %d closed %d times (error %v), want once without error", i, h.closes, h.err)
		}
		h.mu.Unlock()
	}
}

// TestBindLoopbackRefusesTakenOtherFamily: when another program holds the
// other family's loopback on the port asked for, bindLoopback refuses and
// leaves nothing bound: the first family's socket it bound is closed.
func TestBindLoopbackRefusesTakenOtherFamily(t *testing.T) {
	t.Parallel()
	needBothLoopbacks(t)
	for _, tc := range []struct{ squat, flagHost string }{
		{"[::1]:0", "127.0.0.1"},
		{"[::1]:0", "localhost"},
		{"127.0.0.1:0", "[::1]"},
	} {
		t.Run(tc.flagHost, func(t *testing.T) {
			t.Parallel()
			for attempt := 1; ; attempt++ {
				if refusesTakenOtherFamily(t, tc.squat, tc.flagHost) {
					return
				}
				if attempt == squatAttempts {
					t.Fatalf("%d squatter ports on %s all had %s's address taken by another socket", squatAttempts, tc.squat, tc.flagHost)
				}
			}
		})
	}
}

// refusesTakenOtherFamily is one attempt of
// TestBindLoopbackRefusesTakenOtherFamily. It returns false when the first
// family's address on the squatter's port was already in use by another
// socket (squatAttempts); any other failure of that bind fails the test.
// Every return checks that what bindLoopback bound was released.
func refusesTakenOtherFamily(t *testing.T, squat, flagHost string) bool {
	t.Helper()
	squatter, err := net.Listen("tcp", squat)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = squatter.Close() }()
	port := portOf(t, squatter)
	a, err := parseListenAddr(flagHost + ":" + strconv.Itoa(int(port)))
	if err != nil {
		t.Fatal(err)
	}
	rec := &bindRecorder{}
	defer rec.checkReleased(t)
	lns, err := bindLoopback(a, rec.listen, rec.hold(holdWildcards), discardLogger())
	if err == nil {
		for _, l := range lns {
			_ = l.Close()
		}
		t.Fatalf("bound %d listeners next to a program holding %s", len(lns), squatter.Addr())
	}
	binds := rec.recorded()
	first := netip.AddrPortFrom(a.host, port).String()
	if len(binds) == 1 && binds[0].addr == first && binds[0].err != nil {
		if !addrTaken(binds[0].err) {
			t.Fatalf("binding %s: %v, want success or address in use", first, binds[0].err)
		}
		t.Logf("another socket holds %s; trying another port: %v", first, binds[0].err)
		return false
	}
	want := squatter.Addr().String() + ", the other loopback address on the same port, cannot be bound"
	if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "refuses to start") {
		t.Fatalf("error %q, want it to contain %q", err, want)
	}
	// The first family was bound, then released; the other was refused.
	if len(binds) != 2 || binds[0].addr != first || binds[0].err != nil || binds[1].addr != squatter.Addr().String() || binds[1].err == nil || len(rec.holds) != 0 {
		t.Fatalf("binds %+v, holds %d; want %s bound, then %s refused, and nothing held", binds, len(rec.holds), first, squatter.Addr())
	}
	return true
}

// TestServeListenOtherFamilyTaken: serve exits 1 before the upstream starts
// (it does not exist, and its error would say so) when the other family's
// loopback is taken on the --listen port, naming that address and no
// token.
func TestServeListenOtherFamilyTaken(t *testing.T) {
	t.Parallel()
	needBothLoopbacks(t)
	for attempt := 1; ; attempt++ {
		if serveListenOtherFamilyTaken(t) {
			return
		}
		if attempt == squatAttempts {
			t.Fatalf("%d squatter ports on [::1] all had 127.0.0.1's address taken by another socket", squatAttempts)
		}
	}
}

// serveListenOtherFamilyTaken is one attempt of
// TestServeListenOtherFamilyTaken. It returns false when serve's first
// bind, of 127.0.0.1 on the squatter's port, found it taken by another
// socket (squatAttempts).
func serveListenOtherFamilyTaken(t *testing.T) bool {
	t.Helper()
	squatter, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = squatter.Close() }()
	port := strconv.Itoa(int(portOf(t, squatter)))
	var stderr lockedBuffer
	code := serveContext(t.Context(), []string{
		"--server", "netdev-ssh-mcp", "--upstream", filepath.Join(t.TempDir(), "no-such-upstream"), "--no-policy",
		"--listen", "localhost:" + port,
	}, &stderr, envMap(map[string]string{listenTokenEnv: testListenToken}))
	out := stderr.String()
	checkNoCanary(t, "stderr", out)
	if code == exitFail && strings.Contains(out, "fathomgate: serve: --listen: listen tcp 127.0.0.1:"+port+":") {
		t.Logf("another socket holds 127.0.0.1:%s; trying another port", port)
		return false
	}
	if code != exitFail || !strings.Contains(out, "fathomgate: serve: --listen: [::1]:"+port+", the other loopback address") || strings.Contains(out, "no-such-upstream") {
		t.Fatalf("exit %d; stderr %q", code, out)
	}
	return true
}

// fakeListener is a listener that accepts nothing, for bindLoopback's
// injected binds.
type fakeListener struct {
	addr   netip.AddrPort
	noTCP  bool // Addr is not a *net.TCPAddr
	mu     sync.Mutex
	closed bool
}

func (f *fakeListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }

func (f *fakeListener) Addr() net.Addr {
	if f.noTCP {
		return &net.UnixAddr{Name: "fake", Net: "unix"}
	}
	return net.TCPAddrFromAddrPort(f.addr)
}
func (f *fakeListener) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeListener) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// countCloser counts Close calls.
type countCloser struct {
	mu sync.Mutex
	n  int
}

func (c *countCloser) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return nil
}

func (c *countCloser) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// TestBindLoopbackHoldInjected: bindLoopback's handling of the wildcard
// hold (M1-27), with every bind injected. The hold runs on the port both
// loopbacks were bound on; its failure closes the loopbacks and refuses,
// naming what it names, after retrying on new ports for port 0; what it
// holds is closed once, by whichever listener closes first.
func TestBindLoopbackHoldInjected(t *testing.T) {
	t.Parallel()
	errHeld := errors.New("0.0.0.0:8931, a wildcard address on the same port, cannot be held (bind: in use)")
	for _, tc := range []struct {
		name     string
		flag     string
		failures int    // holds that fail before one succeeds
		want     string // error substring; "" binds
		holds    int
	}{
		{name: "held", flag: "localhost:8931", holds: 1},
		{name: "wildcard taken, fixed port", flag: "localhost:8931", failures: 1, want: errHeld.Error() + "; fathomgate refuses to start", holds: 1},
		{name: "wildcard taken once, port 0", flag: "localhost:0", failures: 1, holds: 2},
		{name: "wildcard always taken, port 0", flag: "localhost:0", failures: 1 << 30, want: "cannot be held", holds: bindAttempts},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := parseListenAddr(tc.flag)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var all []*fakeListener
			next := uint16(40000)
			listen := func(_, address string) (net.Listener, error) {
				mu.Lock()
				defer mu.Unlock()
				ap := netip.MustParseAddrPort(address)
				if ap.Port() == 0 {
					next++
					ap = netip.AddrPortFrom(ap.Addr(), next)
				}
				f := &fakeListener{addr: ap}
				all = append(all, f)
				return f, nil
			}
			held := &countCloser{}
			holds := 0
			hold := func(port uint16) (io.Closer, error) {
				mu.Lock()
				defer mu.Unlock()
				holds++
				if want := all[len(all)-1].addr.Port(); port != want {
					t.Errorf("hold on port %d, want %d", port, want)
				}
				if holds <= tc.failures {
					return nil, errHeld
				}
				return held, nil
			}
			lns, err := bindLoopback(a, listen, hold, discardLogger())
			if holds != tc.holds {
				t.Errorf("%d holds, want %d", holds, tc.holds)
			}
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error %v, want %q", err, tc.want)
				}
				for _, f := range all {
					if !f.isClosed() {
						t.Errorf("%s left bound after the refusal", f.addr)
					}
				}
				return
			}
			if err != nil || len(lns) != 2 {
				t.Fatalf("%d listeners, %v; want 2", len(lns), err)
			}
			for _, f := range all[:len(all)-2] {
				if !f.isClosed() {
					t.Errorf("%s from a failed attempt left bound", f.addr)
				}
			}
			if held.count() != 0 {
				t.Fatal("the hold was closed while the listeners are open")
			}
			for _, l := range lns {
				_ = l.Close()
			}
			if held.count() != 1 {
				t.Errorf("the hold was closed %d times, want 1", held.count())
			}
			for _, f := range all[len(all)-2:] {
				if !f.isClosed() {
					t.Errorf("%s left bound after Close", f.addr)
				}
			}
		})
	}
}

// TestBindLoopbackInjected: bindLoopback's decisions, with every bind
// injected. The first family always binds (port 0 gets 40001, 40002, ...);
// otherErr decides the second bind of each attempt.
func TestBindLoopbackInjected(t *testing.T) {
	t.Parallel()
	errInUse := errors.New("bind: address already in use")
	for _, tc := range []struct {
		name     string
		flag     string
		otherErr func(attempt int) error
		noTCP    bool   // the first listener's Addr names no TCP port
		skip     bool   // no family-missing error on this platform
		want     string // error substring; "" binds
		wantN    int    // listeners returned
		attempts int
		warns    bool
	}{
		{name: "both bind", flag: "127.0.0.1:8931", otherErr: func(int) error { return nil }, wantN: 2, attempts: 1},
		{name: "IPv6 asked", flag: "[::1]:8931", otherErr: func(int) error { return nil }, wantN: 2, attempts: 1},
		{name: "other in use, fixed port", flag: "127.0.0.1:8931", otherErr: func(int) error { return errInUse }, want: "[::1]:8931, the other loopback address on the same port, cannot be bound (bind: address already in use); fathomgate refuses to start", attempts: 1},
		{name: "IPv4 in use, fixed port", flag: "[::1]:8931", otherErr: func(int) error { return errInUse }, want: "127.0.0.1:8931, the other loopback address", attempts: 1},
		{name: "other in use once, port 0", flag: "localhost:0", otherErr: func(n int) error {
			if n == 1 {
				return errInUse
			}
			return nil
		}, wantN: 2, attempts: 2},
		{name: "other always in use, port 0", flag: "localhost:0", otherErr: func(int) error { return errInUse }, want: "cannot be bound", attempts: bindAttempts},
		{name: "first listener names no port", flag: "127.0.0.1:0", otherErr: func(int) error { return nil }, noTCP: true, want: "cannot tell which port 127.0.0.1:0 was bound on", attempts: 1},
		{name: "no loopback of the other family", flag: "127.0.0.1:8931", otherErr: func(int) error { return errFamilyMissing }, skip: errFamilyMissing == nil, wantN: 1, attempts: 1, warns: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.skip {
				t.Skip("no loopback-family error on this platform")
			}
			a, err := parseListenAddr(tc.flag)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var firsts []*fakeListener
			attempt, next := 0, uint16(40000)
			listen := func(_, address string) (net.Listener, error) {
				mu.Lock()
				defer mu.Unlock()
				ap := netip.MustParseAddrPort(address)
				if ap.Addr() == a.host {
					attempt++
					if ap.Port() == 0 {
						next++
						ap = netip.AddrPortFrom(ap.Addr(), next)
					}
					f := &fakeListener{addr: ap, noTCP: tc.noTCP}
					firsts = append(firsts, f)
					return f, nil
				}
				if ap.Addr() != a.other() || ap.Port() != firsts[len(firsts)-1].addr.Port() {
					t.Errorf("second bind on %s, want %s on the first's port", ap, a.other())
				}
				if err := tc.otherErr(attempt); err != nil {
					return nil, &net.OpError{Op: "listen", Net: "tcp", Err: err}
				}
				return &fakeListener{addr: ap}, nil
			}
			var logs lockedBuffer
			lns, err := bindLoopback(a, listen, nil, slog.New(slog.NewTextHandler(&logs, nil)))
			if attempt != tc.attempts {
				t.Errorf("%d attempts, want %d", attempt, tc.attempts)
			}
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error %v, want %q", err, tc.want)
				}
				for _, f := range firsts {
					if !f.isClosed() {
						t.Errorf("%s left bound after the refusal", f.addr)
					}
				}
				return
			}
			if err != nil || len(lns) != tc.wantN {
				t.Fatalf("%d listeners, %v; want %d", len(lns), err, tc.wantN)
			}
			if lns[0] != firsts[len(firsts)-1] {
				t.Errorf("the first listener is not the address asked for")
			}
			for _, f := range firsts[:len(firsts)-1] {
				if !f.isClosed() {
					t.Errorf("%s from a failed attempt left bound", f.addr)
				}
			}
			if got := strings.Contains(logs.String(), "no loopback address of the other family"); got != tc.warns {
				t.Errorf("warning logged %v, want %v:\n%s", got, tc.warns, logs.String())
			}
		})
	}
}

// fakeTimer records Stop; fire runs the function it was started with.
type fakeTimer struct {
	mu      sync.Mutex
	d       time.Duration
	f       func()
	stopped int
}

func (ft *fakeTimer) Stop() bool {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.stopped++
	return true
}

func (ft *fakeTimer) stops() int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return ft.stopped
}

// TestFirstRequestTimer (L1 in the security review of PR #109; S2 in the
// Go review of PR #112): each accepted connection gets a timer of
// firstHeader from ConnContext that closes it; the first request to reach
// the handler, which net/http calls once the headers are read, stops it
// before the handler runs, so a slow body is not timed; later requests do
// not touch it. With firstHeader 0 there is no timer. No clock involved.
func TestFirstRequestTimer(t *testing.T) {
	t.Parallel()
	const firstHeader = 3 * time.Second
	var timers []*fakeTimer
	var stoppedAtEntry []int
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		stoppedAtEntry = append(stoppedAtEntry, timers[len(timers)-1].stops())
	})
	srv := newHTTPServer(h, io.NopCloser(nil), shutdownGrace, nil)
	if srv.firstHeader != firstHeaderTimeout || srv.ConnContext == nil {
		t.Fatalf("first-request timer %v, hook set %v", srv.firstHeader, srv.ConnContext != nil)
	}
	srv.firstHeader = firstHeader
	srv.afterFunc = func(d time.Duration, f func()) stopper {
		ft := &fakeTimer{d: d, f: f}
		timers = append(timers, ft)
		return ft
	}

	t.Run("silent connection is closed when the timer fires", func(t *testing.T) {
		server, client := net.Pipe()
		defer func() { _ = client.Close() }()
		_ = srv.ConnContext(context.Background(), server)
		ft := timers[len(timers)-1]
		if ft.d != firstHeader {
			t.Fatalf("timer of %v, want %v", ft.d, firstHeader)
		}
		ft.f()
		if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("the connection is still open after the timer fired: %v", err)
		}
	})
	t.Run("first request stops the timer before the handler, once", func(t *testing.T) {
		server, client := net.Pipe()
		defer func() { _ = client.Close(); _ = server.Close() }()
		ctx := srv.ConnContext(context.Background(), server)
		ft := timers[len(timers)-1]
		stoppedAtEntry = nil
		for range 2 {
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader("{}"))
			srv.Handler.ServeHTTP(httptest.NewRecorder(), req)
		}
		if len(stoppedAtEntry) != 2 || stoppedAtEntry[0] != 1 || ft.stops() != 1 {
			t.Fatalf("stops seen by the handler %v, total %d; want [1 1], 1", stoppedAtEntry, ft.stops())
		}
	})
	t.Run("no timer when turned off", func(t *testing.T) {
		n := len(timers)
		srv.firstHeader = 0
		defer func() { srv.firstHeader = firstHeader }()
		server, client := net.Pipe()
		defer func() { _ = client.Close(); _ = server.Close() }()
		ctx := srv.ConnContext(context.Background(), server)
		if len(timers) != n || ctx.Value(firstRequestKey{}) != nil {
			t.Fatal("a timer was started with firstHeader 0")
		}
	})
}

// TestFirstHeaderTimeoutSmoke: the same through a real socket, with wide
// bounds. A connection that sends nothing, or half a header, is closed
// well before readHeaderTimeout.
func TestFirstHeaderTimeoutSmoke(t *testing.T) {
	t.Parallel()
	const firstHeader = 200 * time.Millisecond
	srv := newHTTPServer(http.NotFoundHandler(), io.NopCloser(nil), shutdownGrace, nil)
	srv.firstHeader = firstHeader
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(limitListener(inner, 4)) }()
	defer func() {
		_ = srv.Close()
		<-served
	}()
	for _, partial := range []string{"", "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n"} {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_, _ = io.WriteString(c, partial)
		_ = c.SetReadDeadline(time.Now().Add(readHeaderTimeout))
		_, _ = io.Copy(io.Discard, c) // ends when the server closes it
		d := time.Since(start)
		_ = c.Close()
		if d >= readHeaderTimeout/2 {
			t.Errorf("sent %q: closed after %v, want about %v", partial, d, firstHeader)
		}
	}
}

// TestLimitListenersShareSlots: the connection cap is shared by the
// listeners of both loopback families. Each listener accepts once: with a
// loop, the listener that just accepted could take the freed slot again
// and starve the other (B1 in the Go review of PR #112).
func TestLimitListenersShareSlots(t *testing.T) {
	t.Parallel()
	inners := make([]net.Listener, 0, 2)
	for range 2 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		inners = append(inners, l)
	}
	ls := limitListeners(inners, 1)
	accepted := make(chan net.Conn, 2)
	var wg sync.WaitGroup
	for _, l := range ls {
		wg.Go(func() {
			if c, err := l.Accept(); err == nil {
				accepted <- c
			}
		})
	}
	clients := make([]net.Conn, 0, len(inners))
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()
	for _, l := range inners {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
	}
	first := <-accepted
	// A negative check, as in TestLimitListener: the second connection is
	// already dialled, so a cap per listener would accept it at once.
	select {
	case c := <-accepted:
		_ = c.Close()
		t.Fatal("the second listener accepted past the shared cap")
	case <-time.After(100 * time.Millisecond):
	}
	_ = first.Close()
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("closing a connection did not free the shared slot")
	}
	for _, l := range ls {
		_ = l.Close()
	}
	wg.Wait()
}

// TestLimitedConnCloseWrite: CloseWrite reaches the TCP connection, so the
// peer reads EOF while the connection stays open for reading (the FIN
// net/http sends after a Connection: close answer).
func TestLimitedConnCloseWrite(t *testing.T) {
	t.Parallel()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := limitListener(inner, 1)
	defer func() { _ = l.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	c := <-accepted
	defer func() { _ = c.Close() }()
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("limitedConn has no CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := client.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read %d, %v after CloseWrite; want EOF", n, err)
	}
}
