// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests of the fixes to the post-merge security review of PR #109 (T0.52)
// in cmd/fathomgate/listen.go: both loopback families bound (H1) and the
// first request's header timeout (L1).

// needBothLoopbacks skips the test on a host that cannot bind both
// 127.0.0.1 and [::1]. CI's Linux, macOS and Windows runners have both.
func needBothLoopbacks(t *testing.T) {
	t.Helper()
	for _, a := range []string{"127.0.0.1:0", "[::1]:0"} {
		l, err := net.Listen("tcp", a)
		if err != nil {
			t.Skipf("this host cannot bind %s (%v); the test needs both loopback families", a, err)
		}
		_ = l.Close()
	}
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
			lns, err := bindLoopback(a, net.Listen, discardLogger())
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

// TestBindLoopbackRefusesTakenOtherFamily: when another program holds the
// other family's loopback on the port asked for, bindLoopback refuses and
// leaves nothing bound.
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
			squatter, err := net.Listen("tcp", tc.squat)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = squatter.Close() }()
			port := portOf(t, squatter)
			a, err := parseListenAddr(tc.flagHost + ":" + strconv.Itoa(int(port)))
			if err != nil {
				t.Fatal(err)
			}
			lns, err := bindLoopback(a, net.Listen, discardLogger())
			if err == nil {
				for _, l := range lns {
					_ = l.Close()
				}
				t.Fatalf("bound %d listeners next to a program holding %s", len(lns), squatter.Addr())
			}
			want := squatter.Addr().String() + ", the other loopback address on the same port, cannot be bound"
			if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "refuses to start") {
				t.Fatalf("error %q, want it to contain %q", err, want)
			}
			// The first family was released.
			l, err := net.Listen("tcp", netip.AddrPortFrom(a.host, port).String())
			if err != nil {
				t.Fatalf("the address asked for is still bound after the refusal: %v", err)
			}
			_ = l.Close()
		})
	}
}

// TestServeListenOtherFamilyTaken: serve exits 1 before the upstream starts
// (it does not exist, and its error would say so) when the other family's
// loopback is taken on the --listen port, naming that address and no
// token.
func TestServeListenOtherFamilyTaken(t *testing.T) {
	t.Parallel()
	needBothLoopbacks(t)
	squatter, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = squatter.Close() }()
	port := strconv.Itoa(int(portOf(t, squatter)))
	var stderr lockedBuffer
	code := serveContext(t.Context(), []string{
		"--server", "netdev-ssh-mcp", "--upstream", filepath.Join(t.TempDir(), "no-such-upstream"),
		"--listen", "localhost:" + port,
	}, &stderr, envMap(map[string]string{listenTokenEnv: testListenToken}))
	out := stderr.String()
	if code != exitFail || !strings.Contains(out, "fathomgate: serve: --listen: [::1]:"+port+", the other loopback address") || strings.Contains(out, "no-such-upstream") {
		t.Fatalf("exit %d; stderr %q", code, out)
	}
	checkNoCanary(t, "stderr", out)
}

// fakeListener is a listener that accepts nothing, for bindLoopback's
// injected binds.
type fakeListener struct {
	addr   netip.AddrPort
	mu     sync.Mutex
	closed bool
}

func (f *fakeListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (f *fakeListener) Addr() net.Addr            { return net.TCPAddrFromAddrPort(f.addr) }
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
		skip     bool   // no family-missing error on this platform
		want     string // error substring; "" binds
		wantN    int    // listeners returned
		attempts int
		warns    bool
	}{
		{name: "both bind", flag: "127.0.0.1:8931", otherErr: func(int) error { return nil }, wantN: 2, attempts: 1},
		{name: "IPv6 asked", flag: "[::1]:8931", otherErr: func(int) error { return nil }, wantN: 2, attempts: 1},
		{name: "other in use, fixed port", flag: "127.0.0.1:8931", otherErr: func(int) error { return errInUse }, want: "[::1]:8931, the other loopback address on the same port, cannot be bound (listen tcp: bind: address already in use); fathomgate refuses to start", attempts: 1},
		{name: "IPv4 in use, fixed port", flag: "[::1]:8931", otherErr: func(int) error { return errInUse }, want: "127.0.0.1:8931, the other loopback address", attempts: 1},
		{name: "other in use once, port 0", flag: "localhost:0", otherErr: func(n int) error {
			if n == 1 {
				return errInUse
			}
			return nil
		}, wantN: 2, attempts: 2},
		{name: "other always in use, port 0", flag: "localhost:0", otherErr: func(int) error { return errInUse }, want: "cannot be bound", attempts: bindAttempts},
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
					f := &fakeListener{addr: ap}
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
			lns, err := bindLoopback(a, listen, slog.New(slog.NewTextHandler(&logs, nil)))
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

// TestFirstHeaderTimeout (L1 in the security review of PR #109): a
// connection that sends nothing is closed firstHeader after it was
// accepted, not after readHeaderTimeout, so a client without a token holds
// a connection slot that long at most. A connection that sent its first
// request in time keeps readHeaderTimeout and IdleTimeout for later ones.
func TestFirstHeaderTimeout(t *testing.T) {
	t.Parallel()
	const firstHeader = 300 * time.Millisecond
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	srv := newHTTPServer(h, io.NopCloser(nil), shutdownGrace, nil)
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(limitListener(inner, 4, firstHeader)) }()
	// Cleanup, not defer: the parallel subtests run after this function
	// returns.
	t.Cleanup(func() {
		_ = srv.Close()
		<-served
	})
	addr := inner.Addr().String()

	t.Run("silent connection", func(t *testing.T) {
		t.Parallel()
		for _, partial := range []string{"", "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n"} {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			_, _ = io.WriteString(c, partial)
			_ = c.SetReadDeadline(time.Now().Add(readHeaderTimeout))
			_, _ = io.Copy(io.Discard, c) // ends when the server closes it
			d := time.Since(start)
			_ = c.Close()
			if d < firstHeader-50*time.Millisecond || d >= readHeaderTimeout/2 {
				t.Errorf("sent %q: closed after %v, want about %v", partial, d, firstHeader)
			}
		}
	})
	t.Run("later requests keep the usual timeouts", func(t *testing.T) {
		t.Parallel()
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		br := bufio.NewReader(c)
		for i := range 2 {
			if _, err := fmt.Fprintf(c, "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"); err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || resp.Close {
				t.Fatalf("request %d: status %d, close %v", i, resp.StatusCode, resp.Close)
			}
			// Idle past firstHeader: the kept-alive connection must survive.
			time.Sleep(2 * firstHeader)
		}
	})
}

// TestLimitListenersShareSlots: the connection cap is shared by the
// listeners of both loopback families.
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
	ls := limitListeners(inners, 1, 0)
	accepted := make(chan net.Conn, 2)
	var wg sync.WaitGroup
	for _, l := range ls {
		wg.Go(func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
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
