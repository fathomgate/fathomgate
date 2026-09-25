// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// errFamilyMissing is the bind error of a host without IPv6.
var errFamilyMissing error = os.NewSyscallError("bind", windows.WSAEADDRNOTAVAIL)

func TestLoopbackFamilyMissingWindows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		errno syscall.Errno
		want  bool
	}{
		{windows.WSAEADDRNOTAVAIL, true},
		{windows.WSAEAFNOSUPPORT, true},
		{windows.WSAEPROTONOSUPPORT, true},
		// Must refuse to start.
		{windows.WSAEADDRINUSE, false},
		{windows.WSAEACCES, false},
	} {
		t.Run(tc.errno.Error(), func(t *testing.T) {
			t.Parallel()
			if got := loopbackFamilyMissing(os.NewSyscallError("bind", tc.errno)); got != tc.want {
				t.Fatalf("loopbackFamilyMissing %v, want %v", got, tc.want)
			}
		})
	}
}

// listenReuseAddr binds and listens on addr with SO_REUSEADDR set before
// bind: the squatting technique SO_EXCLUSIVEADDRUSE exists to stop.
func listenReuseAddr(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(context.Background(), "tcp", addr)
}

// exclusiveAddrUse reads SO_EXCLUSIVEADDRUSE from a listener's socket.
func exclusiveAddrUse(t *testing.T, l net.Listener) int {
	t.Helper()
	tl, ok := l.(*net.TCPListener)
	if !ok {
		t.Fatalf("listener is %T, want *net.TCPListener", l)
	}
	rc, err := tl.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		v, gerr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatalf("getsockopt SO_EXCLUSIVEADDRUSE: %v", gerr)
	}
	return v
}

// TestBindLoopbackExclusiveWindows is the regression test for M1-27: every
// socket bindLoopback binds through listenTCP carries SO_EXCLUSIVEADDRUSE,
// and while fathomgate holds its addresses no other socket can bind either
// of them, with SO_REUSEADDR (the squatting technique) or without. The
// residual is logged, not asserted: a wildcard bind of the same port still
// succeeds on Windows, and when it does the agents' loopback connections
// must still reach fathomgate while it runs.
func TestBindLoopbackExclusiveWindows(t *testing.T) {
	t.Parallel()
	needBothLoopbacks(t)
	for _, flag := range []string{"localhost:0", "[::1]:0"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()
			a, err := parseListenAddr(flag)
			if err != nil {
				t.Fatal(err)
			}
			lns, err := bindLoopback(a, listenTCP, discardLogger())
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
			for _, l := range lns {
				if v := exclusiveAddrUse(t, l); v != 1 {
					t.Errorf("%s: SO_EXCLUSIVEADDRUSE is %d, want 1", l.Addr(), v)
				}
			}
			for _, host := range []string{"127.0.0.1", "::1"} {
				addr := netip.AddrPortFrom(netip.MustParseAddr(host), port).String()
				for name, listen := range map[string]listenFunc{"SO_REUSEADDR": func(_, a string) (net.Listener, error) { return listenReuseAddr(a) }, "no options": net.Listen} {
					l, err := listen("tcp", addr)
					if err == nil {
						_ = l.Close()
						t.Errorf("%s could be bound (%s) while fathomgate listens on it", addr, name)
						continue
					}
					if !errors.Is(err, windows.WSAEACCES) && !errors.Is(err, windows.WSAEADDRINUSE) {
						t.Errorf("bind %s (%s): %v, want WSAEACCES or WSAEADDRINUSE", addr, name, err)
					}
				}
			}
			for _, wild := range []string{"0.0.0.0", "::"} {
				addr := netip.AddrPortFrom(netip.MustParseAddr(wild), port).String()
				squatter, err := listenReuseAddr(addr)
				if err != nil {
					t.Logf("residual: a wildcard bind of %s is refused on this host: %v", addr, err)
					continue
				}
				t.Logf("residual: a wildcard bind of %s succeeds on this host (docs/security/threat-model.md, port squatting row)", addr)
				for _, l := range lns {
					if err := reachesFathomgate(l, squatter); err != nil {
						t.Errorf("with %s bound, a connection to %s: %v", addr, l.Addr(), err)
					}
				}
				_ = squatter.Close()
			}
		})
	}
}

// reachesFathomgate dials fg's address and checks that fg, not squatter,
// accepts the connection.
func reachesFathomgate(fg, squatter net.Listener) error {
	c, err := net.DialTimeout("tcp", fg.Addr().String(), 5*time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	// A squatter that accepts it has taken the connection.
	if err := squatter.(*net.TCPListener).SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		return err
	}
	if sc, err := squatter.Accept(); err == nil {
		_ = sc.Close()
		return errors.New("the wildcard socket accepted it")
	}
	if err := fg.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	defer func() { _ = fg.(*net.TCPListener).SetDeadline(time.Time{}) }()
	fc, err := fg.Accept()
	if err != nil {
		return err
	}
	return fc.Close()
}

// fakeRawConn is a syscall.RawConn whose socket handle is invalid.
type fakeRawConn struct{}

func (fakeRawConn) Control(f func(fd uintptr)) error  { f(uintptr(windows.InvalidHandle)); return nil }
func (fakeRawConn) Read(func(fd uintptr) bool) error  { return nil }
func (fakeRawConn) Write(func(fd uintptr) bool) error { return nil }

// TestBindControlFailsClosedWindows: when SO_EXCLUSIVEADDRUSE cannot be set,
// bindControl fails, so the bind fails and fathomgate does not start.
func TestBindControlFailsClosedWindows(t *testing.T) {
	t.Parallel()
	err := bindControl("tcp4", "127.0.0.1:0", fakeRawConn{})
	if err == nil || !strings.Contains(err.Error(), "SO_EXCLUSIVEADDRUSE") || !errors.Is(err, windows.WSAENOTSOCK) {
		t.Fatalf("bindControl on an invalid socket: %v, want a SO_EXCLUSIVEADDRUSE error wrapping WSAENOTSOCK", err)
	}
}
