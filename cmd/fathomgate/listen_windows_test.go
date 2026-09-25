// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

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

// squatTarget is an address a squatter binds: a loopback address or one of
// the three wildcards.
type squatTarget struct {
	name   string
	addr   netip.Addr
	v6only int // IPV6_V6ONLY for an IPv6 target
}

var squatTargets = []squatTarget{
	{"127.0.0.1", netip.MustParseAddr("127.0.0.1"), 0},
	{"[::1]", netip.IPv6Loopback(), 1},
	{"0.0.0.0", netip.IPv4Unspecified(), 0},
	{"[::] (IPv6 only)", netip.IPv6Unspecified(), 1},
	{"[::] (dual-stack)", netip.IPv6Unspecified(), 0},
}

// squatBind binds a socket to target on port, with SO_REUSEADDR when reuse
// is set (the squatting technique), without listening, so no test opens a
// listening socket on a wildcard address (the Windows firewall prompts for
// those). It returns the socket and the port bound.
func squatBind(target squatTarget, port uint16, reuse bool) (windows.Handle, uint16, error) {
	family := windows.AF_INET
	if target.addr.Is6() {
		family = windows.AF_INET6
	}
	s, err := windows.WSASocket(int32(family), windows.SOCK_STREAM, windows.IPPROTO_TCP, nil, 0, windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		return windows.InvalidHandle, 0, err
	}
	fail := func(err error) (windows.Handle, uint16, error) {
		_ = windows.Closesocket(s)
		return windows.InvalidHandle, 0, err
	}
	var sa windows.Sockaddr
	if family == windows.AF_INET {
		sa = &windows.SockaddrInet4{Port: int(port), Addr: target.addr.As4()}
	} else {
		if err := windows.SetsockoptInt(s, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, target.v6only); err != nil {
			return fail(err)
		}
		sa = &windows.SockaddrInet6{Port: int(port), Addr: target.addr.As16()}
	}
	if reuse {
		if err := windows.SetsockoptInt(s, windows.SOL_SOCKET, windows.SO_REUSEADDR, 1); err != nil {
			return fail(err)
		}
	}
	if err := windows.Bind(s, sa); err != nil {
		return fail(os.NewSyscallError("bind", err))
	}
	got, err := windows.Getsockname(s)
	if err != nil {
		return fail(err)
	}
	switch a := got.(type) {
	case *windows.SockaddrInet4:
		return s, uint16(a.Port), nil
	case *windows.SockaddrInet6:
		return s, uint16(a.Port), nil
	}
	return fail(fmt.Errorf("getsockname: %T", got))
}

// tcpListener unwraps what bindLoopback returns to its *net.TCPListener.
func tcpListener(t *testing.T, l net.Listener) *net.TCPListener {
	t.Helper()
	if h, ok := l.(*heldListener); ok {
		l = h.Listener
	}
	tl, ok := l.(*net.TCPListener)
	if !ok {
		t.Fatalf("listener is %T, want *net.TCPListener", l)
	}
	return tl
}

// exclusiveAddrUse reads SO_EXCLUSIVEADDRUSE from a listener's socket.
func exclusiveAddrUse(t *testing.T, l net.Listener) int {
	t.Helper()
	rc, err := tcpListener(t, l).SyscallConn()
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

// reachesFathomgate dials l's address and checks that l accepts it.
func reachesFathomgate(t *testing.T, l net.Listener) {
	t.Helper()
	c, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", l.Addr(), err)
	}
	defer func() { _ = c.Close() }()
	tl := tcpListener(t, l)
	if err := tl.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tl.SetDeadline(time.Time{}) }()
	a, err := tl.Accept()
	if err != nil {
		t.Fatalf("%s did not accept the connection: %v", l.Addr(), err)
	}
	_ = a.Close()
}

// TestBindLoopbackExclusiveWindows is the regression test for M1-27. With
// the listener up (bindLoopback with holdWildcards, as serve binds): both
// loopback sockets carry SO_EXCLUSIVEADDRUSE; no other socket can bind the
// port on either loopback address or on any of the three wildcards, with
// SO_REUSEADDR (the squatting technique) or without; agents still reach
// fathomgate on both addresses; and closing the listeners closes every
// socket bindLoopback bound, the wildcards with them (checkReleased;
// binding the wildcards again would race other tests' sockets on the
// freed port, as squatAttempts explains).
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
			rec := &bindRecorder{}
			lns, err := bindLoopback(a, rec.listen, rec.hold(holdWildcards), discardLogger())
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			defer func() {
				if !closed {
					for _, l := range lns {
						_ = l.Close()
					}
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
			for _, target := range squatTargets {
				for _, reuse := range []bool{false, true} {
					s, _, err := squatBind(target, port, reuse)
					if err == nil {
						_ = windows.Closesocket(s)
						t.Errorf("%s could be bound on port %d (SO_REUSEADDR %v) while fathomgate listens on it", target.name, port, reuse)
						continue
					}
					if !errors.Is(err, windows.WSAEACCES) && !errors.Is(err, windows.WSAEADDRINUSE) {
						t.Errorf("bind %s on port %d (SO_REUSEADDR %v): %v, want WSAEACCES or WSAEADDRINUSE", target.name, port, reuse, err)
					}
				}
			}
			for _, l := range lns {
				reachesFathomgate(t, l)
			}
			// Shutdown releases the wildcards too.
			for _, l := range lns {
				_ = l.Close()
			}
			closed = true
			if len(rec.holds) != 1 {
				t.Fatalf("%d wildcard holds, want 1", len(rec.holds))
			}
			if hs, ok := rec.holds[0].c.(heldSockets); !ok || len(hs) != len(wildcards) {
				t.Fatalf("held %T %v, want %d wildcard sockets", rec.holds[0].c, rec.holds[0].c, len(wildcards))
			}
			rec.checkReleased(t)
		})
	}
}

// TestBindLoopbackRefusesHeldWildcardWindows: when another socket already
// holds port P on a wildcard, of any of the three kinds, bindLoopback
// refuses, naming it, and leaves nothing bound.
func TestBindLoopbackRefusesHeldWildcardWindows(t *testing.T) {
	t.Parallel()
	needBothLoopbacks(t)
	for i, w := range wildcards {
		target := squatTargets[2+i]
		t.Run(target.name, func(t *testing.T) {
			t.Parallel()
			for attempt := 1; ; attempt++ {
				if refusesHeldWildcard(t, target, w) {
					return
				}
				if attempt == squatAttempts {
					t.Fatalf("%d squatter ports on %s all had a loopback address taken by another socket", squatAttempts, target.name)
				}
			}
		})
	}
}

// refusesHeldWildcard is one attempt of
// TestBindLoopbackRefusesHeldWildcardWindows. It returns false, having
// checked nothing, when a loopback address on the squatter's port was
// already taken by another socket (squatAttempts).
func refusesHeldWildcard(t *testing.T, target squatTarget, w wildcard) bool {
	t.Helper()
	s, port, err := squatBind(target, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.Closesocket(s) }()
	a, err := parseListenAddr("localhost:" + strconv.Itoa(int(port)))
	if err != nil {
		t.Fatal(err)
	}
	rec := &bindRecorder{}
	lns, err := bindLoopback(a, rec.listen, rec.hold(holdWildcards), discardLogger())
	if err == nil {
		for _, l := range lns {
			_ = l.Close()
		}
		t.Fatalf("bound %d listeners next to a socket holding %s on port %d", len(lns), target.name, port)
	}
	binds := rec.recorded()
	for _, b := range binds {
		if b.err != nil {
			t.Logf("another socket holds %s; trying another port: %v", b.addr, b.err)
			return false
		}
	}
	want := fmt.Sprintf("%s:%d%s, a wildcard address on the same port, cannot be held", w.host, port, w.kind)
	if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "refuses to start") {
		t.Fatalf("error %q, want it to contain %q", err, want)
	}
	if len(binds) != 2 || len(rec.holds) != 0 {
		t.Fatalf("binds %+v, holds %d; want both loopbacks bound and the hold refused", binds, len(rec.holds))
	}
	rec.checkReleased(t)
	return true
}

// TestServeListenWildcardHeldWindows: serve exits 1 before the upstream
// starts (it does not exist, and its error would say so) when another
// socket holds the --listen port on a wildcard, naming the address.
func TestServeListenWildcardHeldWindows(t *testing.T) {
	t.Parallel()
	needBothLoopbacks(t)
	for attempt := 1; ; attempt++ {
		if serveListenWildcardHeld(t) {
			return
		}
		if attempt == squatAttempts {
			t.Fatalf("%d squatter ports on the dual-stack wildcard all had a loopback address taken by another socket", squatAttempts)
		}
	}
}

// serveListenWildcardHeld is one attempt of
// TestServeListenWildcardHeldWindows. It returns false when serve found a
// loopback address on the squatter's port taken by another socket
// (squatAttempts).
func serveListenWildcardHeld(t *testing.T) bool {
	t.Helper()
	s, port, err := squatBind(squatTargets[4], 0, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.Closesocket(s) }()
	p := strconv.Itoa(int(port))
	var stderr lockedBuffer
	code := serveContext(t.Context(), []string{
		"--server", "netdev-ssh-mcp", "--upstream", filepath.Join(t.TempDir(), "no-such-upstream"), "--no-policy",
		"--listen", "localhost:" + p,
	}, &stderr, envMap(map[string]string{listenTokenEnv: testListenToken}))
	out := stderr.String()
	checkNoCanary(t, "stderr", out)
	if code == exitFail && (strings.Contains(out, "fathomgate: serve: --listen: listen tcp 127.0.0.1:"+p+":") ||
		strings.Contains(out, "fathomgate: serve: --listen: [::1]:"+p+", the other loopback address on the same port, cannot be bound")) {
		t.Logf("another socket holds a loopback address on port %s; trying another port", p)
		return false
	}
	if code != exitFail || !strings.Contains(out, "fathomgate: serve: --listen: [::]:"+p+" (dual-stack), a wildcard address on the same port, cannot be held") || strings.Contains(out, "no-such-upstream") {
		t.Fatalf("exit %d; stderr %q", code, out)
	}
	return true
}

var procGetHandleInformation = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation")

// TestHoldWildcardsNotInherited: the wildcard sockets are not inheritable,
// so the upstream, started after the bind, never holds the port.
func TestHoldWildcardsNotInherited(t *testing.T) {
	t.Parallel()
	needBothLoopbacks(t)
	l, err := listenTCP("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	held, err := holdWildcards(portOf(t, l))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	hs, ok := held.(heldSockets)
	if !ok || len(hs) != len(wildcards) {
		t.Fatalf("held %T %v, want %d sockets", held, held, len(wildcards))
	}
	for i, s := range hs {
		var flags uint32
		// x/sys/windows v0.48.0 has SetHandleInformation but no Get.
		if r, _, err := procGetHandleInformation.Call(uintptr(s), uintptr(unsafe.Pointer(&flags))); r == 0 {
			t.Fatalf("GetHandleInformation: %v", err)
		}
		if flags&windows.HANDLE_FLAG_INHERIT != 0 {
			t.Errorf("wildcard socket %d is inheritable", i)
		}
	}
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
