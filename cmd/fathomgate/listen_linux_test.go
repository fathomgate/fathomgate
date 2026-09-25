// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
)

// soReusePort is Linux's SO_REUSEPORT on amd64 and arm64 (asm-generic
// socket.h). The syscall package does not define it, and golang.org/x/sys/unix
// is not a dependency.
const soReusePort = 0xf

// listenWithOpts binds and listens on addr with each SOL_SOCKET option in
// opts set to 1 before bind.
func listenWithOpts(addr string, opts ...int) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			for _, o := range opts {
				if serr == nil {
					serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, o, 1)
				}
			}
		}); err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(context.Background(), "tcp", addr)
}

// TestBindLoopbackRefusesWildcardLinux backs the comment on bindControl in
// listen_unix.go (M1-27): Linux needs no SO_EXCLUSIVEADDRUSE, because while
// fathomgate listens on 127.0.0.1:P and [::1]:P no other socket can bind
// either of them, or the wildcard on P, with SO_REUSEADDR, SO_REUSEPORT or
// neither.
func TestBindLoopbackRefusesWildcardLinux(t *testing.T) {
	t.Parallel()
	needBothLoopbacks(t)
	a, err := parseListenAddr("localhost:0")
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
	for _, host := range []string{"127.0.0.1", "::1", "0.0.0.0", "::"} {
		addr := netip.AddrPortFrom(netip.MustParseAddr(host), port).String()
		for name, opts := range map[string][]int{
			"no options":                nil,
			"SO_REUSEADDR":              {syscall.SO_REUSEADDR},
			"SO_REUSEADDR SO_REUSEPORT": {syscall.SO_REUSEADDR, soReusePort},
		} {
			l, err := listenWithOpts(addr, opts...)
			if err == nil {
				_ = l.Close()
				t.Errorf("%s could be bound (%s) while fathomgate listens on port %d", addr, name, port)
				continue
			}
			if !errors.Is(err, syscall.EADDRINUSE) {
				t.Errorf("bind %s (%s): %v, want EADDRINUSE", addr, name, err)
			}
		}
	}
}
