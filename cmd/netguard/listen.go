package main

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// The server side of the Streamable HTTP listener (ADR 0016: cmd/netguard
// owns the listener, the connection cap, the http.Server settings and the
// lifecycle; internal/proxy exports only the handler). `netguard serve
// --listen` wires these in T0.31; until then only their tests use them.

const (
	// maxConnections caps open TCP connections (limitListener). Further
	// connections wait in the kernel backlog.
	maxConnections = 128
	// maxHeaderBytes caps request headers.
	maxHeaderBytes = 64 << 10
	// readHeaderTimeout bounds how long request headers may take.
	readHeaderTimeout = 10 * time.Second
	// idleTimeout closes a keep-alive connection with no request.
	idleTimeout = 120 * time.Second
)

// newHTTPServer returns the http.Server for the listener, serving h (from
// proxy.HTTPHandler): header limit and timeouts set, and no server-wide
// ReadTimeout or WriteTimeout (either would cut long SSE responses; the
// handler sets per-request body read and per-write deadlines instead).
// Server errors go to logger at warn.
//
// p (the Proxy) is closed when the server shuts down: Shutdown alone waits
// for every connection to go idle, and a 2025-era session's open GET stream
// never does, so without the hook Shutdown would run to its deadline.
// Close cancels the calls in flight and closes the agent sessions, which
// ends those streams. The caller still calls p.Close after Shutdown
// returns; it waits for the first Close to finish.
func newHTTPServer(h http.Handler, p io.Closer, logger *slog.Logger) *http.Server {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	srv := &http.Server{
		Handler:           h,
		MaxHeaderBytes:    maxHeaderBytes,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	srv.RegisterOnShutdown(func() { _ = p.Close() })
	return srv
}

// limitListener returns a listener that holds at most n connections open at
// once (maxConnections for netguard). Accept waits for a slot before
// accepting, so further connections queue in the kernel. n below 1 is a
// programmer error and panics.
func limitListener(l net.Listener, n int) net.Listener {
	if n < 1 {
		panic("netguard: limitListener needs at least one connection slot")
	}
	return &limitedListener{Listener: l, sem: make(chan struct{}, n), done: make(chan struct{})}
}

type limitedListener struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// Accept waits for a free slot, then accepts.
func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitedConn{Conn: c, release: func() { <-l.sem }}, nil
}

// Close closes the listener and wakes an Accept waiting for a slot.
func (l *limitedListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

// Close closes the connection and frees its slot, once.
func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// errMCPGODEBUG is the refusal of --listen when MCPGODEBUG is set.
var errMCPGODEBUG = errors.New("MCPGODEBUG is set: its go-sdk compatibility switches (allowsessionsinstateless=1 among them) would change transport security without appearing on the command line; unset it to use the HTTP listener")

// checkListenEnvironment refuses an environment that would change go-sdk's
// transport behaviour unseen: MCPGODEBUG set to anything, even empty.
// proxy.HTTPHandler refuses it too; serve runs this first so it can exit 2
// with the variable named before starting the upstream (T0.31).
func checkListenEnvironment(lookup lookupEnvFunc) error {
	if _, set := lookup("MCPGODEBUG"); set {
		return errMCPGODEBUG
	}
	return nil
}
