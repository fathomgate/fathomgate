package proxy

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Server-side settings for the HTTP listener that live outside the handler
// (ADR 0016, "Request handling", steps 1 and 8). cmd/netguard (T0.31) owns
// the listener and the lifecycle; these helpers keep the values in one
// place with the handler they protect.

const (
	// MaxConnections caps open TCP connections (LimitListener). Further
	// connections wait in the kernel backlog.
	MaxConnections = 128
	// MaxHeaderBytes caps request headers.
	MaxHeaderBytes = 64 << 10
	// ReadHeaderTimeout bounds how long request headers may take.
	ReadHeaderTimeout = 10 * time.Second
	// IdleTimeout closes a keep-alive connection with no request.
	IdleTimeout = 120 * time.Second
)

// NewHTTPServer returns the http.Server for the listener: header limit and
// timeouts set, and no server-wide ReadTimeout or WriteTimeout (either
// would cut long SSE responses; the handler sets per-request body read and
// per-write deadlines instead). Server errors go to logger at warn.
func NewHTTPServer(h http.Handler, logger *slog.Logger) *http.Server {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &http.Server{
		Handler:           h,
		MaxHeaderBytes:    MaxHeaderBytes,
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       IdleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

// LimitListener returns a listener that holds at most n connections open at
// once (MaxConnections for netguard). Accept waits for a slot before
// accepting, so further connections queue in the kernel.
func LimitListener(l net.Listener, n int) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n), done: make(chan struct{})}
}

type limitListener struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// Accept waits for a free slot, then accepts.
func (l *limitListener) Accept() (net.Conn, error) {
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
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

// Close closes the listener and wakes an Accept waiting for a slot.
func (l *limitListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

// Close closes the connection and frees its slot, once.
func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// ErrMCPGODEBUG is returned by CheckEnvironment when MCPGODEBUG is set.
var ErrMCPGODEBUG = errors.New("MCPGODEBUG is set: its go-sdk compatibility switches (allowsessionsinstateless=1 among them) would change transport security without appearing on the command line; unset it to use the HTTP listener")

// CheckEnvironment refuses an environment that would change go-sdk's
// transport behaviour unseen: MCPGODEBUG set to anything, even empty.
// lookup is os.LookupEnv outside tests. HTTPHandler runs it; cmd/netguard
// runs it first to exit 2 with the variable named (T0.31).
func CheckEnvironment(lookup func(string) (string, bool)) error {
	if _, set := lookup("MCPGODEBUG"); set {
		return ErrMCPGODEBUG
	}
	return nil
}
