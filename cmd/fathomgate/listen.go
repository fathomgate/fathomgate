// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fathomgate/fathomgate/internal/proxy"
)

// The server side of the Streamable HTTP listener (ADR 0016: cmd/fathomgate
// owns the listener, the connection cap, the http.Server settings and the
// lifecycle; internal/proxy exports only the handler). `fathomgate serve
// --listen` runs it (runListener) instead of the stdio agent side.

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
	// shutdownGrace is how long requests in flight get to finish on
	// shutdown before the proxy is closed, which cancels the calls still
	// running and closes every agent session (ADR 0016; J4 in the
	// re-review of PR #72).
	shutdownGrace = 5 * time.Second
	// closeWait bounds how long shutdown then waits for the connections to
	// close before they are closed by force.
	closeWait = 5 * time.Second
)

// errListenAddr is the refusal of a --listen address that is not loopback.
// It never quotes the value.
var errListenAddr = errors.New("--listen takes localhost:<port>, an IPv4 address in 127.0.0.0/8 with a port, or [::1]:<port>; fathomgate listens on loopback only in M0, until the policy pipeline is wired (M1)")

// parseListenAddr checks a --listen value and returns the address to bind.
// The host must be written out: localhost (bound as 127.0.0.1, never
// resolved), an IPv4 address in 127.0.0.0/8, or [::1]. A bare :port, an
// unspecified address, any other address or a host name is refused, and so
// is an IPv4-mapped IPv6 address or a zone. Port 0 asks the OS for a free
// port.
func parseListenAddr(s string) (string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", errListenAddr
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", errors.New("--listen: the port must be a number from 0 to 65535")
	}
	if host == "localhost" {
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return "", errListenAddr
	}
	loopback4 := ip.Is4() && ip.IsLoopback()
	if !loopback4 && ip != netip.IPv6Loopback() {
		return "", errListenAddr
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// listenServer is the http.Server for the listener, with what its
// shutdown hook needs.
type listenServer struct {
	*http.Server
	requests *requestTracker
	// hookDone is closed once the shutdown hook has closed the proxy.
	hookDone chan struct{}
}

// newHTTPServer returns the http.Server for the listener, serving h (from
// proxy.HTTPHandler): header limit and timeouts set, and no server-wide
// ReadTimeout or WriteTimeout (either would cut long SSE responses; the
// handler sets per-request body read and per-write deadlines instead).
// Server errors go to logger at warn.
//
// p (the Proxy) is closed by a shutdown hook: Shutdown alone waits for
// every connection to go idle, and a 2025-era session's open GET stream
// never does, so without the hook Shutdown would run to its deadline. The
// hook first gives the requests in flight (every method but GET) up to
// grace to finish, then closes p, which cancels the calls still running
// and closes the agent sessions, and so ends the GET streams. With nothing
// in flight it closes p at once. The caller waits for hookDone after
// Shutdown returns, then calls p.Close again, which waits for the first
// Close to finish.
func newHTTPServer(h http.Handler, p io.Closer, grace time.Duration, logger *slog.Logger) *listenServer {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	s := &listenServer{requests: &requestTracker{}, hookDone: make(chan struct{})}
	s.Server = &http.Server{
		Handler:           s.requests.wrap(h),
		MaxHeaderBytes:    maxHeaderBytes,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	s.RegisterOnShutdown(func() {
		defer close(s.hookDone)
		ctx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		if !s.requests.wait(ctx) {
			logger.Warn("shutdown grace ended with requests in flight; cancelling them", "grace", grace)
		}
		_ = p.Close()
	})
	return s
}

// requestTracker counts the requests being served, other than GET: those
// are open SSE streams that never end on their own, and the shutdown grace
// must not wait for them.
type requestTracker struct {
	mu   sync.Mutex
	n    int
	idle chan struct{} // closed when n reaches 0; nil while nobody waits
}

// wrap counts every request h serves, other than GET.
func (t *requestTracker) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.add(1)
			defer t.add(-1)
		}
		h.ServeHTTP(w, r)
	})
}

func (t *requestTracker) add(d int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.n += d
	if t.n == 0 && t.idle != nil {
		close(t.idle)
		t.idle = nil
	}
}

// wait returns true once no request is being served, or false when ctx
// ends first.
func (t *requestTracker) wait(ctx context.Context) bool {
	t.mu.Lock()
	if t.n == 0 {
		t.mu.Unlock()
		return true
	}
	if t.idle == nil {
		t.idle = make(chan struct{})
	}
	idle := t.idle
	t.mu.Unlock()
	select {
	case <-idle:
		return true
	case <-ctx.Done():
		return false
	}
}

// listenRun is what runListener needs from the command line.
type listenRun struct {
	tokens    listenTokens
	server    string   // the upstream's --server name
	passNames []string // --upstream-env-pass names, for the log line
	// grace replaces shutdownGrace when set (tests).
	grace time.Duration
}

// runListener serves p over Streamable HTTP on ln until ctx ends (SIGINT or
// SIGTERM: exit 0), the upstream exits (exit 1) or the listener fails
// (exit 1), then shuts down: it stops accepting, gives the requests in
// flight shutdownGrace, closes the agent sessions and then the upstream
// (p.Close). It owns ln and p from here on and closes both. The one
// `listening url=...` line tells scripts the real address.
func runListener(ctx context.Context, p *proxy.Proxy, ln net.Listener, run listenRun, logger *slog.Logger, out io.Writer) int {
	grace := run.grace
	if grace == 0 {
		grace = shutdownGrace
	}
	h, err := p.HTTPHandler(proxy.HTTPOptions{Tokens: run.tokens.byName})
	if err != nil {
		_ = ln.Close()
		closeProxy(p, logger)
		_, _ = fmt.Fprintf(out, "fathomgate: serve: %v\n", err)
		return exitUsage
	}
	srv := newHTTPServer(h, p, grace, logger)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(limitListener(ln, maxConnections)) }()
	attrs := []any{"url", "http://" + ln.Addr().String() + proxy.HTTPPath, "server", run.server, "principals", strings.Join(run.tokens.names, ",")}
	if len(run.passNames) > 0 {
		attrs = append(attrs, "upstream_env_pass", strings.Join(run.passNames, ","))
	}
	logger.Info("listening", append(attrs, "policy", "none (M0 pass-through: every call is forwarded)")...)

	code := exitOK
	select {
	case <-ctx.Done():
		logger.Info("shutting down", "grace", grace)
	case <-p.UpstreamExited():
		_, _ = fmt.Fprintf(out, "fathomgate: serve: upstream %s exited; the listener has stopped so a supervisor can restart fathomgate\n", run.server)
		code = exitFail
	case err := <-served:
		served <- err
		_, _ = fmt.Fprintf(out, "fathomgate: serve: listener: %v\n", err)
		code = exitFail
	}

	sctx, cancel := context.WithTimeout(context.Background(), grace+closeWait)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		logger.Warn("connections still open after the shutdown grace; closing them", "error", err)
		_ = srv.Close()
	}
	<-srv.hookDone
	<-served
	closeProxy(p, logger)
	return code
}

// closeProxy closes p (the upstream), logging a failure.
func closeProxy(p *proxy.Proxy, logger *slog.Logger) {
	if err := p.Close(); err != nil {
		logger.Warn("closing upstream", "error", err)
	}
}

// limitListener returns a listener that holds at most n connections open at
// once (maxConnections for fathomgate). Accept waits for a slot before
// accepting, so further connections queue in the kernel. n below 1 is a
// programmer error and panics.
func limitListener(l net.Listener, n int) net.Listener {
	if n < 1 {
		panic("fathomgate: limitListener needs at least one connection slot")
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

// checkListenEnvironment refuses an environment that would change go-sdk's
// transport behaviour unseen: MCPGODEBUG set to anything, even empty.
// proxy.HTTPHandler refuses it too, with this same error value, so there is
// one refusal text (K4 in the re-review of PR #72); serve runs this first,
// before it binds or starts the upstream, so it can exit 2 with the
// variable named (S6 in the security review of T0.40).
func checkListenEnvironment(lookup lookupEnvFunc) error {
	if _, set := lookup("MCPGODEBUG"); set {
		return proxy.ErrMCPGODEBUG
	}
	return nil
}
