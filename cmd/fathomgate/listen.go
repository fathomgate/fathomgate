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
	// firstHeaderTimeout bounds how long a new connection may take to send
	// its first request's headers, counted from accept (L1 in the security
	// review of PR #109). A client that has not authenticated yet then holds
	// one of the maxConnections slots for this long at most, not for
	// readHeaderTimeout. Later requests on a kept-alive connection get
	// readHeaderTimeout.
	firstHeaderTimeout = 3 * time.Second
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
var errListenAddr = errors.New("--listen takes localhost:<port>, 127.0.0.1:<port> or [::1]:<port>; fathomgate listens on loopback only in M0, until the policy pipeline is wired (M1)")

// listenAddr is a checked --listen value: the loopback address asked for
// and its port (0: the OS picks one).
type listenAddr struct {
	host netip.Addr
	port uint16
}

// ipv4Loopback is 127.0.0.1, the only IPv4 address --listen takes.
var ipv4Loopback = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// other is the loopback address of the other family, which bindLoopback
// binds on the same port as host: [::1] for 127.0.0.1, 127.0.0.1 for
// [::1].
func (a listenAddr) other() netip.Addr {
	if a.host.Is4() {
		return netip.IPv6Loopback()
	}
	return ipv4Loopback
}

// parseListenAddr checks a --listen value. The host must be one of
// localhost (taken as 127.0.0.1, never resolved), 127.0.0.1 or [::1], the
// two addresses a client may reach for localhost; bindLoopback binds both
// of them on the port whichever is given. Everything else is refused: any
// other address in 127.0.0.0/8 (bound alone it would leave 127.0.0.1 and
// [::1] on its port to another local user; security review of PR #112), a
// bare :port, an unspecified address, a LAN address, a host name, an
// IPv4-mapped IPv6 address or a zone. Port 0 asks the OS for a free port.
func parseListenAddr(s string) (listenAddr, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return listenAddr{}, errListenAddr
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return listenAddr{}, errors.New("--listen: the port must be a number from 0 to 65535")
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || (ip != ipv4Loopback && ip != netip.IPv6Loopback()) {
		return listenAddr{}, errListenAddr
	}
	return listenAddr{host: ip, port: uint16(p)}, nil
}

// listenFunc is listenTCP; tests inject failures.
type listenFunc func(network, address string) (net.Listener, error)

// listenTCP is the listenFunc serve binds with: net.Listen, with bindControl
// run on the socket before bind. On Windows that sets SO_EXCLUSIVEADDRUSE
// (listen_windows.go; ADR 0029, M1-27); elsewhere bindControl is nil and
// listenTCP is net.Listen (listen_unix.go says why). A bind that cannot set
// the option fails, so fathomgate does not start on a socket without it.
func listenTCP(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: bindControl}
	return lc.Listen(context.Background(), network, address)
}

// bindAttempts bounds how many ports bindLoopback tries for port 0 when the
// other family's loopback is taken on the port the OS picked.
const bindAttempts = 8

// bindLoopback binds a, then the other loopback family on the same port
// (H1 in the security review of PR #109). A client given
// http://localhost:<port>/mcp may try [::1] before 127.0.0.1, or the
// reverse, so with one family bound another local user could bind the
// other on the same port and receive the client's bearer token. Holding
// both closes that. If the other family's address cannot be bound because
// the host has no loopback of that family, bindLoopback logs a warning and
// listens on a alone. Any other failure, in use above all, is an error and
// leaves nothing bound; for port 0 the OS is first asked for another port,
// up to bindAttempts times. The listeners come back in bind order, a first.
func bindLoopback(a listenAddr, listen listenFunc, logger *slog.Logger) ([]net.Listener, error) {
	for attempt := 1; ; attempt++ {
		first, err := listen("tcp", netip.AddrPortFrom(a.host, a.port).String())
		if err != nil {
			return nil, err
		}
		// The port comes from the bound address; a listener that cannot say
		// which port it holds is refused rather than guessed at.
		ta, ok := first.Addr().(*net.TCPAddr)
		if !ok || ta.Port <= 0 || ta.Port > 65535 {
			_ = first.Close()
			return nil, fmt.Errorf("cannot tell which port %s was bound on (%v)", netip.AddrPortFrom(a.host, a.port), first.Addr())
		}
		other := netip.AddrPortFrom(a.other(), uint16(ta.Port)).String()
		second, err := listen("tcp", other)
		switch {
		case err == nil:
			return []net.Listener{first, second}, nil
		case loopbackFamilyMissing(err):
			logger.Warn("this host has no loopback address of the other family; listening on one address only", "missing", other, "error", err)
			return []net.Listener{first}, nil
		}
		_ = first.Close()
		if a.port == 0 && attempt < bindAttempts {
			continue
		}
		// net.OpError's text repeats the address; name it once.
		cause := err
		var oe *net.OpError
		if errors.As(err, &oe) && oe.Err != nil {
			cause = oe.Err
		}
		return nil, fmt.Errorf("%s, the other loopback address on the same port, cannot be bound (%w); fathomgate refuses to start, because a client that resolves localhost to that address would send its token to whatever holds it. Stop that program or use another port", other, cause)
	}
}

// listenServer is the http.Server for the listener, with what its
// shutdown hook needs.
type listenServer struct {
	*http.Server
	requests *requestTracker
	// hookDone is closed once the shutdown hook has closed the proxy.
	hookDone chan struct{}
	// firstHeader is how long a new connection gets to deliver its first
	// request's headers (firstHeaderTimeout; 0 turns the timer off), and
	// afterFunc starts that timer (time.AfterFunc). Tests change them
	// before Serve.
	firstHeader time.Duration
	afterFunc   func(time.Duration, func()) stopper
}

// stopper is the part of *time.Timer the first-request timer uses.
type stopper interface{ Stop() bool }

// firstRequestKey is the connection context key of a *firstRequest.
type firstRequestKey struct{}

// firstRequest is one connection's first-request timer (L1 in the security
// review of PR #109). ConnContext starts it when the connection is
// accepted; it closes the connection unless a request's headers have been
// read first, which is when net/http calls the handler, and seen stops it.
// This uses only documented http.Server hooks, so it does not depend on
// the order in which net/http sets deadlines, and it works the same under
// TLS. A timer that fires just as the first request reaches the handler
// closes that connection mid-request; the client sees a reset.
type firstRequest struct {
	once  sync.Once
	timer stopper
}

// seen stops the timer, once per connection.
func (f *firstRequest) seen() { f.once.Do(func() { f.timer.Stop() }) }

// firstRequestSeen stops the connection's first-request timer before h
// runs, so the first request's body, however slow, is not timed by it.
func firstRequestSeen(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f, ok := r.Context().Value(firstRequestKey{}).(*firstRequest); ok {
			f.seen()
		}
		h.ServeHTTP(w, r)
	})
}

// newHTTPServer returns the http.Server for the listener, serving h (from
// proxy.HTTPHandler): header limit and timeouts set, and no server-wide
// ReadTimeout or WriteTimeout (either would cut long SSE responses; the
// handler sets per-request body read and per-write deadlines instead).
// Server errors go to logger at warn. A new connection that has not
// delivered a request's headers within firstHeaderTimeout of being
// accepted is closed (firstRequest).
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
	s := &listenServer{
		requests:    &requestTracker{},
		hookDone:    make(chan struct{}),
		firstHeader: firstHeaderTimeout,
		afterFunc:   func(d time.Duration, f func()) stopper { return time.AfterFunc(d, f) },
	}
	s.Server = &http.Server{
		Handler:           firstRequestSeen(s.requests.wrap(h)),
		MaxHeaderBytes:    maxHeaderBytes,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if s.firstHeader <= 0 {
				return ctx
			}
			f := &firstRequest{timer: s.afterFunc(s.firstHeader, func() { _ = c.Close() })}
			return context.WithValue(ctx, firstRequestKey{}, f)
		},
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

// requestTracker counts the requests being served, other than the
// long-lived streams (longLived): those never end on their own, and the
// shutdown grace must not wait for them.
type requestTracker struct {
	mu   sync.Mutex
	n    int
	idle chan struct{} // closed when n reaches 0; nil while nobody waits
}

// wrap counts every request h serves, other than the long-lived streams.
func (t *requestTracker) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !longLived(r) {
			t.add(1)
			defer t.add(-1)
		}
		h.ServeHTTP(w, r)
	})
}

// longLived reports a request that opens a stream which never ends on its
// own: a 2025-era GET stream, or a 2026-era subscriptions/listen POST,
// named by its Mcp-Method header. go-sdk answers 400 to a 2026-era request
// whose header and body disagree, so the header cannot hide a tool call;
// a 2025-era request that carries it only gives up its own grace.
func longLived(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Header.Get("Mcp-Method") == "subscriptions/listen"
}

// add changes the count by d and wakes wait when it reaches 0.
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

// runListener serves p over Streamable HTTP on lns (bindLoopback's
// listeners, one or both loopback families) until ctx ends (SIGINT or
// SIGTERM: exit 0), the upstream exits (exit 1) or a listener fails (exit
// 1), then shuts down: it stops accepting, gives the requests in flight
// shutdownGrace, closes the agent sessions and then the upstream
// (p.Close). It owns lns and p from here on and closes them all. One
// `listening url=...` line per listener, in bind order, tells scripts and
// operators the real addresses.
func runListener(ctx context.Context, p *proxy.Proxy, lns []net.Listener, run listenRun, logger *slog.Logger, out io.Writer) int {
	grace := run.grace
	if grace == 0 {
		grace = shutdownGrace
	}
	h, err := p.HTTPHandler(proxy.HTTPOptions{Tokens: run.tokens.byName})
	if err != nil {
		for _, ln := range lns {
			_ = ln.Close()
		}
		closeProxy(p, logger)
		_, _ = fmt.Fprintf(out, "fathomgate: serve: %v\n", err)
		return exitUsage
	}
	srv := newHTTPServer(h, p, grace, logger)
	served := make(chan error, len(lns))
	for _, ln := range limitListeners(lns, maxConnections) {
		go func() { served <- srv.Serve(ln) }()
	}
	for _, ln := range lns {
		attrs := []any{"url", "http://" + ln.Addr().String() + proxy.HTTPPath, "server", run.server, "principals", strings.Join(run.tokens.names, ",")}
		if len(run.passNames) > 0 {
			attrs = append(attrs, "upstream_env_pass", strings.Join(run.passNames, ","))
		}
		logger.Info("listening", append(attrs, "policy", "none (M0 pass-through: every call is forwarded)")...)
	}

	code := exitOK
	pending := len(lns) // Serve calls that have not returned
	select {
	case <-ctx.Done():
		logger.Info("shutting down", "grace", grace)
	case <-p.UpstreamExited():
		_, _ = fmt.Fprintf(out, "fathomgate: serve: upstream %s exited; the listener has stopped so a supervisor can restart fathomgate\n", run.server)
		code = exitFail
	case serveErr := <-served:
		pending--
		_, _ = fmt.Fprintf(out, "fathomgate: serve: listener: %v\n", serveErr)
		code = exitFail
	}

	sctx, cancel := context.WithTimeout(context.Background(), grace+closeWait)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		logger.Warn("connections still open after the shutdown grace; closing them", "error", err)
		_ = srv.Close()
	}
	<-srv.hookDone
	for range pending {
		<-served
	}
	closeProxy(p, logger)
	return code
}

// closeProxy closes p (the upstream), logging a failure.
func closeProxy(p *proxy.Proxy, logger *slog.Logger) {
	if err := p.Close(); err != nil {
		logger.Warn("closing upstream", "error", err)
	}
}

// limitListener is limitListeners for one listener.
func limitListener(l net.Listener, n int) net.Listener {
	return limitListeners([]net.Listener{l}, n)[0]
}

// limitListeners returns listeners that together hold at most n connections
// open at once (maxConnections for fathomgate), whichever listener they
// arrive on. Accept takes a slot before it accepts, so further connections
// queue in the kernel. An Accept that is waiting for a connection already
// holds its slot: with both loopback listeners idle, two of the n slots are
// held that way, and a listener whose peer takes every other slot waits
// until one is freed even if its own Accept would find a connection. n
// below 1 is a programmer error and panics.
func limitListeners(ls []net.Listener, n int) []net.Listener {
	if n < 1 {
		panic("fathomgate: limitListener needs at least one connection slot")
	}
	sem := make(chan struct{}, n)
	out := make([]net.Listener, len(ls))
	for i, l := range ls {
		out[i] = &limitedListener{Listener: l, sem: sem, done: make(chan struct{})}
	}
	return out
}

// limitedListener is one listener of limitListeners: it takes a slot from
// the shared semaphore before each Accept.
type limitedListener struct {
	net.Listener
	sem       chan struct{} // shared by every listener of one limitListeners call
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

// limitedConn is a connection accepted by a limitedListener; closing it
// frees its slot.
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

// CloseWrite half-closes the connection when the one underneath can (a
// *net.TCPConn), so net/http sends FIN after a Connection: close answer
// before it closes, as it does on an unwrapped connection.
func (c *limitedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
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
