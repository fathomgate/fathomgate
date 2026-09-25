// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The Streamable HTTP listener toward the agent (T0.27, ADR 0016;
// profile-schema section 8.5).
//
// One http.Handler serves /mcp for both protocol eras. go-sdk v1.8 cannot:
// its StreamableHTTPHandler is either stateful, and then refuses every
// 2026-07-28 request but server/discover (serveStatefulPOST), or stateless,
// and then serves 2025-era requests on throwaway sessions that cannot carry
// the relayed elicitation/create (ephemeralConnectOpts). So a dispatcher
// sits in front of one of each, both serving the proxy's one mcp.Server.
//
// Every request passes these checks in order; the first failure answers:
//
//  1. Host: a request that arrived on a loopback address with a non-loopback
//     Host gets 403 (DNS rebinding). go-sdk's own check stays on behind it.
//  2. Origin: any Origin header (including "null"), or a Sec-Fetch-Site other
//     than "none" or "same-origin", gets 403, on every method and before
//     authentication. No CORS headers are ever sent.
//  3. Path: anything but /mcp is 404.
//  4. Bearer token (go-sdk's auth.RequireBearerToken with a constant-time
//     verifier): 401 with WWW-Authenticate: Bearer.
//  5. POSTs in flight, overall and per principal: 503 with Retry-After: 1.
//  6. Era dispatch on MCP-Protocol-Version.
//  7. Stateful sessions: a POST that could open one when the overall or the
//     principal's cap is reached first evicts the principal's least
//     recently used idle session (reserveSession); with none, it gets 503.
//  8. go-sdk: body size (413), Content-Type, Accept, _meta and header
//     agreement, Mcp-Method and Mcp-Name.
//
// Every 401, 403, 404, 413 and 503 also carries Connection: close, so a
// refused client holds none of the listener's connection slots (H3 in the
// review of PR #68). Tool calls are then capped per session and per
// principal in Proxy.handler (calls.go). Every write to the agent runs under
// a write deadline, so an agent that stops reading costs a bounded time per
// write, not a goroutine forever (T3 in the review of PR #63). A stateful
// session with no POST in progress for SessionTimeout has its calls
// cancelled and is closed (liveSession).

// HTTPPath is the only path the listener serves.
const HTTPPath = "/mcp"

// Defaults for HTTPOptions. They are the values ADR 0016 fixes for M0, the
// per-session and per-principal call caps the review of PR #63 (T3) added,
// and the per-principal session cap the review of PR #68 (H2) added.
const (
	defaultMaxInFlight             = 64
	defaultMaxInFlightPerPrincipal = 32
	defaultMaxSessions             = 16
	defaultMaxSessionsPerPrincipal = 4
	defaultMaxCallsPerSession      = 8
	defaultMaxCallsPerPrincipal    = 32
	defaultSessionTimeout          = 30 * time.Minute
	defaultOrphanTTL               = 5 * time.Minute
	defaultWriteTimeout            = 10 * time.Second
	defaultBodyReadTimeout         = 30 * time.Second
	// maxRequestBodyBytes is the body limit; go-sdk answers 413 past it.
	maxRequestBodyBytes = 4 << 20
	// minTokenBytes is the shortest bearer token accepted.
	minTokenBytes = 32
)

// HTTPOptions configures [Proxy.HTTPHandler]. Tokens is required. Every
// other field's zero value means its default (profile-schema section 8.5);
// a negative value is an error. No field turns a check off.
type HTTPOptions struct {
	// Tokens maps each principal name to its bearer token. Every token is
	// named: names are 1 to 64 characters from [A-Za-z0-9_.:-]. Each token
	// is at least 32 bytes of printable ASCII without spaces, and no two
	// names share a token. Tokens must be random (for example the output of
	// `openssl rand -hex 32`); fathomgate checks their shape, not their
	// entropy. A principal is attribution only (audit, requestState
	// binding): never an approver identity (CLAUDE.md invariant 6).
	Tokens map[string][]byte

	// MaxInFlight caps POSTs in flight across every principal, long-lived
	// 2026 subscriptions/listen streams included.
	MaxInFlight int
	// MaxInFlightPerPrincipal caps one principal's POSTs in flight, so one
	// principal cannot take every slot of MaxInFlight.
	MaxInFlightPerPrincipal int
	// MaxSessions caps open stateful (2025-era) sessions.
	MaxSessions int
	// MaxSessionsPerPrincipal caps one principal's open stateful sessions,
	// so one principal cannot take every slot of MaxSessions.
	MaxSessionsPerPrincipal int
	// MaxCallsPerSession and MaxCallsPerPrincipal cap tool calls in flight.
	// They count calls, not requests: a 2025-era call whose POST was dropped
	// keeps running and keeps counting.
	MaxCallsPerSession   int
	MaxCallsPerPrincipal int
	// SessionTimeout closes a stateful session with no POST in progress for
	// this long, cancelling any call still running on it first.
	SessionTimeout time.Duration
	// OrphanTTL is how long a call that has ended keeps a stateful
	// upstream's prompt from being attributed to another agent session,
	// because the upstream may still be working on it (profile-schema
	// section 8.4). It is separate from SessionTimeout and much shorter by
	// default (5 minutes against 30): an idle session costs one slot, while
	// an orphan refuses other agents' prompts.
	OrphanTTL time.Duration
	// WriteTimeout bounds each write (and flush) to the agent. A write that
	// cannot complete in time fails and the connection is dropped.
	WriteTimeout time.Duration
	// BodyReadTimeout bounds how long a request body may take to arrive.
	BodyReadTimeout time.Duration
}

// resolved returns o with defaults filled in, or an error for a negative
// value.
func (o HTTPOptions) resolved() (HTTPOptions, error) {
	ints := []struct {
		name string
		v    *int
		def  int
	}{
		{"MaxInFlight", &o.MaxInFlight, defaultMaxInFlight},
		{"MaxInFlightPerPrincipal", &o.MaxInFlightPerPrincipal, defaultMaxInFlightPerPrincipal},
		{"MaxSessions", &o.MaxSessions, defaultMaxSessions},
		{"MaxSessionsPerPrincipal", &o.MaxSessionsPerPrincipal, defaultMaxSessionsPerPrincipal},
		{"MaxCallsPerSession", &o.MaxCallsPerSession, defaultMaxCallsPerSession},
		{"MaxCallsPerPrincipal", &o.MaxCallsPerPrincipal, defaultMaxCallsPerPrincipal},
	}
	for _, f := range ints {
		switch {
		case *f.v < 0:
			return o, fmt.Errorf("proxy: HTTPOptions.%s is negative", f.name)
		case *f.v == 0:
			*f.v = f.def
		}
	}
	durs := []struct {
		name string
		v    *time.Duration
		def  time.Duration
	}{
		{"SessionTimeout", &o.SessionTimeout, defaultSessionTimeout},
		{"OrphanTTL", &o.OrphanTTL, defaultOrphanTTL},
		{"WriteTimeout", &o.WriteTimeout, defaultWriteTimeout},
		{"BodyReadTimeout", &o.BodyReadTimeout, defaultBodyReadTimeout},
	}
	for _, f := range durs {
		switch {
		case *f.v < 0:
			return o, fmt.Errorf("proxy: HTTPOptions.%s is negative", f.name)
		case *f.v == 0:
			*f.v = f.def
		}
	}
	return o, nil
}

// ErrMCPGODEBUG is the refusal of the HTTP listener when MCPGODEBUG is set,
// even to an empty value. [Proxy.HTTPHandler] returns it, and cmd/fathomgate
// runs the same check first, and returns this same error, so it can exit 2
// before it starts the upstream. It is exported so that there is one
// refusal text in one place (K4 in the re-review of PR #72).
var ErrMCPGODEBUG = errors.New("MCPGODEBUG is set: its go-sdk compatibility switches (allowsessionsinstateless=1 among them) would change transport security without appearing on the command line; unset it to use the HTTP listener")

// tokenEntry is one configured token, kept only as its digest.
type tokenEntry struct {
	name   string
	digest [sha256.Size]byte
}

// checkTokens validates the configured tokens and returns them by name.
func checkTokens(tokens map[string][]byte) ([]tokenEntry, error) {
	if len(tokens) == 0 {
		return nil, errors.New("proxy: the HTTP listener needs at least one bearer token")
	}
	out := make([]tokenEntry, 0, len(tokens))
	seen := make(map[[sha256.Size]byte]string, len(tokens))
	for name, tok := range tokens {
		if err := validPrincipalName(name); err != nil {
			return nil, err
		}
		// The error never quotes the token.
		if len(tok) < minTokenBytes {
			return nil, fmt.Errorf("proxy: the token for principal %s is %d bytes; at least %d are required", name, len(tok), minTokenBytes)
		}
		for _, b := range tok {
			if b <= ' ' || b >= 0x7f {
				return nil, fmt.Errorf("proxy: the token for principal %s contains white space, a control character or a non-ASCII byte", name)
			}
		}
		d := sha256.Sum256(tok)
		if other, dup := seen[d]; dup {
			return nil, fmt.Errorf("proxy: principals %s and %s have the same token", min(name, other), max(name, other))
		}
		seen[d] = name
		out = append(out, tokenEntry{name: name, digest: d})
	}
	slices.SortFunc(out, func(a, b tokenEntry) int { return strings.Compare(a.name, b.name) })
	return out, nil
}

// validPrincipalName checks a principal name: 1 to 64 of [A-Za-z0-9_.:-].
func validPrincipalName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("proxy: principal name %q must be 1 to 64 characters", clip(name))
	}
	for _, r := range name {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.:-", r)
		if !ok {
			return fmt.Errorf("proxy: principal name %q may contain only letters, digits and _.:-", clip(name))
		}
	}
	return nil
}

// shortHash is the first 12 hex digits of s's SHA-256: how session ids
// appear in logs. Never log one in full.
func shortHash(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:6])
}

// contextPrincipal returns the principal authenticated for an HTTP request,
// from its context, or "" (before authentication). Attribution only; see
// [HTTPOptions].
func contextPrincipal(ctx context.Context) string {
	if ti := auth.TokenInfoFromContext(ctx); ti != nil {
		return ti.UserID
	}
	return ""
}

// principalOf is the principal a tools/call arrived with over HTTP, or "".
// go-sdk copies the HTTP request's TokenInfo into every JSON-RPC request's
// Extra, per POST, so this is right for stateful sessions too, whose
// handler context is detached from the POST.
func principalOf(req *mcp.CallToolRequest) string {
	if req == nil || req.Extra == nil || req.Extra.TokenInfo == nil {
		return ""
	}
	return req.Extra.TokenInfo.UserID
}

// listenerKey marks the context of every request the listener has
// authenticated (serveAuthed). go-sdk builds each session's context from
// the context of the HTTP request that created it (the initialise POST for
// a stateful session, the request itself for a stateless one) and keeps its
// values, so the tool handler's context carries the mark whatever go-sdk
// puts in the request's Extra.
type listenerKey struct{}

// fromListener reports whether ctx belongs to a request the listener
// authenticated.
func fromListener(ctx context.Context) bool {
	marked, _ := ctx.Value(listenerKey{}).(bool)
	return marked
}

// transportOf is the agent transport a tools/call arrived on: http when
// its context carries the listener's mark (serveAuthed), or when go-sdk set
// the request's Extra with an HTTP header or a TokenInfo, as its Streamable
// HTTP server does on every request it serves (streamable.go); otherwise a
// session Proxy.Run serves, whose stdio and in-memory transports set
// neither and whose context is never marked.
//
// Either sign is enough for http, so a listener call cannot read as stdio
// if a go-sdk release stops setting Extra: the mark alone still says http
// (L1 in the security review of T0.48). A call that reads as http but has
// no principal (principalOf) is refused before dispatch (Proxy.handler),
// so it binds neither the local agent's {stdio, ""} nor an {http, ""} that
// no listener request can have (TestListenerCallWithoutExtra). A request
// with no Extra and no mark is stdio with no principal, and that binding
// cannot open a state issued over the listener, whose principal is never
// empty (TestTransportOfFailsClosed).
func transportOf(ctx context.Context, req *mcp.CallToolRequest) agentTransport {
	if fromListener(ctx) {
		return transportHTTP
	}
	if req != nil && req.Extra != nil && (req.Extra.Header != nil || req.Extra.TokenInfo != nil) {
		return transportHTTP
	}
	return transportStdio
}

// httpHandler is the chain HTTPHandler returns.
type httpHandler struct {
	p         *Proxy
	opts      HTTPOptions
	logger    *slog.Logger
	tokens    []tokenEntry
	stateful  *mcp.StreamableHTTPHandler
	stateless *mcp.StreamableHTTPHandler
	authed    http.Handler // RequireBearerToken around serveAuthed

	lastAuthLog atomic.Int64 // unix nanoseconds; rate-limits refusal logs
	// useSeq orders session use for eviction: register, endPOST and endGET
	// take the next value (liveSession.lastSeq). A counter, not a clock,
	// because a coarse clock (Windows) gives two uses the same time.
	useSeq atomic.Uint64

	mu                   sync.Mutex
	inFlight             int
	perPrincipal         map[string]int
	sessions             int
	sessionsPerPrincipal map[string]int
	live                 map[string]*liveSession // stateful sessions by id
	// early counts the POSTs in progress on a session id that is not (yet)
	// in live, by id and principal: a POST can arrive on a new session
	// before settleSession has registered it (S7 in the security review of
	// T0.40), and the registration counts it as in progress. Entries last
	// only as long as their POSTs, so the POST caps bound the map.
	early map[earlySession]int
	// earlyGets counts the GET streams open on a session id that is not
	// (yet) in live, in the same way, so a stream opened before the session
	// is registered still keeps it from being evicted (T0.57). Entries last
	// only as long as their streams: go-sdk answers a GET on an id it does
	// not know with 404 at once, and a stream holds one of the listener's
	// 128 connections.
	earlyGets map[earlySession]int
	// capLog rate-limits the Warn line of a session-cap refusal per
	// principal (capLogAllowLocked). Principals are configured, so the map is
	// bounded by the tokens.
	capLog map[string]*capLogState
	// evictClosed, set by tests under mu, runs after an evicted session's
	// go-sdk Close has returned and before its tombstone leaves live.
	evictClosed func(sid string)
}

// capLogState is one principal's session-cap refusal log state.
type capLogState struct {
	last       time.Time
	suppressed int
}

// capLogInterval is the least time between two session-cap refusal lines
// for one principal.
const capLogInterval = time.Second

// earlySession names a session id and a principal whose requests are
// counted before the session is registered (httpHandler.early and
// earlyGets).
type earlySession struct{ sid, principal string }

// HTTPHandler returns the Streamable HTTP handler for the agent side, serving
// HTTPPath for both protocol eras with every check in the list at the top of
// http.go. It can be built once per Proxy. It fails if opts is invalid or if
// MCPGODEBUG is set in the environment (go-sdk's compatibility switches
// would change transport security unseen).
//
// The caller owns the listener, its connection cap and the http.Server
// (ADR 0016). It must register [Proxy.Close] to run when the server shuts
// down, srv.RegisterOnShutdown(func() { _ = p.Close() }), and call Close
// again after Shutdown returns, which waits for the first Close to finish.
// Shutdown alone does not end a 2025-era session's open GET stream, so
// without the hook it waits for its deadline; Close cancels the calls in
// flight and closes every agent session, which ends those streams.
func (p *Proxy) HTTPHandler(opts HTTPOptions) (http.Handler, error) {
	if _, set := os.LookupEnv("MCPGODEBUG"); set {
		return nil, ErrMCPGODEBUG
	}
	o, err := opts.resolved()
	if err != nil {
		return nil, err
	}
	tokens, err := checkTokens(o.Tokens)
	if err != nil {
		return nil, err
	}
	o.Tokens = nil // only digests are kept
	limits := newCallLimits(o.MaxCallsPerSession, o.MaxCallsPerPrincipal)
	limits.orphanTTL = o.OrphanTTL
	if !p.limits.CompareAndSwap(nil, limits) {
		return nil, errors.New("proxy: HTTPHandler was already built for this proxy")
	}
	h := &httpHandler{
		p:                    p,
		opts:                 o,
		logger:               p.logger,
		tokens:               tokens,
		perPrincipal:         make(map[string]int),
		sessionsPerPrincipal: make(map[string]int),
		live:                 make(map[string]*liveSession),
		early:                make(map[earlySession]int),
		earlyGets:            make(map[earlySession]int),
		capLog:               make(map[string]*capLogState),
	}
	getServer := func(*http.Request) *mcp.Server { return p.server }
	sdkLogger := slog.New(minLevel{p.logger.Handler(), slog.LevelWarn})
	// Neither handler sets JSONResponse: with it, go-sdk sends a call's
	// progress to the standalone stream, apart from (and possibly after) the
	// call's result (T4 in the review of PR #63; pinned by
	// TestHTTPProgressNeverFollowsResult). Neither has an EventStore (no
	// resumption), and neither sets DisableLocalhostProtection.
	//
	// go-sdk's own SessionTimeout stays set as a backstop, but fathomgate
	// runs its own idle expiry on the same clock (liveSession): go-sdk's
	// idle Close waits for the session's calls instead of cancelling them,
	// so a call stuck upstream would pin the session and its slot forever.
	h.stateful = mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{
		Logger:              sdkLogger,
		SessionTimeout:      o.SessionTimeout,
		MaxRequestBodyBytes: maxRequestBodyBytes,
	})
	h.stateless = mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{
		Stateless:                    true,
		Logger:                       sdkLogger,
		MaxRequestBodyBytes:          maxRequestBodyBytes,
		PropagateRequestCancellation: true,
	})
	h.authed = auth.RequireBearerToken(h.verify, &auth.RequireBearerTokenOptions{
		// The token carries no expiry; it is valid while configured.
		AllowMissingExpiration: true,
	})(http.HandlerFunc(h.serveAuthed))
	return h, nil
}

// ServeHTTP runs the checks in order and hands the request to go-sdk.
func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	// The previous request on a keep-alive connection left a deadline armed
	// for its final flush (finish); nothing of this request may inherit it.
	_ = rc.SetWriteDeadline(time.Time{})
	dw := &deadlineWriter{w: w, rc: rc, timeout: h.opts.WriteTimeout}
	defer dw.finish()
	// The body must arrive within BodyReadTimeout. The read deadline is
	// cleared once the body has been read to its end, before net/http starts
	// its background read (which would cancel the request on a deadline;
	// net/http 1.26 and later also clear it when they start that read). A
	// request without a body gets none: net/http has already started that
	// background read.
	if r.Body != nil && r.Body != http.NoBody {
		if err := rc.SetReadDeadline(time.Now().Add(h.opts.BodyReadTimeout)); err == nil {
			r.Body = &deadlineBody{ReadCloser: r.Body, rc: rc}
		}
	}

	switch {
	case !hostAllowed(r):
		http.Error(dw, "Forbidden: invalid Host header", http.StatusForbidden)
		return
	case crossOrigin(r):
		http.Error(dw, "Forbidden: requests with an Origin header or from another site are not accepted", http.StatusForbidden)
		return
	case r.URL.Path != HTTPPath:
		http.NotFound(dw, r)
		return
	}
	h.authed.ServeHTTP(&authWriter{ResponseWriter: dw, h: h, r: r}, r)
}

// hostAllowed mirrors go-sdk's DNS-rebinding check, so it runs before
// authentication: a request that arrived on a loopback address must name a
// loopback host. From M1, --listen-host extends this (ADR 0016).
func hostAllowed(r *http.Request) bool {
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || local == nil || !isLoopback(local.String()) {
		return true
	}
	return isLoopback(r.Host)
}

// isLoopback reports whether addr (host or host:port) is localhost or a
// loopback IP, as go-sdk's internal util.IsLoopback does.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = strings.Trim(addr, "[]")
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// crossOrigin reports a request a browser sent on behalf of a page: any
// Origin header, or a Sec-Fetch-Site other than none or same-origin. MCP
// agents are not browsers and send neither. This is not the standard
// library's CrossOriginProtection, which exempts GET, HEAD and OPTIONS and
// accepts an Origin equal to Host (what a DNS-rebinding page sends).
func crossOrigin(r *http.Request) bool {
	if _, ok := r.Header["Origin"]; ok {
		return true
	}
	for _, v := range r.Header.Values("Sec-Fetch-Site") {
		if v != "none" && v != "same-origin" {
			return true
		}
	}
	return false
}

// verify is the auth.TokenVerifier: SHA-256 of the presented token compared
// in constant time with every configured digest, without stopping at a
// match, so neither the length nor the content nor which token matched
// shows in the timing.
func (h *httpHandler) verify(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	d := sha256.Sum256([]byte(token))
	match := -1
	for i, e := range h.tokens {
		eq := subtle.ConstantTimeCompare(d[:], e.digest[:])
		match = subtle.ConstantTimeSelect(eq, i, match)
	}
	if match < 0 {
		return nil, auth.ErrInvalidToken
	}
	return &auth.TokenInfo{UserID: h.tokens[match].name}, nil
}

// authWriter wraps the response across go-sdk's auth middleware only: on a
// 401 it adds WWW-Authenticate: Bearer (the middleware adds it only with
// OAuth metadata) and logs the refusal, at most once per second.
type authWriter struct {
	http.ResponseWriter
	h *httpHandler
	r *http.Request
}

// WriteHeader adds the challenge and logs the refusal on a 401.
func (a *authWriter) WriteHeader(code int) {
	if code == http.StatusUnauthorized {
		if a.Header().Get("WWW-Authenticate") == "" {
			a.Header().Set("WWW-Authenticate", "Bearer")
		}
		a.h.logRefusal(a.r)
	}
	a.ResponseWriter.WriteHeader(code)
}

// logRefusal logs a failed authentication with the remote address and the
// reason, never the header's value, at most once per second.
func (h *httpHandler) logRefusal(r *http.Request) {
	now := time.Now().UnixNano()
	last := h.lastAuthLog.Load()
	if now-last < int64(time.Second) || !h.lastAuthLog.CompareAndSwap(last, now) {
		return
	}
	reason := "unknown token"
	switch f := strings.Fields(r.Header.Get("Authorization")); {
	case len(f) == 0:
		reason = "no Authorization header"
	case len(f) != 2 || !strings.EqualFold(f[0], "bearer"):
		reason = "not a bearer token"
	}
	h.logger.Warn("listener: authentication failed", "remote", r.RemoteAddr, "reason", reason)
}

// serveAuthed runs after authentication: it marks the request's context as
// the listener's, then runs the POST caps, era dispatch and the session
// cap.
func (h *httpHandler) serveAuthed(w http.ResponseWriter, r *http.Request) {
	if aw, ok := w.(*authWriter); ok {
		w = aw.ResponseWriter
	}
	// Every call this request carries, or a session it creates carries,
	// reads as http from here on (transportOf).
	r = r.WithContext(context.WithValue(r.Context(), listenerKey{}, true))
	principal := contextPrincipal(r.Context())
	if r.Method == http.MethodPost {
		release, ok := h.acquirePOST(principal)
		if !ok {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Service Unavailable: too many requests in flight", http.StatusServiceUnavailable)
			return
		}
		defer release()
	}
	if statelessRequest(r) {
		h.stateless.ServeHTTP(w, r)
		return
	}
	sid := r.Header.Get("Mcp-Session-Id")
	switch {
	case r.Method == http.MethodDelete && sid != "":
		// go-sdk's session Close waits for calls in flight; cancel them
		// first, if the session is this principal's.
		// A call go-sdk has delivered but fathomgate has not yet admitted is
		// not cancelled here, and go-sdk's Close then waits for it. The
		// DELETE does not pause the idle clock, so the idle expiry retires
		// the session and cancels that call after SessionTimeout (threat
		// model row 34, T0.57).
		if n := h.p.limits.Load().cancelSession(sid, principal); n > 0 {
			h.logger.Info("agent session deleted; cancelling its calls", "session", shortHash(sid), "principal", principal, "calls", n)
		} else {
			h.logger.Debug("agent session DELETE received", "session", shortHash(sid), "principal", principal)
		}
	case r.Method == http.MethodPost && sid != "":
		// A POST on the session's own principal's behalf pauses fathomgate's
		// idle expiry, as it pauses go-sdk's; another principal's gets 403
		// from go-sdk and touches nothing. That includes a POST that
		// arrives before the session is registered (beginPOST). A POST on
		// an evicted session gets 404, as it will once go-sdk has closed it.
		end, ok := h.beginPOST(sid, principal)
		if !ok {
			http.Error(w, "Not Found: session not found", http.StatusNotFound)
			return
		}
		defer end()
	case r.Method == http.MethodGet && sid != "":
		// An open GET stream makes a session ineligible for eviction; it
		// does not pause the idle clock (liveSession).
		end, ok := h.beginGET(sid, principal)
		if !ok {
			http.Error(w, "Not Found: session not found", http.StatusNotFound)
			return
		}
		defer end()
	case r.Method == http.MethodPost && sid == "":
		// go-sdk creates a session for every session-less POST on the
		// stateful handler, and keeps it if the POST was an initialise.
		slot, reason := h.reserveSession(principal)
		if slot == nil {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Service Unavailable: "+reason, http.StatusServiceUnavailable)
			return
		}
		defer h.settleSession(w, principal, slot)
	}
	h.stateful.ServeHTTP(w, r)
}

// statelessRequest reports a request for the stateless handler:
// MCP-Protocol-Version at or after 2026-07-28 (string comparison, as
// eraOf). Everything else, malformed requests included, goes to the
// stateful handler, which answers with go-sdk's own errors.
func statelessRequest(r *http.Request) bool {
	v := r.Header.Get("Mcp-Protocol-Version")
	return v != "" && v >= statelessVersion
}

// acquirePOST takes one slot of the overall and the principal's POST caps.
func (h *httpHandler) acquirePOST(principal string) (func(), bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inFlight >= h.opts.MaxInFlight || h.perPrincipal[principal] >= h.opts.MaxInFlightPerPrincipal {
		return nil, false
	}
	h.inFlight++
	h.perPrincipal[principal]++
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.inFlight--
		if h.perPrincipal[principal]--; h.perPrincipal[principal] <= 0 {
			delete(h.perPrincipal, principal)
		}
	}, true
}

// sessionSlot is one stateful session's place under the session caps,
// overall and for its principal. It is released once: when the session
// ends, when go-sdk did not keep it, or when it is evicted (T0.57), which
// hands the slot to the initialise that evicted it before the evicted
// session has finished closing.
type sessionSlot struct {
	h         *httpHandler
	principal string
	released  bool // guarded by h.mu
}

// releaseLocked gives the slot back. Callers hold h.mu.
func (s *sessionSlot) releaseLocked() {
	if s.released {
		return
	}
	s.released = true
	s.h.sessions--
	if s.h.sessionsPerPrincipal[s.principal]--; s.h.sessionsPerPrincipal[s.principal] <= 0 {
		delete(s.h.sessionsPerPrincipal, s.principal)
	}
}

// release gives the slot back.
func (s *sessionSlot) release() {
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	s.releaseLocked()
}

// reserveSession takes one stateful session slot, overall and for
// principal, or returns nil and the reason for the 503. go-sdk has no
// session cap and Server.Sessions also lists stateless requests' sessions,
// so fathomgate counts its own.
//
// When a cap is reached, the principal's own least recently used idle
// session is evicted to make room (T0.57, ADR 0016 amendment of
// 2026-09-25): an agent that restarts without a DELETE (a crash, or an SDK
// whose close does not send one) would otherwise be refused a session until
// its old ones reached SessionTimeout. Idle means no POST in progress, no
// GET stream open and no call in flight, and the last is claimed, not just
// checked (claimEvictableLocked), so eviction never cancels a call, never
// cuts a stream, and never lets a call start on the session it evicted.
// Only the same principal's sessions are candidates: one principal can
// never end another's. With no idle session of its own, the initialise gets
// 503 as before, so the caps still bound the sessions that are in use; the
// 503 is logged with what kept each of the principal's sessions in use
// (capLogAllowLocked).
func (h *httpHandler) reserveSession(principal string) (*sessionSlot, string) {
	h.mu.Lock()
	var evicted []*liveSession
	var inUse sessionUse
	logRefusal, suppressed := false, 0
	reason := ""
	for {
		switch {
		case h.sessionsPerPrincipal[principal] >= h.opts.MaxSessionsPerPrincipal:
			reason = "too many sessions open for this principal"
		case h.sessions >= h.opts.MaxSessions:
			reason = "too many sessions open"
		default:
			reason = ""
		}
		if reason == "" {
			break
		}
		victim := h.claimEvictableLocked(principal)
		if victim == nil {
			inUse = h.useLocked(principal)
			logRefusal, suppressed = h.capLogAllowLocked(principal, time.Now())
			break
		}
		h.evictLocked(victim)
		evicted = append(evicted, victim)
	}
	var slot *sessionSlot
	if reason == "" {
		h.sessions++
		h.sessionsPerPrincipal[principal]++
		slot = &sessionSlot{h: h, principal: principal}
	}
	h.mu.Unlock()
	for _, ls := range evicted {
		h.closeEvicted(ls)
	}
	if logRefusal {
		h.logger.Warn("listener: new session refused: "+reason+" and none of the principal's sessions is idle",
			"principal", principal, "sessions", inUse.sessions, "posting", inUse.posting, "streaming", inUse.streaming,
			"calling", inUse.calling, "closing", inUse.closing, "suppressed", suppressed)
	}
	return slot, reason
}

// sessionUse counts what keeps a principal's live sessions from being
// evicted, for the log line of a session-cap 503. A session can count
// under more than one heading.
type sessionUse struct {
	sessions, posting, streaming, calling, closing int
}

// useLocked counts principal's live sessions and what keeps each in use.
// Callers hold h.mu.
func (h *httpHandler) useLocked(principal string) sessionUse {
	limits := h.p.limits.Load()
	var u sessionUse
	for _, ls := range h.live {
		if ls.principal != principal {
			continue
		}
		u.sessions++
		ls.mu.Lock()
		active, gets, stopped := ls.active, ls.gets, ls.stopped
		ls.mu.Unlock()
		if stopped || ls.evicted {
			u.closing++
			continue
		}
		if active > 0 {
			u.posting++
		}
		if gets > 0 {
			u.streaming++
		}
		if limits.busy(ls.ss) {
			u.calling++
		}
	}
	return u
}

// capLogAllowLocked reports whether a session-cap refusal for principal
// may be logged at now, at most one line per capLogInterval per principal
// (so one principal's refusals never hide another's), and how many lines
// for that principal were held back since the last one, which the line
// reports as suppressed. An operator can tell from the line whether a
// client is holding streams open on sessions it no longer uses (T0.57).
// Callers hold h.mu.
func (h *httpHandler) capLogAllowLocked(principal string, now time.Time) (bool, int) {
	st := h.capLog[principal]
	if st == nil {
		st = &capLogState{}
		h.capLog[principal] = st
	}
	if !st.last.IsZero() && now.Sub(st.last) < capLogInterval {
		st.suppressed++
		return false, 0
	}
	n := st.suppressed
	st.last, st.suppressed = now, 0
	return true, n
}

// claimEvictableLocked returns principal's least recently used session that
// is idle and claims it for eviction, or nil if it has none. A session is
// a candidate when it has no POST in progress, no GET stream open and is
// not stopped (liveSession.idleState). Candidates are tried in order of
// last use, and the first one callLimits.claimIdle retires, because it has
// no call in flight, is the one returned: the check and the retirement are
// one step under callLimits.mu, so a call go-sdk has delivered but not yet
// admitted is refused by admit rather than run on the evicted session.
// Callers hold h.mu; claimIdle then takes callLimits.mu (lock order h.mu,
// then callLimits.mu).
func (h *httpHandler) claimEvictableLocked(principal string) *liveSession {
	type candidate struct {
		ls  *liveSession
		seq uint64
	}
	var cands []candidate
	for _, ls := range h.live {
		if ls.principal != principal || ls.evicted {
			continue
		}
		if seq, _, idle := ls.idleState(); idle {
			cands = append(cands, candidate{ls, seq})
		}
	}
	slices.SortFunc(cands, func(a, b candidate) int { return cmp.Compare(a.seq, b.seq) })
	limits := h.p.limits.Load()
	for _, c := range cands {
		if limits.claimIdle(c.ls.ss) {
			return c.ls
		}
	}
	return nil
}

// evictLocked takes ls out of service: its slot goes back at once, its idle
// clock stops, and every later request on its id gets 404 from fathomgate
// (serveAuthed), which tells a 2025-era client to start a new session. The
// go-sdk session is closed by closeEvicted, after h.mu is released. Callers
// hold h.mu, and have claimed ls (claimEvictableLocked), so callLimits
// refuses every call on it from now on.
func (h *httpHandler) evictLocked(ls *liveSession) {
	ls.evicted = true
	ls.stop()
	if ls.slot != nil {
		ls.slot.releaseLocked()
	}
}

// closeEvicted closes an evicted session's go-sdk session on a goroutine
// callLimits tracks, which Proxy.Close joins. The session had no call in
// flight when it was claimed and callLimits refuses any since, so go-sdk's
// Close waits for nothing. If the proxy is already closing, Proxy.Close
// closes the session itself.
//
// The evicted session stays in live, as a tombstone that answers its own
// principal 404 (beginPOST, beginGET), until ss.Close has returned, and only
// then is it forgotten (forgetEvicted). go-sdk's Close closes the connection,
// which ends Wait and so wakes the session's watcher (settleSession), before
// it runs the onClose that takes the id out of go-sdk's handler. In between,
// go-sdk still finds the session and answers a call on it 200 with an empty
// body instead of 404, so the watcher must not be the one to drop the entry:
// a client told 200 would not start a new session.
//
// The eviction's Info line is not rate-limited: each one needs an
// initialise, and the POST caps (64 overall, 32 per principal) bound those.
//
// If the principal's own DELETE runs go-sdk's Close at the same moment and
// wins it, this Close can return while that DELETE is still removing the
// id, leaving a tiny window of an empty 200; it affects only the principal
// that sent the DELETE, which already asked for the session to end.
func (h *httpHandler) closeEvicted(ls *liveSession) {
	_, since, _ := ls.idleState()
	h.logger.Info("agent session evicted: its principal reached a session cap and this was its least recently used idle session",
		"session", shortHash(ls.sid), "principal", ls.principal, "idle", time.Since(since).Round(time.Second).String())
	limits := h.p.limits.Load()
	started := limits.track(func() {
		if err := ls.ss.Close(); err != nil {
			h.logger.Debug("closing an evicted agent session", "session", shortHash(ls.sid), "error", err)
		}
		h.mu.Lock()
		hook := h.evictClosed
		h.mu.Unlock()
		if hook != nil {
			hook(ls.sid)
		}
		h.forgetEvicted(ls)
	})
	if !started {
		// The proxy is closing and Proxy.Close closes the session; nothing
		// is served any more, so the tombstone has no one to answer.
		h.forgetEvicted(ls)
	}
}

// forgetEvicted takes an evicted session's tombstone out of live.
func (h *httpHandler) forgetEvicted(ls *liveSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.live[ls.sid] == ls {
		delete(h.live, ls.sid)
	}
}

// settleSession runs after the stateful handler served a session-less POST.
// If go-sdk kept the session, the slot is held until the session ends: by
// DELETE, fathomgate's idle expiry (liveSession) or Proxy.Close. Otherwise the
// slot is released now.
//
// A session go-sdk kept is one whose id the response carries and which is
// still among the server's sessions: go-sdk names the new session in the
// response of every session-less POST, and closes it again at the end of
// that request unless it was an initialise. Fathomgate registers whatever is
// left, without asking for initialise parameters (J2 in the re-review of
// PR #72): go-sdk's own idle timer is the longer of the two, so a session
// fathomgate did not register would be invisible to its idle accounting, which
// is what cancels a call stuck upstream.
//
// The goroutine that waits for the session to end is tracked by callLimits
// and joined by Proxy.Close. If the proxy is already closing, the session is
// closed at once instead.
func (h *httpHandler) settleSession(w http.ResponseWriter, principal string, slot *sessionSlot) {
	release := slot.release
	sid := w.Header().Get("Mcp-Session-Id")
	var kept *mcp.ServerSession
	if sid != "" {
		for ss := range h.p.server.Sessions() {
			if ss.ID() == sid {
				kept = ss
				break
			}
		}
	}
	if kept == nil {
		release()
		return
	}
	limits := h.p.limits.Load()
	ls := &liveSession{h: h, ss: kept, sid: sid, principal: principal, slot: slot}
	h.register(ls)
	started := limits.track(func() {
		_ = kept.Wait()
		// stop waits on ls.mu, so an expire that retired the session has
		// finished doing so (it retires under ls.mu).
		ls.stop()
		h.mu.Lock()
		// An evicted session's entry is closeEvicted's to remove, once
		// go-sdk has forgotten the id too (forgetEvicted); evicted is set
		// under h.mu, so this read cannot miss an eviction.
		if h.live[sid] == ls && !ls.evicted {
			delete(h.live, sid)
		}
		// The session is closed. Nothing can retire it after this forget:
		// if it was not evicted it has left live, and eviction claims only
		// sessions in live, under h.mu; if it was evicted its entry stays in
		// live until forgetEvicted, but claimEvictableLocked skips evicted
		// entries and expire returns once stop has run. So the retired set
		// cannot keep a closed session (the #121 leak).
		limits.forget(kept)
		h.mu.Unlock()
		h.p.counters.forgetSession("s" + sid)
		release()
		h.logger.Info("agent session closed", "session", shortHash(sid), "principal", principal)
	})
	if !started {
		h.mu.Lock()
		delete(h.live, sid)
		h.mu.Unlock()
		_ = kept.Close()
		release()
		return
	}
	ls.arm()
	// A session that has not initialised yet has no negotiated protocol.
	protocol := ""
	if ip := kept.InitializeParams(); ip != nil {
		protocol = ip.ProtocolVersion
	}
	h.logger.Info("agent session opened", "session", shortHash(sid), "principal", principal, "protocol", protocol)
}

// register makes ls the live session for its id. The POSTs of its
// principal already in progress on that id (beginPOST) count as in
// progress on ls, so arm does not start the idle clock under them.
//
// Without this (S7 in the security review of T0.40), settleSession runs
// only after the stateful handler has sent the response that names the new
// session, so an agent that POSTs again at once (its first tools/call, say)
// found no live session, paused nothing, and the idle clock then started
// with that POST still in progress: a call made in it could be cancelled at
// SessionTimeout while it ran.
func (h *httpHandler) register(ls *liveSession) {
	k := earlySession{ls.sid, ls.principal}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.live[ls.sid] = ls
	ls.mu.Lock()
	ls.active += h.early[k]
	ls.gets += h.earlyGets[k]
	ls.touchLocked()
	ls.mu.Unlock()
	delete(h.early, k)
	delete(h.earlyGets, k)
}

// beginPOST marks a POST on session sid on principal's behalf as in
// progress and returns the function that marks it ended. On a live session
// of that principal it pauses the idle clock (startPOST). On an id that is
// not live yet it is counted in early, which register adds to the session
// if it is registered while the POST is still in progress. Another
// principal's POST on a live session gets 403 from go-sdk and pauses
// nothing.
//
// Session ids are never reused, so a POST counted in early that finds a
// live session when it ends was counted by register into that session.
//
// ok is false for a POST of the session's own principal on a session
// fathomgate has evicted (reserveSession): the caller answers 404 and the
// POST never reaches go-sdk, so nothing can start on a session that is
// being closed. Another principal's POST on it still gets go-sdk's 403.
func (h *httpHandler) beginPOST(sid, principal string) (end func(), ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ls := h.live[sid]; ls != nil {
		if ls.principal != principal {
			return func() {}, true
		}
		if ls.evicted {
			return nil, false
		}
		ls.startPOST()
		return ls.endPOST, true
	}
	k := earlySession{sid, principal}
	h.early[k]++
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if ls := h.live[sid]; ls != nil && ls.principal == principal {
			ls.endPOST()
			return
		}
		// Not registered, or registered and already gone: either way the
		// count is ours to take back, if it is still there.
		if h.early[k] > 0 {
			if h.early[k]--; h.early[k] == 0 {
				delete(h.early, k)
			}
		}
	}, true
}

// liveSession is fathomgate's idle expiry for one stateful session (H2 in the
// review of PR #68). It mirrors go-sdk's: the clock runs while no POST for
// the session is in progress (a GET stream does not stop it) and is reset
// when the last one ends. When it runs out, the session's calls are
// cancelled first and only then is the session closed, because go-sdk's
// Close waits for calls in flight and a call stuck upstream would otherwise
// hold the session, and its slot, forever. The timer's callback is owned by
// the session; it returns once the session is closed.
//
// The idle clock is a real-time clock (time.AfterFunc), not the proxy's
// Proxy.now, which tests replace to drive the progress rate limit and the
// orphan expiry. It has to be: it must fire on its own, with no request to
// carry a clock reading in, and it mirrors go-sdk's timer, which is
// real-time too. Tests shorten SessionTimeout instead of moving a clock
// (K3 in the re-review of PR #72).
type liveSession struct {
	h         *httpHandler
	ss        *mcp.ServerSession
	sid       string
	principal string
	// slot is the session's place under the session caps (settleSession).
	slot *sessionSlot
	// evicted is set, under h.mu, when reserveSession has taken the
	// session out of service to make room for its principal's new one.
	evicted bool

	mu      sync.Mutex
	active  int // POSTs in progress
	gets    int // GET streams open (beginGET)
	timer   *time.Timer
	stopped bool // the session has ended, expired or been evicted; the timer is dead
	// running reports that the idle clock is counting down: armed, no POST
	// in progress, not stopped. Kept beside the timer so it can be read
	// without touching the timer.
	running bool
	// lastSeq orders the session's last use (registration, or the end of a
	// POST or GET) against every other session's, from httpHandler.useSeq:
	// how eviction picks the least recently used idle session. lastUsed is
	// the same moment on the clock, for the eviction log line only.
	lastSeq  uint64
	lastUsed time.Time
}

// touchLocked records a use of the session now. Callers hold s.mu.
func (s *liveSession) touchLocked() {
	s.lastSeq = s.h.useSeq.Add(1)
	s.lastUsed = time.Now()
}

// idleState reports whether the session is a candidate for eviction (no
// POST in progress, no GET stream open, not stopped), and its last use as a
// sequence number and a time. Calls in flight are callLimits' to decide
// (claimIdle): a 2025-era call whose POST was dropped keeps the session in
// use.
func (s *liveSession) idleState() (seq uint64, since time.Time, idle bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeq, s.lastUsed, s.active == 0 && s.gets == 0 && !s.stopped
}

// beginGET marks a GET stream of principal on session sid as open and
// returns the function that marks it closed. ok is false for the session's
// own principal on an evicted session (404, as for beginPOST). Another
// principal's GET is left to go-sdk's 403 and counted nowhere. A GET on an
// id that is not live yet is counted in earlyGets, which register adds to
// the session, as beginPOST does for POSTs: an agent can open its stream
// as soon as it has the id from the initialise response, before
// settleSession has registered the session.
func (h *httpHandler) beginGET(sid, principal string) (end func(), ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ls := h.live[sid]; ls != nil {
		if ls.principal != principal {
			return func() {}, true
		}
		if ls.evicted {
			return nil, false
		}
		ls.startGET()
		return ls.endGET, true
	}
	k := earlySession{sid, principal}
	h.earlyGets[k]++
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if ls := h.live[sid]; ls != nil && ls.principal == principal {
			ls.endGET()
			return
		}
		if h.earlyGets[k] > 0 {
			if h.earlyGets[k]--; h.earlyGets[k] == 0 {
				delete(h.earlyGets, k)
			}
		}
	}, true
}

// startGET counts an open GET stream: while one is open the session is in
// use and cannot be evicted. It does not touch the idle clock, which only
// POSTs pause (as in go-sdk).
func (s *liveSession) startGET() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
}

// endGET counts a GET stream closed and records the use, so the session
// moves to the back of the eviction order (touchLocked).
func (s *liveSession) endGET() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets--
	s.touchLocked()
}

// arm starts the idle clock once the session is registered.
func (s *liveSession) arm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.timer != nil {
		return
	}
	s.timer = time.AfterFunc(s.h.opts.SessionTimeout, s.expire)
	s.running = true
	if s.active > 0 {
		s.timer.Stop()
		s.running = false
	}
}

func (s *liveSession) startPOST() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == 0 && s.timer != nil {
		s.timer.Stop()
		s.running = false
	}
	s.active++
}

func (s *liveSession) endPOST() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	s.touchLocked()
	if s.active == 0 && s.timer != nil && !s.stopped {
		s.timer.Reset(s.h.opts.SessionTimeout)
		s.running = true
	}
}

// stop kills the idle clock for good.
func (s *liveSession) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	s.running = false
	if s.timer != nil {
		s.timer.Stop()
	}
}

// expire runs when the idle clock runs out: it retires the session, which
// cancels its calls and refuses any call go-sdk delivered but had not yet
// admitted (callLimits.retire, T0.57), then closes the session. Without
// the retirement such a call would start after the cancellation and run on
// a closing session, which go-sdk's Close waits for with no idle clock left
// to cancel it. A POST that started meanwhile wins.
//
// The retirement happens under s.mu, so the session's watcher
// (settleSession), whose stop waits on s.mu, calls callLimits.forget only
// after it: a retirement can never land after the forget and leave a
// closed session in the retired set. Lock order: liveSession.mu, then
// callLimits.mu (nothing takes callLimits.mu and then a liveSession.mu).
func (s *liveSession) expire() {
	s.mu.Lock()
	if s.stopped || s.active > 0 {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	s.running = false
	n := s.h.p.limits.Load().retire(s.ss)
	s.mu.Unlock()
	s.h.logger.Info("agent session idle; closing it", "session", shortHash(s.sid), "principal", s.principal, "calls_cancelled", n)
	if err := s.ss.Close(); err != nil {
		s.h.logger.Debug("closing an idle agent session", "session", shortHash(s.sid), "error", err)
	}
}

// deadlineWriter puts a write deadline on every write and flush to the
// agent, and clears it afterwards, so a stuck write returns within timeout
// (net/http then drops the connection and cancels the request) while an
// idle stream (a stateful GET, a call waiting on a device) has none. go-sdk
// writes each response under its stream's lock; mu serialises anyway.
type deadlineWriter struct {
	w       http.ResponseWriter
	rc      *http.ResponseController
	timeout time.Duration
	mu      sync.Mutex
}

// Header returns the response headers.
func (d *deadlineWriter) Header() http.Header { return d.w.Header() }

// WriteHeader sends the status line (buffered by net/http until a write or
// flush). A refusal also closes the connection (closesConnection).
func (d *deadlineWriter) WriteHeader(code int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if closesConnection(code) {
		d.w.Header().Set("Connection", "close")
	}
	d.w.WriteHeader(code)
}

// closesConnection reports a refusal after which net/http closes the
// connection (Connection: close) instead of keeping it alive: 401, 403,
// 404, 413 and 503. A refused client, authenticated or not, then holds none
// of the listener's connection slots.
func closesConnection(code int) bool {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusRequestEntityTooLarge, http.StatusServiceUnavailable:
		return true
	}
	return false
}

// Write writes b under the write deadline.
func (d *deadlineWriter) Write(b []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.arm()
	defer d.disarm()
	return d.w.Write(b)
}

// FlushError is what http.ResponseController.Flush (go-sdk's writeEvent)
// calls.
func (d *deadlineWriter) FlushError() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.arm()
	defer d.disarm()
	return d.rc.Flush()
}

// Flush is FlushError for callers that use http.Flusher.
func (d *deadlineWriter) Flush() { _ = d.FlushError() }

// Unwrap lets http.ResponseController reach the connection for anything
// deadlineWriter does not implement.
func (d *deadlineWriter) Unwrap() http.ResponseWriter { return d.w }

func (d *deadlineWriter) arm()    { _ = d.rc.SetWriteDeadline(time.Now().Add(d.timeout)) }
func (d *deadlineWriter) disarm() { _ = d.rc.SetWriteDeadline(time.Time{}) }

// finish arms the deadline for net/http's final flush after the handler
// returns (buffered data and the chunked terminator). The next request on
// the connection re-arms per write.
func (d *deadlineWriter) finish() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.arm()
}

// deadlineBody clears the body read deadline once the body has been read to
// its end or failed.
type deadlineBody struct {
	io.ReadCloser
	rc   *http.ResponseController
	once sync.Once
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(func() { _ = b.rc.SetReadDeadline(time.Time{}) })
	}
	return n, err
}
