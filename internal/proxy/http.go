package proxy

import (
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
//     principal's cap is reached gets 503.
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
	// `openssl rand -hex 32`); netguard checks their shape, not their
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
// even to an empty value. [Proxy.HTTPHandler] returns it, and cmd/netguard
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
	early map[earlyPOST]int
}

// earlyPOST names the POSTs counted in httpHandler.early.
type earlyPOST struct{ sid, principal string }

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
		early:                make(map[earlyPOST]int),
	}
	getServer := func(*http.Request) *mcp.Server { return p.server }
	sdkLogger := slog.New(minLevel{p.logger.Handler(), slog.LevelWarn})
	// Neither handler sets JSONResponse: with it, go-sdk sends a call's
	// progress to the standalone stream, apart from (and possibly after) the
	// call's result (T4 in the review of PR #63; pinned by
	// TestHTTPProgressNeverFollowsResult). Neither has an EventStore (no
	// resumption), and neither sets DisableLocalhostProtection.
	//
	// go-sdk's own SessionTimeout stays set as a backstop, but netguard
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

// serveAuthed runs after authentication: the POST caps, era dispatch and
// the session cap.
func (h *httpHandler) serveAuthed(w http.ResponseWriter, r *http.Request) {
	if aw, ok := w.(*authWriter); ok {
		w = aw.ResponseWriter
	}
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
		if n := h.p.limits.Load().cancelSession(sid, principal); n > 0 {
			h.logger.Info("agent session deleted; cancelling its calls", "session", shortHash(sid), "principal", principal, "calls", n)
		}
	case r.Method == http.MethodPost && sid != "":
		// A POST on the session's own principal's behalf pauses netguard's
		// idle expiry, as it pauses go-sdk's; another principal's gets 403
		// from go-sdk and touches nothing. That includes a POST that
		// arrives before the session is registered (beginPOST).
		defer h.beginPOST(sid, principal)()
	case r.Method == http.MethodPost && sid == "":
		// go-sdk creates a session for every session-less POST on the
		// stateful handler, and keeps it if the POST was an initialise.
		release, reason := h.reserveSession(principal)
		if release == nil {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Service Unavailable: "+reason, http.StatusServiceUnavailable)
			return
		}
		defer h.settleSession(w, principal, release)
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

// reserveSession takes one stateful session slot, overall and for
// principal, or returns nil and the reason for the 503. go-sdk has no
// session cap and Server.Sessions also lists stateless requests' sessions,
// so netguard counts its own.
func (h *httpHandler) reserveSession(principal string) (func(), string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.sessionsPerPrincipal[principal] >= h.opts.MaxSessionsPerPrincipal:
		return nil, "too many sessions open for this principal"
	case h.sessions >= h.opts.MaxSessions:
		return nil, "too many sessions open"
	}
	h.sessions++
	h.sessionsPerPrincipal[principal]++
	var once sync.Once
	return func() {
		once.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.sessions--
			if h.sessionsPerPrincipal[principal]--; h.sessionsPerPrincipal[principal] <= 0 {
				delete(h.sessionsPerPrincipal, principal)
			}
		})
	}, ""
}

// settleSession runs after the stateful handler served a session-less POST.
// If go-sdk kept the session, the slot is held until the session ends: by
// DELETE, netguard's idle expiry (liveSession) or Proxy.Close. Otherwise the
// slot is released now.
//
// A session go-sdk kept is one whose id the response carries and which is
// still among the server's sessions: go-sdk names the new session in the
// response of every session-less POST, and closes it again at the end of
// that request unless it was an initialise. Netguard registers whatever is
// left, without asking for initialise parameters (J2 in the re-review of
// PR #72): go-sdk's own idle timer is the longer of the two, so a session
// netguard did not register would be invisible to its idle accounting, which
// is what cancels a call stuck upstream.
//
// The goroutine that waits for the session to end is tracked by callLimits
// and joined by Proxy.Close. If the proxy is already closing, the session is
// closed at once instead.
func (h *httpHandler) settleSession(w http.ResponseWriter, principal string, release func()) {
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
	ls := &liveSession{h: h, ss: kept, sid: sid, principal: principal}
	h.register(ls)
	started := limits.track(func() {
		_ = kept.Wait()
		ls.stop()
		h.mu.Lock()
		if h.live[sid] == ls {
			delete(h.live, sid)
		}
		h.mu.Unlock()
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
	k := earlyPOST{ls.sid, ls.principal}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.live[ls.sid] = ls
	ls.mu.Lock()
	ls.active += h.early[k]
	ls.mu.Unlock()
	delete(h.early, k)
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
func (h *httpHandler) beginPOST(sid, principal string) func() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ls := h.live[sid]; ls != nil {
		if ls.principal != principal {
			return func() {}
		}
		ls.startPOST()
		return ls.endPOST
	}
	k := earlyPOST{sid, principal}
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
	}
}

// liveSession is netguard's idle expiry for one stateful session (H2 in the
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

	mu      sync.Mutex
	active  int // POSTs in progress
	timer   *time.Timer
	stopped bool // the session has ended or expired; the timer is dead
}

// arm starts the idle clock once the session is registered.
func (s *liveSession) arm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.timer != nil {
		return
	}
	s.timer = time.AfterFunc(s.h.opts.SessionTimeout, s.expire)
	if s.active > 0 {
		s.timer.Stop()
	}
}

func (s *liveSession) startPOST() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == 0 && s.timer != nil {
		s.timer.Stop()
	}
	s.active++
}

func (s *liveSession) endPOST() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	if s.active == 0 && s.timer != nil && !s.stopped {
		s.timer.Reset(s.h.opts.SessionTimeout)
	}
}

// stop kills the idle clock for good.
func (s *liveSession) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	if s.timer != nil {
		s.timer.Stop()
	}
}

// expire runs when the idle clock runs out: it cancels the session's calls,
// then closes the session. A POST that started meanwhile wins.
func (s *liveSession) expire() {
	s.mu.Lock()
	if s.stopped || s.active > 0 {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	s.mu.Unlock()
	n := s.h.p.limits.Load().cancelSession(s.sid, s.principal)
	s.h.logger.Info("agent session idle; closing it", "session", shortHash(s.sid), "principal", s.principal, "calls_cancelled", n)
	_ = s.ss.Close()
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
