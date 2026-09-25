// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tier 1 tests of the Streamable HTTP listener (T0.27, ADR 0016): both
// eras, every check and cap, over a real loopback socket (httptest) with the
// recording fake upstream in process.

var (
	tokAlice = []byte("FAKE-alice-token-0123456789abcdef0123")
	tokBob   = []byte("FAKE-bob-token-0123456789abcdef0123456")
	tokCarol = []byte("FAKE-carol-token-0123456789abcdef01234")
)

// gateListener wraps the test server's listener so a test can make the
// server's writes on one connection block, as they do when the agent at the
// other end stops reading. A blocked write honours the write deadline the
// handler sets, as a kernel socket does.
type gateListener struct {
	net.Listener
	mu     sync.Mutex
	paused map[string]bool      // by the client's address
	conns  map[string]*gateConn // by the client's address
}

func (l *gateListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	g := &gateConn{Conn: c, l: l, key: c.RemoteAddr().String()}
	l.mu.Lock()
	if l.conns == nil {
		l.conns = make(map[string]*gateConn)
	}
	l.conns[g.key] = g
	l.mu.Unlock()
	return g, nil
}

func (l *gateListener) pause(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.paused == nil {
		l.paused = make(map[string]bool)
	}
	l.paused[addr] = true
}

func (l *gateListener) resume(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.paused, addr)
}

func (l *gateListener) resumeAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.paused = nil
}

func (l *gateListener) isPaused(addr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.paused[addr]
}

func (l *gateListener) conn(addr string) *gateConn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conns[addr]
}

type gateConn struct {
	net.Conn
	l   *gateListener
	key string

	mu          sync.Mutex
	deadline    time.Time
	stuck       bool // a write is blocked on the gate
	sawDeadline bool // a blocked write had a deadline set
	timedOut    bool // a blocked write failed on its deadline
}

func (c *gateConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *gateConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *gateConn) Write(b []byte) (int, error) {
	for c.l.isPaused(c.key) {
		c.mu.Lock()
		dl := c.deadline
		c.stuck = true
		if !dl.IsZero() {
			c.sawDeadline = true
		}
		if !dl.IsZero() && !time.Now().Before(dl) {
			c.stuck, c.timedOut = false, true
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		c.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	c.mu.Lock()
	c.stuck = false
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *gateConn) state() (stuck, sawDeadline, timedOut bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stuck, c.sawDeadline, c.timedOut
}

// httpSetup configures an httpHarness.
type httpSetup struct {
	upstream string      // upstream era; v2026 if empty
	opts     HTTPOptions // Tokens default to alice, bob and carol
	hooks    *blockHooks
	extra    func(*mcp.Server)
	logger   *slog.Logger
	// now, if set, is the proxy's clock. It is installed before the
	// handler serves anything, so no request can race with it.
	now func() time.Time
	// beforeAdmit, if set, is Proxy.testHookBeforeAdmit, installed before
	// the handler serves anything, like now.
	beforeAdmit func()
	// policy, if set, is Options.Gate.
	policy Gate
}

type httpHarness struct {
	proxy *Proxy
	hh    *httpHandler // the chain HTTPHandler returned, for its own state
	srv   *httptest.Server
	url   string
	lst   *gateListener
	rec   *recorder
	gets  atomic.Int32 // GET requests being served
	raw   *http.Client
}

func newHTTPHarness(t *testing.T, s httpSetup) *httpHarness {
	t.Helper()
	ctx := context.Background()
	if s.upstream == "" {
		s.upstream = v2026
	}
	rec := &recorder{}
	up := fakeUpstream(rec, s.hooks)
	addEraTools(up, rec)
	if s.extra != nil {
		s.extra(up)
	}
	upSrvT, upCliT := mcp.NewInMemoryTransports()
	if _, err := up.Connect(ctx, pinServer(s.upstream, upSrvT), nil); err != nil {
		t.Fatal(err)
	}
	p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: reuse(upCliT)}}, Options{Version: "test", Logger: s.logger, Gate: s.policy})
	if err != nil {
		t.Fatal(err)
	}
	if s.now != nil {
		p.now = s.now
	}
	p.testHookBeforeAdmit = s.beforeAdmit
	opts := s.opts
	if opts.Tokens == nil {
		opts.Tokens = map[string][]byte{"alice": tokAlice, "bob": tokBob, "carol": tokCarol}
	}
	hd, err := p.HTTPHandler(opts)
	if err != nil {
		_ = p.Close()
		t.Fatal(err)
	}
	h := &httpHarness{proxy: p, hh: hd.(*httpHandler), rec: rec, raw: &http.Client{Transport: &http.Transport{}}}
	counted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			h.gets.Add(1)
			defer h.gets.Add(-1)
		}
		hd.ServeHTTP(w, r)
	})
	h.srv = httptest.NewUnstartedServer(counted)
	h.lst = &gateListener{Listener: h.srv.Listener}
	h.srv.Listener = h.lst
	// As cmd/fathomgate configures it (newHTTPServer there): no server-wide
	// ReadTimeout or WriteTimeout, so the handler's own deadlines are what
	// is tested.
	errLog := s.logger
	if errLog == nil {
		errLog = discardLogger()
	}
	h.srv.Config = &http.Server{
		Handler:           counted,
		MaxHeaderBytes:    64 << 10,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(errLog.Handler(), slog.LevelWarn),
	}
	h.srv.Start()
	h.url = h.srv.URL + HTTPPath
	t.Cleanup(func() {
		h.lst.resumeAll()
		if err := p.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		h.raw.CloseIdleConnections()
		h.srv.CloseClientConnections()
		h.srv.Close()
	})
	return h
}

// bearer adds an Authorization header to every request. With legacy set it
// pins the client to the stateful era at the HTTP layer: server/discover is
// answered locally with method-not-found, as a 2025-era server answers it,
// so go-sdk falls back to initialise. (legacyAgent would hide the
// connection's session hooks, and with them the standalone GET stream.)
type bearer struct {
	token  []byte
	base   http.RoundTripper
	legacy bool
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	if b.legacy && r.Method == http.MethodPost && r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(body, &m) == nil && m.Method == "server/discover" {
			out := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Method not found"}}`, m.ID)
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
				Header:  http.Header{"Content-Type": {"application/json"}},
				Body:    io.NopCloser(strings.NewReader(out)),
				Request: r, ContentLength: int64(len(out)),
			}, nil
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b.token))
	return b.base.RoundTrip(r)
}

// connect opens a go-sdk client session over HTTP, pinned to era, with
// token. opts may be nil.
func (h *httpHarness) connect(t *testing.T, era string, token []byte, opts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	cs, err := h.tryConnect(t, era, token, opts)
	if err != nil {
		t.Fatalf("connect (%s): %v", era, err)
	}
	return cs
}

func (h *httpHarness) tryConnect(t *testing.T, era string, token []byte, opts *mcp.ClientOptions) (*mcp.ClientSession, error) {
	t.Helper()
	tr := &http.Transport{}
	ct := &mcp.StreamableClientTransport{Endpoint: h.url, HTTPClient: &http.Client{Transport: bearer{token, tr, era == v2025}}, MaxRetries: -1}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, opts).Connect(context.Background(), ct, nil)
	if err != nil {
		tr.CloseIdleConnections()
		return nil, err
	}
	t.Cleanup(func() {
		_ = cs.Close()
		tr.CloseIdleConnections()
	})
	return cs, nil
}

// answering is client options whose elicitation handler accepts with
// agentPassword.
func answering() *mcp.ClientOptions {
	return &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"password": agentPassword}}, nil
		},
	}
}

// meta2026 is the per-request _meta of a stateless agent, plus extra keys.
func meta2026(extra string) string {
	m := `"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"raw","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}`
	if extra != "" {
		m += "," + extra
	}
	return `"_meta":{` + m + `}`
}

// call2026 is a stateless tools/call body and its headers.
func call2026(tool, progressToken string) (string, map[string]string) {
	extra := ""
	if progressToken != "" {
		extra = fmt.Sprintf(`"progressToken":%q`, progressToken)
	}
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":{},%s}}`, tool, meta2026(extra))
	return body, map[string]string{"Mcp-Protocol-Version": v2026, "Mcp-Method": "tools/call", "Mcp-Name": tool}
}

// call2025 is a tools/call body and its headers on a stateful session.
func call2025(sessionID, tool, progressToken string) (string, map[string]string) {
	meta := ""
	if progressToken != "" {
		meta = fmt.Sprintf(`,"_meta":{"progressToken":%q}`, progressToken)
	}
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":77,"method":"tools/call","params":{"name":%q,"arguments":{}%s}}`, tool, meta)
	return body, map[string]string{"Mcp-Protocol-Version": v2025, "Mcp-Session-Id": sessionID}
}

// ping2026 is a cheap stateless request (tools/list; 2026-07-28 has no
// ping) and its headers.
func ping2026() (string, map[string]string) {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta2026("") + `}}`,
		map[string]string{"Mcp-Protocol-Version": v2026, "Mcp-Method": "tools/list"}
}

// initialize2025 is a stateful initialise request body.
const initialize2025 = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}` //nolint:misspell // MCP wire method name, not prose

// request builds a raw request to the listener. A nil token sends no
// Authorization header.
func (h *httpHarness) request(ctx context.Context, method string, token []byte, hdr map[string]string, body string) *http.Request {
	var rd io.Reader = http.NoBody
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.url, rd)
	if err != nil {
		panic(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != nil {
		req.Header.Set("Authorization", "Bearer "+string(token))
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	return req
}

// reply is what do keeps of a response once its body is read and closed.
type reply struct {
	StatusCode int
	Header     http.Header
}

// do sends a raw request and reads the whole response.
func (h *httpHarness) do(t *testing.T, req *http.Request) (reply, string) {
	t.Helper()
	resp, err := h.raw.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return reply{resp.StatusCode, resp.Header}, string(b)
}

// stuckClient is an HTTP client on a connection of its own whose server-side
// writes the test can pause. addr is the connection's client address once
// dialled.
type stuckClient struct {
	client *http.Client
	tr     *http.Transport
	addr   chan string
}

// newStuckClient returns a client whose connection is paused from the start
// (the server's first write blocks) when paused is set.
func (h *httpHarness) newStuckClient(paused bool) *stuckClient {
	s := &stuckClient{addr: make(chan string, 1)}
	var d net.Dialer
	s.tr = &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := d.DialContext(ctx, network, addr)
		if err == nil {
			if paused {
				h.lst.pause(c.LocalAddr().String())
			}
			s.addr <- c.LocalAddr().String()
		}
		return c, err
	}}
	s.client = &http.Client{Transport: s.tr}
	return s
}

// sseKinds reads an SSE body to its end and returns "progress" or
// "response" for each JSON-RPC message in it, in order.
func sseKinds(t *testing.T, r io.Reader) []string {
	t.Helper()
	var kinds []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		var m struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal([]byte(data), &m); err != nil {
			t.Fatalf("SSE data is not JSON: %q", data)
		}
		switch {
		case m.Method == "notifications/progress":
			kinds = append(kinds, "progress")
		case len(m.ID) > 0 && m.Method == "":
			kinds = append(kinds, "response")
		}
	}
	return kinds
}

// checkOrder fails if a progress notification follows the response, or if
// there is no response.
func checkOrder(t *testing.T, kinds []string) (progress int) {
	t.Helper()
	seen := false
	for _, k := range kinds {
		switch {
		case k == "response":
			seen = true
		case seen:
			t.Fatalf("a progress notification followed the result: %v", kinds)
		default:
			progress++
		}
	}
	if !seen {
		t.Fatalf("no result in the stream: %v", kinds)
	}
	return progress
}

// TestHTTPChecks: every refusal in ADR 0016's order, before and after
// authentication, in both eras, and no CORS header on any response.
func TestHTTPChecks(t *testing.T) {
	h := newHTTPHarness(t, httpSetup{})
	ping, pingHdr := ping2026()
	with := func(base map[string]string, kv ...string) map[string]string {
		out := map[string]string{}
		for k, v := range base {
			out[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			out[kv[i]] = kv[i+1]
		}
		return out
	}
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"pad":"` + strings.Repeat("x", maxRequestBodyBytes) + `"}}`
	cases := []struct {
		name   string
		method string
		path   string
		token  []byte
		hdr    map[string]string
		body   string
		want   int
	}{
		{"authenticated stateless ping", "POST", "", tokAlice, pingHdr, ping, 200},
		{"authenticated stateful initialise", "POST", "", tokAlice, nil, initialize2025, 200},
		{"no token", "POST", "", nil, pingHdr, ping, 401},
		{"wrong token of the same length", "POST", "", []byte(strings.Repeat("F", len(tokAlice))), pingHdr, ping, 401},
		{"truncated token", "POST", "", tokAlice[:len(tokAlice)-1], pingHdr, ping, 401},
		{"token with a suffix", "POST", "", append(append([]byte{}, tokAlice...), 'x'), pingHdr, ping, 401},
		{"basic scheme", "POST", "", nil, with(pingHdr, "Authorization", "Basic "+string(tokAlice)), ping, 401},
		{"stateful request without token", "POST", "", nil, nil, initialize2025, 401},
		{"GET without token", "GET", "", nil, nil, "", 401},
		{"Origin without token", "POST", "", nil, with(pingHdr, "Origin", "http://evil.example"), ping, 403},
		{"Origin with token", "POST", "", tokAlice, with(pingHdr, "Origin", "http://evil.example"), ping, 403},
		{"Origin equal to Host", "POST", "", tokAlice, with(pingHdr, "Origin", "http://"+strings.TrimPrefix(h.srv.URL, "http://")), ping, 403},
		{"Origin null", "POST", "", tokAlice, with(pingHdr, "Origin", "null"), ping, 403},
		{"empty Origin", "POST", "", tokAlice, with(pingHdr, "Origin", ""), ping, 403},
		{"Origin on GET", "GET", "", tokAlice, map[string]string{"Origin": "http://evil.example"}, "", 403},
		{"Origin on DELETE", "DELETE", "", tokAlice, map[string]string{"Origin": "http://evil.example", "Mcp-Session-Id": "x"}, "", 403},
		{"Origin on OPTIONS", "OPTIONS", "", nil, map[string]string{"Origin": "http://evil.example"}, "", 403},
		{"cross-site Sec-Fetch-Site", "POST", "", tokAlice, with(pingHdr, "Sec-Fetch-Site", "cross-site"), ping, 403},
		{"same-site Sec-Fetch-Site", "POST", "", tokAlice, with(pingHdr, "Sec-Fetch-Site", "same-site"), ping, 403},
		{"Sec-Fetch-Site none", "POST", "", tokAlice, with(pingHdr, "Sec-Fetch-Site", "none"), ping, 200},
		{"Sec-Fetch-Site same-origin", "POST", "", tokAlice, with(pingHdr, "Sec-Fetch-Site", "same-origin"), ping, 200},
		{"rebinding Host without token", "POST", "", nil, with(pingHdr, "Host", "evil.example"), ping, 403},
		{"rebinding Host with token", "POST", "", tokAlice, with(pingHdr, "Host", "evil.example:8080"), ping, 403},
		{"localhost Host", "POST", "", tokAlice, with(pingHdr, "Host", "localhost"), ping, 200},
		{"other path", "POST", "/other", tokAlice, pingHdr, ping, 404},
		{"trailing slash", "POST", "/mcp/", tokAlice, pingHdr, ping, 404},
		{"other path without token", "GET", "/", nil, nil, "", 404},
		{"OPTIONS with token", "OPTIONS", "", tokAlice, nil, "", 405},
		{"body over 4 MiB, stateless", "POST", "", tokAlice, pingHdr, big, 413},
		{"body over 4 MiB, stateful", "POST", "", tokAlice, nil, big, 413},
		{"stateless GET", "GET", "", tokAlice, map[string]string{"Mcp-Protocol-Version": v2026}, "", 405},
		{"unsupported old version", "POST", "", tokAlice, map[string]string{"Mcp-Protocol-Version": "2020-01-01"}, initialize2025, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := h.request(context.Background(), c.method, c.token, c.hdr, c.body)
			if c.path != "" {
				req.URL.Path = c.path
			}
			resp, body := h.do(t, req)
			if resp.StatusCode != c.want {
				t.Fatalf("status %d, want %d (body %q)", resp.StatusCode, c.want, clip(body))
			}
			if c.want == 401 && resp.Header.Get("WWW-Authenticate") != "Bearer" {
				t.Errorf("WWW-Authenticate %q, want Bearer", resp.Header.Get("WWW-Authenticate"))
			}
			for k := range resp.Header {
				if strings.HasPrefix(k, "Access-Control-") {
					t.Errorf("CORS header %s sent", k)
				}
			}
			if c.token != nil && strings.Contains(body, string(c.token)) {
				t.Errorf("the response quotes the token")
			}
		})
	}
}

// TestHTTPDispatch: MCP-Protocol-Version picks the handler. A 2026 request
// is served statelessly (no session, a stray session id ignored, header
// checks enforced); anything else goes to the stateful handler.
func TestHTTPDispatch(t *testing.T) {
	h := newHTTPHarness(t, httpSetup{})
	ctx := context.Background()

	resp, _ := h.do(t, h.request(ctx, "POST", tokAlice, nil, initialize2025))
	if resp.StatusCode != 200 || resp.Header.Get("Mcp-Session-Id") == "" {
		t.Fatalf("initialise: status %d, session id %q; want 200 and a session", resp.StatusCode, resp.Header.Get("Mcp-Session-Id"))
	}

	body, hdr := call2026("netdev-ssh-mcp.run_show_command", "")
	hdr["Mcp-Session-Id"] = "not-a-session"
	resp, got := h.do(t, h.request(ctx, "POST", tokAlice, hdr, body))
	if resp.StatusCode != 200 || resp.Header.Get("Mcp-Session-Id") != "" || !strings.Contains(got, "ok run_show_command") {
		t.Fatalf("stateless call: status %d, session %q, body %q", resp.StatusCode, resp.Header.Get("Mcp-Session-Id"), clip(got))
	}

	body, hdr = call2026("netdev-ssh-mcp.run_show_command", "")
	hdr["Mcp-Name"] = "netdev-ssh-mcp.get_config"
	if resp, got := h.do(t, h.request(ctx, "POST", tokAlice, hdr, body)); resp.StatusCode != 400 {
		t.Fatalf("Mcp-Name mismatch: status %d, want 400 (%q)", resp.StatusCode, clip(got))
	}

	// A 2026 body without the header reaches the stateful handler, which
	// refuses it.
	body, _ = call2026("netdev-ssh-mcp.run_show_command", "")
	if resp, got := h.do(t, h.request(ctx, "POST", tokAlice, nil, body)); resp.StatusCode != 400 {
		t.Fatalf("2026 body on the stateful handler: status %d, want 400 (%q)", resp.StatusCode, clip(got))
	}
}

// TestHTTPEraMatrix is matrix row 23's tier-1 half: each agent era, over
// HTTP, against each upstream era, lists the prefixed tools, calls one and
// gets an upstream prompt as 8.4 says.
func TestHTTPEraMatrix(t *testing.T) {
	for _, e := range eras {
		t.Run("agent "+e.agent+" upstream "+e.upstream, func(t *testing.T) {
			h := newHTTPHarness(t, httpSetup{upstream: e.upstream})
			cs := h.connect(t, e.agent, tokAlice, answering())
			ctx := context.Background()
			if got := cs.ID() != ""; got != (e.agent == v2025) {
				t.Fatalf("session id %q for a %s agent", cs.ID(), e.agent)
			}
			tools, err := cs.ListTools(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(tools.Tools, func(tl *mcp.Tool) bool { return tl.Name == "netdev-ssh-mcp.run_show_command" }) {
				t.Fatalf("tools/list has no netdev-ssh-mcp.run_show_command")
			}
			res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01"}})
			if err != nil || res.IsError || !strings.Contains(text(res), "ok run_show_command") {
				t.Fatalf("call: %v %q", err, text(res))
			}
			res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask"})
			if e.agent == v2026 && e.upstream == v2025 {
				// The run_show_command above left an orphan under its own
				// per-request key (T0.44), foreign to this request's, so the
				// orphan rule refuses the prompt with the
				// ADR 0014 wording, as a note (S3 in the security review of
				// T0.40). go-sdk's upstream then fails the call, and the
				// agent gets that upstream error, relayed and labelled, not
				// fathomgate's text in its place; it quotes the refusal the
				// upstream received.
				var werr *jsonrpc.Error
				if !errors.As(err, &werr) || !strings.HasPrefix(werr.Message, "upstream netdev-ssh-mcp: ") || !strings.Contains(werr.Message, "ADR 0014") {
					t.Fatalf("stateful prompt to a stateless agent: %v, want the upstream's error quoting the ADR 0014 refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError || !strings.Contains(text(res), "pw=accept:"+agentPassword) {
				t.Fatalf("prompt: %q", text(res))
			}
		})
	}
}

// TestHTTPSessionBinding: a stateful session belongs to the principal that
// opened it. Another principal's requests on it get 403, and its DELETE
// neither closes the session nor cancels its calls.
func TestHTTPSessionBinding(t *testing.T) {
	hooks := &blockHooks{blocked: make(chan struct{}, 4), cancelled: make(chan struct{}, 4)}
	h := newHTTPHarness(t, httpSetup{hooks: hooks})
	ctx := context.Background()
	cs := h.connect(t, v2025, tokAlice, nil)
	go func() { _, _ = cs.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.block"}) }()
	<-hooks.blocked

	body, hdr := call2025(cs.ID(), "netdev-ssh-mcp.run_show_command", "")
	if resp, _ := h.do(t, h.request(ctx, "POST", tokBob, hdr, body)); resp.StatusCode != 403 {
		t.Fatalf("bob on alice's session: status %d, want 403", resp.StatusCode)
	}
	if resp, _ := h.do(t, h.request(ctx, "DELETE", tokBob, map[string]string{"Mcp-Session-Id": cs.ID()}, "")); resp.StatusCode != 403 {
		t.Fatalf("bob's DELETE of alice's session: status %d, want 403", resp.StatusCode)
	}
	// A negative check: nothing to wait for, so give a wrong cancellation
	// 100 ms to show. The DELETE has already been answered, and on the bug
	// this guards against cancelSession runs before go-sdk answers, so the
	// window is generous rather than racy.
	select {
	case <-hooks.cancelled:
		t.Fatal("bob's DELETE cancelled alice's call")
	case <-time.After(100 * time.Millisecond):
	}
	if res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command"}); err != nil || res.IsError {
		t.Fatalf("alice's session after bob's attempts: %v %q", err, text(res))
	}
	// Alice's own DELETE cancels her call.
	if resp, _ := h.do(t, h.request(ctx, "DELETE", tokAlice, map[string]string{"Mcp-Session-Id": cs.ID(), "Mcp-Protocol-Version": v2025}, "")); resp.StatusCode != 204 {
		t.Fatalf("alice's DELETE: status %d, want 204", resp.StatusCode)
	}
	select {
	case <-hooks.cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("alice's DELETE did not cancel her call in flight")
	}
}

// TestHTTPInFlightCap: POSTs in flight are capped per principal and
// overall; the one over gets 503 with Retry-After: 1, before go-sdk.
func TestHTTPInFlightCap(t *testing.T) {
	hooks := &blockHooks{blocked: make(chan struct{}, 4), cancelled: make(chan struct{}, 4)}
	h := newHTTPHarness(t, httpSetup{hooks: hooks, opts: HTTPOptions{MaxInFlight: 2, MaxInFlightPerPrincipal: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	block := func(tok []byte) {
		body, hdr := call2026("netdev-ssh-mcp.block", "")
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp, err := h.raw.Do(h.request(ctx, "POST", tok, hdr, body)); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
		<-hooks.blocked
	}
	ping, pingHdr := ping2026()
	check := func(who string, tok []byte, want int) {
		t.Helper()
		resp, _ := h.do(t, h.request(context.Background(), "POST", tok, pingHdr, ping))
		if resp.StatusCode != want {
			t.Fatalf("%s: status %d, want %d", who, resp.StatusCode, want)
		}
		if want == 503 && resp.Header.Get("Retry-After") != "1" {
			t.Fatalf("%s: Retry-After %q, want 1", who, resp.Header.Get("Retry-After"))
		}
	}
	block(tokAlice)
	check("alice's second POST", tokAlice, 503)
	check("bob while alice holds her slot", tokBob, 200)
	block(tokBob)
	check("carol with every slot taken", tokCarol, 503)
	// GET is not a POST and is not counted.
	cancel()
	wg.Wait()
	for range 2 {
		select {
		case <-hooks.cancelled:
		case <-time.After(5 * time.Second):
			t.Fatal("dropping a stateless POST did not cancel its upstream call")
		}
	}
	waitFor(t, "the POST slots to free up", func() bool {
		resp, _ := h.do(t, h.request(context.Background(), "POST", tokCarol, pingHdr, ping))
		return resp.StatusCode == 200
	})
}

// TestHTTPSessionCap: at most MaxSessions stateful sessions; an initialise
// past it gets 503 before go-sdk creates a session; a closed session frees
// its slot; stateless requests are not counted.
func TestHTTPSessionCap(t *testing.T) {
	h := newHTTPHarness(t, httpSetup{opts: HTTPOptions{MaxSessions: 2}})
	ctx := context.Background()
	first := h.connect(t, v2025, tokAlice, nil)
	h.connect(t, v2025, tokBob, nil)
	resp, _ := h.do(t, h.request(ctx, "POST", tokCarol, nil, initialize2025))
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("third initialise: status %d, Retry-After %q; want 503 and 1", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if _, err := h.tryConnect(t, v2025, tokCarol, nil); err == nil {
		t.Fatal("a third stateful client connected past the cap")
	}
	stateless := h.connect(t, v2026, tokCarol, nil)
	if res, err := stateless.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command"}); err != nil || res.IsError {
		t.Fatalf("stateless call with the session cap reached: %v %q", err, text(res))
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitFor(t, "the closed session's slot to free up", func() bool {
		resp, _ := h.do(t, h.request(ctx, "POST", tokCarol, nil, initialize2025))
		return resp.StatusCode == 200
	})
}

// TestHTTPCallCaps (T3 in the review of PR #63): tool calls in flight are
// capped per session and per principal, and a call over either cap is
// refused before it reaches the upstream. Another principal is unaffected.
// Deleting a session cancels its calls.
func TestHTTPCallCaps(t *testing.T) {
	hooks := &blockHooks{blocked: make(chan struct{}, 8), cancelled: make(chan struct{}, 8)}
	h := newHTTPHarness(t, httpSetup{hooks: hooks, opts: HTTPOptions{MaxCallsPerSession: 2, MaxCallsPerPrincipal: 3}})
	ctx := context.Background()
	blocks := func() int {
		n := 0
		for _, c := range h.rec.all() {
			if c.Name == "block" {
				n++
			}
		}
		return n
	}
	s1 := h.connect(t, v2025, tokAlice, nil)
	s2 := h.connect(t, v2025, tokAlice, nil)
	// go-sdk's client Close waits for its calls; cancel them first
	// (cleanups run last in, first out).
	callCtx, cancelCalls := context.WithCancel(ctx)
	t.Cleanup(cancelCalls)
	start := func(cs *mcp.ClientSession) {
		go func() { _, _ = cs.CallTool(callCtx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.block"}) }()
		select {
		case <-hooks.blocked:
		case <-time.After(5 * time.Second):
			t.Fatal("block call did not reach the upstream")
		}
	}
	start(s1)
	start(s1)
	res, err := s1.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.block"})
	if err != nil || !res.IsError || !strings.Contains(text(res), "on this session (limit 2)") {
		t.Fatalf("third call on a session: %v %q, want the session cap refusal", err, text(res))
	}
	start(s2)
	res, err = s2.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.block"})
	if err != nil || !res.IsError || !strings.Contains(text(res), "for principal alice (limit 3)") {
		t.Fatalf("fourth call of a principal: %v %q, want the principal cap refusal", err, text(res))
	}
	if n := blocks(); n != 3 {
		t.Fatalf("the upstream saw %d block calls, want 3: a refused call reached it", n)
	}

	bob := h.connect(t, v2026, tokBob, nil)
	if res, err := bob.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command"}); err != nil || res.IsError {
		t.Fatalf("bob while alice is at her cap: %v %q", err, text(res))
	}

	resp, _ := h.do(t, h.request(ctx, "DELETE", tokAlice, map[string]string{"Mcp-Session-Id": s1.ID(), "Mcp-Protocol-Version": v2025}, ""))
	if resp.StatusCode != 204 {
		t.Fatalf("DELETE: status %d", resp.StatusCode)
	}
	for range 2 {
		select {
		case <-hooks.cancelled:
		case <-time.After(5 * time.Second):
			t.Fatal("DELETE did not cancel the session's calls")
		}
	}
	waitFor(t, "the deleted session's calls to be released", func() bool { return h.proxy.limits.Load().inFlight() == 1 })
}

// addFloodForever adds "flood_forever": progress with a full-length message
// every 5 ms until the call is cancelled, which it reports on cancelled.
func addFloodForever(cancelled chan<- struct{}) func(*mcp.Server) {
	return func(s *mcp.Server) {
		s.AddTool(&mcp.Tool{Name: "flood_forever", InputSchema: objectSchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			tok := req.Params.GetProgressToken()
			msg := strings.Repeat("m", maxProgressMessage)
			for i := 1; ; i++ {
				_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: tok, Progress: float64(i), Message: msg})
				select {
				case <-ctx.Done():
					cancelled <- struct{}{}
					return nil, ctx.Err()
				case <-time.After(5 * time.Millisecond):
				}
			}
		})
	}
}

// anyRelay returns a progress relay open on up, or nil.
func anyRelay(up *upstream) *progressRelay {
	up.mu.Lock()
	defer up.mu.Unlock()
	for _, r := range up.progress {
		return r
	}
	return nil
}

// TestHTTPStuckAgent (T3 in the review of PR #63): an agent that stops
// reading costs bounded time and goroutines. Its stuck write fails on the
// write deadline, the connection is dropped, its progress sender exits, and
// another principal's calls flow meanwhile. Stateless: the upstream call is
// cancelled with the request. Stateful: the call outlives its POST (go-sdk
// detaches it) and counts toward the caps until its session is deleted.
func TestHTTPStuckAgent(t *testing.T) {
	for _, era := range []string{v2026, v2025} {
		t.Run("agent "+era, func(t *testing.T) {
			base := runtime.NumGoroutine()
			cancelled := make(chan struct{}, 4)
			h := newHTTPHarness(t, httpSetup{extra: addFloodForever(cancelled), opts: HTTPOptions{WriteTimeout: 200 * time.Millisecond}})
			ctx := context.Background()
			up := h.proxy.upstreams[testServer]
			var session *mcp.ClientSession
			body, hdr := call2026("netdev-ssh-mcp.flood_forever", "stuck")
			if era == v2025 {
				session = h.connect(t, v2025, tokAlice, nil)
				body, hdr = call2025(session.ID(), "netdev-ssh-mcp.flood_forever", "stuck")
			}
			sc := h.newStuckClient(true)
			defer sc.tr.CloseIdleConnections()
			done := make(chan error, 1)
			go func() {
				resp, err := sc.client.Do(h.request(ctx, "POST", tokAlice, hdr, body))
				if err == nil {
					_, err = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
				done <- err
			}()
			addr := <-sc.addr
			var gc *gateConn
			waitFor(t, "the server's write to the agent to block", func() bool {
				gc = h.lst.conn(addr)
				if gc == nil {
					return false
				}
				stuck, _, timedOut := gc.state()
				return stuck || timedOut
			})
			var r *progressRelay
			waitFor(t, "the call's progress relay", func() bool {
				r = anyRelay(up)
				return r != nil
			})

			// Another principal is unaffected while alice is stuck.
			bob := h.connect(t, v2026, tokBob, nil)
			if res, err := bob.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command"}); err != nil || res.IsError {
				t.Fatalf("bob while alice is stuck: %v %q", err, text(res))
			}

			// The stuck write fails on its deadline and the agent's
			// connection is dropped.
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the stuck agent's request did not end")
			}
			if _, saw, timedOut := gc.state(); !saw || !timedOut {
				t.Fatalf("stuck write: deadline set %v, timed out %v; want both", saw, timedOut)
			}
			if era == v2025 {
				// The call runs on without its POST, within the caps, and
				// its progress now fails fast.
				if n := h.proxy.limits.Load().inFlight(); n != 1 {
					t.Fatalf("%d calls in flight after the POST dropped, want 1", n)
				}
				if err := session.Close(); err != nil {
					t.Fatalf("close: %v", err)
				}
			}
			select {
			case <-cancelled:
			case <-time.After(5 * time.Second):
				t.Fatal("the upstream call was not cancelled")
			}
			select {
			case <-r.exited:
			case <-time.After(5 * time.Second):
				t.Fatal("the progress sender did not exit")
			}
			waitFor(t, "every call to be released", func() bool { return h.proxy.limits.Load().inFlight() == 0 })
			// Goroutines return to about where they started: bob's session
			// and the listener, not one per stuck notification.
			waitFor(t, "goroutines to settle", func() bool { return runtime.NumGoroutine() < base+40 })
		})
	}
}

// TestHTTPProgressNeverFollowsResult (T4 in the review of PR #63): over
// HTTP, responses are SSE (JSONResponse stays off: with it go-sdk sends
// progress to the standalone stream), and no progress notification follows
// a call's result, on its POST stream or the session's GET stream, even
// when finish gives up on an agent that stopped reading. A notification
// written after the result under the call's context is refused by go-sdk
// (T2). A go-sdk upgrade that changes this routing fails here.
func TestHTTPProgressNeverFollowsResult(t *testing.T) {
	for _, era := range []string{v2026, v2025} {
		t.Run("agent "+era, func(t *testing.T) {
			h := newHTTPHarness(t, httpSetup{opts: HTTPOptions{WriteTimeout: 30 * time.Second}})
			h.proxy.progressWait = 50 * time.Millisecond
			ctx := context.Background()
			up := h.proxy.upstreams[testServer]
			getLog := newProgressLog()
			var session *mcp.ClientSession
			req := call2026
			if era == v2025 {
				session = h.connect(t, v2025, tokAlice, &mcp.ClientOptions{ProgressNotificationHandler: getLog.record})
				req = func(tool, tok string) (string, map[string]string) { return call2025(session.ID(), tool, tok) }
				waitFor(t, "the session's GET stream", func() bool { return h.gets.Load() == 1 })
			}

			// A plain call: SSE, progress then result.
			body, hdr := req("netdev-ssh-mcp.progress", "plain")
			bob := h.connect(t, v2026, tokBob, nil)
			// Release the call once its relay has written at least one
			// notification to the agent, so the stream has progress before
			// the result. The poll runs here, not in waitFor, because
			// t.Fatal must not be called off the test goroutine: a timeout
			// is reported on relErr and the call is released anyway, so the
			// POST below cannot hang.
			relErr := make(chan error, 1)
			go func() {
				deadline := time.Now().Add(5 * time.Second)
				var err error
				for {
					if r := anyRelay(up); r != nil {
						r.mu.Lock()
						sent := r.sent
						r.mu.Unlock()
						if sent >= 1 {
							break
						}
					}
					if time.Now().After(deadline) {
						err = errors.New("timed out waiting for the plain call's relay to write a notification")
						break
					}
					time.Sleep(2 * time.Millisecond)
				}
				_, _ = bob.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.progress_release"})
				relErr <- err
			}()
			resp, err := h.raw.Do(h.request(ctx, "POST", tokAlice, hdr, body))
			if err != nil {
				t.Fatal(err)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
				t.Fatalf("tools/call answered as %q, want text/event-stream (JSONResponse must stay off)", ct)
			}
			kinds := sseKinds(t, resp.Body)
			_ = resp.Body.Close()
			if err := <-relErr; err != nil {
				t.Fatal(err)
			}
			if n := checkOrder(t, kinds); n == 0 {
				t.Fatal("no progress reached the POST stream")
			}

			// finish gives up: the agent stops reading with a write in
			// progress, the call ends, the relay abandons its queue.
			body, hdr = req("netdev-ssh-mcp.progress_flood", "stuck")
			sc := h.newStuckClient(true)
			defer sc.tr.CloseIdleConnections()
			type out struct {
				kinds []string
				err   error
			}
			done := make(chan out, 1)
			go func() {
				resp, err := sc.client.Do(h.request(ctx, "POST", tokAlice, hdr, body))
				if err != nil {
					done <- out{err: err}
					return
				}
				defer func() { _ = resp.Body.Close() }()
				done <- out{kinds: sseKinds(t, resp.Body)}
			}()
			addr := <-sc.addr
			var r *progressRelay
			waitFor(t, "the relay to read the whole flood", func() bool {
				r = relayAt(up, floodSize)
				return r != nil
			})
			waitFor(t, "a write to the agent to block", func() bool {
				gc := h.lst.conn(addr)
				if gc == nil {
					return false
				}
				stuck, _, _ := gc.state()
				return stuck
			})
			if _, err := bob.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.progress_release"}); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "finish to give up", func() bool {
				r.mu.Lock()
				defer r.mu.Unlock()
				return r.abandoned
			})
			h.lst.resume(addr)
			var o out
			select {
			case o = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the stuck call did not return once the agent read again")
			}
			if o.err != nil {
				t.Fatal(o.err)
			}
			if n := checkOrder(t, o.kinds); n == 0 || n > progressBurst {
				t.Fatalf("the agent read %d progress notifications, want 1 to %d (the queue was dropped)", n, progressBurst)
			}
			select {
			case <-r.exited:
			case <-time.After(5 * time.Second):
				t.Fatal("the sender did not exit")
			}

			// T2: a sender that writes after the result, under the call's
			// context, is refused, and nothing reaches the GET stream.
			late := &mcp.ProgressNotificationParams{ProgressToken: "stuck", Progress: 1e9}
			if err := r.session.NotifyProgress(context.WithoutCancel(r.ctx), late); err == nil {
				t.Fatal("go-sdk accepted a progress notification after the call's result")
			}
			// A negative check: a misrouted notification would reach the
			// GET stream within a few milliseconds on loopback, so 100 ms
			// is ample for it to show, and nothing positive can be awaited.
			time.Sleep(100 * time.Millisecond)
			if got := getLog.all(); len(got) != 0 {
				t.Fatalf("%d progress notifications reached the GET stream", len(got))
			}
		})
	}
}

// TestHTTPLogs: refusals and sessions are logged without the token, the
// Authorization header or the session id; a session shows as its hash.
func TestHTTPLogs(t *testing.T) {
	buf := newSyncBuffer()
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := newHTTPHarness(t, httpSetup{logger: logger})
	ping, hdr := ping2026()
	wrong := []byte("FAKE-wrong-token-0123456789abcdef012345")
	if resp, _ := h.do(t, h.request(context.Background(), "POST", wrong, hdr, ping)); resp.StatusCode != 401 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	cs := h.connect(t, v2025, tokAlice, nil)
	buf.waitFor(t, "agent session opened")
	logs := buf.String()
	for _, secret := range [][]byte{wrong, tokAlice, []byte(cs.ID())} {
		if strings.Contains(logs, string(secret)) {
			t.Fatalf("the log contains a token or session id:\n%s", logs)
		}
	}
	for _, want := range []string{"authentication failed", "reason=\"unknown token\"", "session=" + shortHash(cs.ID()), "principal=alice"} {
		if !strings.Contains(logs, want) {
			t.Errorf("the log lacks %q:\n%s", want, logs)
		}
	}
}

// TestHTTPOptions: invalid options and a set MCPGODEBUG are refused, and a
// proxy builds one handler.
func TestHTTPOptions(t *testing.T) {
	long := []byte(strings.Repeat("a", minTokenBytes))
	cases := []struct {
		name string
		opts HTTPOptions
		want string
	}{
		{"no tokens", HTTPOptions{}, "at least one bearer token"},
		{"short token", HTTPOptions{Tokens: map[string][]byte{"a": long[:minTokenBytes-1]}}, "at least 32"},
		{"space in token", HTTPOptions{Tokens: map[string][]byte{"a": append([]byte("x "), long...)}}, "white space"},
		{"newline in token", HTTPOptions{Tokens: map[string][]byte{"a": append(append([]byte{}, long...), '\n')}}, "white space"},
		{"non-ASCII token", HTTPOptions{Tokens: map[string][]byte{"a": append([]byte("é"), long...)}}, "non-ASCII"},
		{"empty name", HTTPOptions{Tokens: map[string][]byte{"": long}}, "1 to 64"},
		{"bad name", HTTPOptions{Tokens: map[string][]byte{"a b": long}}, "letters, digits"},
		// G8 in the review of PR #68: %q escapes the name once, not twice.
		{"control character in name", HTTPOptions{Tokens: map[string][]byte{"a\x1bb": long}}, `principal name "a\x1bb" may contain`},
		{"long name", HTTPOptions{Tokens: map[string][]byte{strings.Repeat("n", 65): long}}, `"` + strings.Repeat("n", 65) + `" must be 1 to 64`},
		{"shared token", HTTPOptions{Tokens: map[string][]byte{"a": long, "b": long}}, "same token"},
		{"negative cap", HTTPOptions{Tokens: map[string][]byte{"a": long}, MaxInFlight: -1}, "negative"},
		{"negative timeout", HTTPOptions{Tokens: map[string][]byte{"a": long}, WriteTimeout: -time.Second}, "negative"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, nil)
			_, err := h.proxy.HTTPHandler(c.opts)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want one containing %q", err, c.want)
			}
			if strings.Contains(fmt.Sprint(err), string(long)) {
				t.Fatal("the error quotes the token")
			}
		})
	}
	t.Run("twice", func(t *testing.T) {
		h := newHarness(t, nil)
		opts := HTTPOptions{Tokens: map[string][]byte{"a": long}}
		if _, err := h.proxy.HTTPHandler(opts); err != nil {
			t.Fatal(err)
		}
		if _, err := h.proxy.HTTPHandler(opts); err == nil {
			t.Fatal("a second handler was built")
		}
	})
	t.Run("MCPGODEBUG", func(t *testing.T) {
		t.Setenv("MCPGODEBUG", "")
		h := newHarness(t, nil)
		if _, err := h.proxy.HTTPHandler(HTTPOptions{Tokens: map[string][]byte{"a": long}}); !errors.Is(err, ErrMCPGODEBUG) {
			t.Fatalf("error %v, want ErrMCPGODEBUG", err)
		}
	})
}

// TestHTTPOptionsResolved (G7 in the review of PR #68): for every field but
// Tokens, zero means the default, a negative value is an error that names
// the field, and a positive value is kept. The fields are enumerated by
// reflection, so a new field without a row in defaults fails here.
func TestHTTPOptionsResolved(t *testing.T) {
	defaults := map[string]int64{
		"MaxInFlight":             defaultMaxInFlight,
		"MaxInFlightPerPrincipal": defaultMaxInFlightPerPrincipal,
		"MaxSessions":             defaultMaxSessions,
		"MaxSessionsPerPrincipal": defaultMaxSessionsPerPrincipal,
		"MaxCallsPerSession":      defaultMaxCallsPerSession,
		"MaxCallsPerPrincipal":    defaultMaxCallsPerPrincipal,
		"SessionTimeout":          int64(defaultSessionTimeout),
		"OrphanTTL":               int64(defaultOrphanTTL),
		"WriteTimeout":            int64(defaultWriteTimeout),
		"BodyReadTimeout":         int64(defaultBodyReadTimeout),
	}
	typ := reflect.TypeFor[HTTPOptions]()
	seen := 0
	for i := range typ.NumField() {
		f := typ.Field(i)
		if f.Name == "Tokens" {
			continue
		}
		seen++
		def, ok := defaults[f.Name]
		if !ok {
			t.Errorf("HTTPOptions.%s has no default in this test", f.Name)
			continue
		}
		t.Run(f.Name, func(t *testing.T) {
			with := func(v int64) HTTPOptions {
				var o HTTPOptions
				reflect.ValueOf(&o).Elem().Field(i).SetInt(v)
				return o
			}
			get := func(o HTTPOptions) int64 { return reflect.ValueOf(o).Field(i).Int() }

			got, err := with(0).resolved()
			if err != nil || get(got) != def {
				t.Fatalf("zero: %d, %v; want the default %d", get(got), err, def)
			}
			if _, err := with(-1).resolved(); err == nil || !strings.Contains(err.Error(), "HTTPOptions."+f.Name+" is negative") {
				t.Fatalf("negative: error %v, want one naming HTTPOptions.%s", err, f.Name)
			}
			const kept = 7
			if got, err := with(kept).resolved(); err != nil || get(got) != kept {
				t.Fatalf("positive: %d, %v; want %d kept", get(got), err, kept)
			}
			// The other fields still resolve to their defaults.
			got, _ = with(kept).resolved()
			for j := range typ.NumField() {
				if g := typ.Field(j); j != i && g.Name != "Tokens" && reflect.ValueOf(got).Field(j).Int() != defaults[g.Name] {
					t.Errorf("%s set: %s = %d, want its default", f.Name, g.Name, reflect.ValueOf(got).Field(j).Int())
				}
			}
		})
	}
	if seen != len(defaults) {
		t.Errorf("%d fields checked, %d defaults listed", seen, len(defaults))
	}
}
