package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tests of T0.30 (ADR 0016): the sealed requestState is bound to the agent
// side it was issued to (transport and principal), the call carries both,
// and the progress relay belongs to one agent request.

// TestSealerBinding: an envelope opens only under the binding it was
// sealed with, and the binding is not in the token.
func TestSealerBinding(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	s := testSealer(t, now)
	st := sealedState{Server: testServer, Tool: "ask", Args: argsDigest(nil), IDs: []string{"pw"}, Up: "up-state-pw", Round: 1}
	alice := stateBinding{transport: transportHTTP, principal: "alice"}
	token, err := s.seal(st, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.open(token, alice); err != nil {
		t.Fatalf("same binding: %v", err)
	}
	for _, other := range []stateBinding{
		{transport: transportHTTP, principal: "bob"},
		{transport: transportHTTP, principal: ""},
		{transport: transportHTTP, principal: "alic"},
		{transport: transportHTTP, principal: "alice\x00"},
		{transport: transportStdio, principal: "alice"},
		{transport: transportStdio, principal: ""},
		{},
	} {
		if _, err := s.open(token, other); !errors.Is(err, errStateAuth) {
			t.Errorf("binding %+v: %v, want %v", other, err, errStateAuth)
		}
	}
	// A local (stdio) state does not open over HTTP either.
	local := stateBinding{transport: transportStdio}
	lt, err := s.seal(st, local)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.open(lt, local); err != nil {
		t.Fatalf("stdio binding: %v", err)
	}
	if _, err := s.open(lt, alice); !errors.Is(err, errStateAuth) {
		t.Errorf("stdio state over http: %v, want %v", err, errStateAuth)
	}
	// The binding is authenticated data, not content: nothing of it is in
	// the token, encoded or not.
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, statePrefix))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"alice", transportHTTP} {
		if strings.Contains(token, v) || strings.Contains(string(raw), v) {
			t.Errorf("token reveals %q", v)
		}
	}
}

// manualMRTR is client options for an agent that declares form elicitation
// and handles input_required itself, so the test holds the requestState.
func manualMRTR() *mcp.ClientOptions {
	opts := answering()
	opts.MultiRoundTrip = &mcp.MultiRoundTripOptions{Disabled: true}
	return opts
}

// wantStateRefused checks that err is the invalid_request_state error with
// exactly detail, and that neither its message nor its data carries any of
// leaks (the issuing principal, the upstream's own state or prompt).
func wantStateRefused(t *testing.T, err error, detail error, leaks ...string) {
	t.Helper()
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) || werr.Code != jsonrpc.CodeInvalidParams {
		t.Fatalf("want -32602, got %v", err)
	}
	var d retryErrorData
	if err := json.Unmarshal(werr.Data, &d); err != nil || d.Reason != reasonInvalidRequestState || d.Detail != detail.Error() {
		t.Fatalf("data %s (%v), want reason %s detail %q", werr.Data, err, reasonInvalidRequestState, detail)
	}
	if want := reasonInvalidRequestState + ": " + d.Tool + ": " + detail.Error(); werr.Message != want {
		t.Errorf("message %q, want %q", werr.Message, want)
	}
	for _, leak := range leaks {
		if strings.Contains(werr.Message, leak) || strings.Contains(string(werr.Data), leak) {
			t.Errorf("refusal carries %q: %s %s", leak, werr.Message, werr.Data)
		}
	}
}

// accepted is the stateless agent's answer to the "pw" prompt.
func accepted() mcp.InputResponseMap {
	return mcp.InputResponseMap{"pw": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"password": agentPassword}}}
}

// askForState calls netdev-ssh-mcp.ask with args and returns the
// requestState netguard issued.
func askForState(t *testing.T, cs *mcp.ClientSession, args map[string]any) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NeedsInput() || !strings.HasPrefix(res.RequestState, statePrefix) {
		t.Fatalf("want input_required with a %s requestState, got %q %q", statePrefix, text(res), res.RequestState)
	}
	return res.RequestState
}

// retry sends the MRTR retry of netdev-ssh-mcp.ask with state.
func retry(cs *mcp.ClientSession, args map[string]any, state string) (*mcp.CallToolResult, error) {
	return cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: args, RequestState: state, InputResponses: accepted()})
}

// TestHTTPRequestStateBoundToPrincipal: a requestState issued to one
// principal is refused, with the forgery's text and nothing else, when
// another principal presents it; nothing reaches the upstream; the issuing
// principal's own retry still crosses. Retired envelope versions are
// refused with a text that says what to do.
func TestHTTPRequestStateBoundToPrincipal(t *testing.T) {
	buf := newSyncBuffer()
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	h := newHTTPHarness(t, httpSetup{logger: logger})
	alice := h.connect(t, v2026, tokAlice, manualMRTR())
	bob := h.connect(t, v2026, tokBob, manualMRTR())
	args := map[string]any{"host": "core-rtr-01"}

	state := askForState(t, alice, args)
	before := len(h.rec.all())

	_, err := retry(bob, args, state)
	wantStateRefused(t, err, errStateAuth, "alice", "up-state", upstreamPrompt)
	buf.waitFor(t, "netguard refused a requestState")
	log := buf.String()
	if !strings.Contains(log, "principal=bob") || !strings.Contains(log, "transport=http") || strings.Contains(log, "alice") {
		t.Errorf("refusal log should name the presenter (bob, http) and never the issuer: %s", log)
	}

	// An envelope version netguard no longer issues: ng2 is what netguard
	// issued before T0.30. The key is per process, so none can verify
	// after the upgrade; the agent is told to call again without it.
	ng2 := "ng2." + strings.TrimPrefix(state, statePrefix)
	_, err = retry(alice, args, ng2)
	wantStateRefused(t, err, errStateRetired, "up-state", upstreamPrompt)

	if n := len(h.rec.all()); n != before {
		t.Fatalf("upstream saw %d refused retries", n-before)
	}

	// Alice's own retry crosses once, with the upstream's own state.
	res, err := retry(alice, args, state)
	if err != nil || res.IsError || !strings.Contains(text(res), "answered state=up-state-pw pw=accept:"+agentPassword) {
		t.Fatalf("alice's retry: %v %q", err, text(res))
	}
	if calls := h.rec.all()[before:]; len(calls) != 1 || calls[0].RequestState != "up-state-pw" {
		t.Fatalf("upstream saw %+v, want alice's one retry", calls)
	}
}

// TestRequestStateBoundToTransport: one proxy with a local agent (Proxy.Run)
// and the HTTP listener. A requestState issued on one transport is refused
// on the other, in both directions; each is accepted on its own.
func TestRequestStateBoundToTransport(t *testing.T) {
	buf := newSyncBuffer()
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	h := newHTTPHarness(t, httpSetup{logger: logger})
	local, _ := connectAgent(t, h.proxy, eraSetup{agent: v2026, upstream: v2026, manualMRTR: true}, &promptLog{})
	alice := h.connect(t, v2026, tokAlice, manualMRTR())
	args := map[string]any{"host": "core-rtr-01"}

	localState := askForState(t, local, args)
	httpState := askForState(t, alice, args)
	before := len(h.rec.all())

	_, err := retry(alice, args, localState)
	wantStateRefused(t, err, errStateAuth, "stdio", "up-state", upstreamPrompt)
	_, err = retry(local, args, httpState)
	wantStateRefused(t, err, errStateAuth, "alice", "http", "up-state", upstreamPrompt)
	if n := len(h.rec.all()); n != before {
		t.Fatalf("upstream saw %d refused retries", n-before)
	}
	log := buf.String()
	if !strings.Contains(log, "transport=stdio principal=(local)") || !strings.Contains(log, "transport=http principal=alice") {
		t.Errorf("refusal log should name each presenter: %s", log)
	}

	for name, cs := range map[string]*mcp.ClientSession{"local": local, "alice": alice} {
		state := localState
		if name == "alice" {
			state = httpState
		}
		res, err := retry(cs, args, state)
		if err != nil || res.IsError || !strings.Contains(text(res), "answered state=up-state-pw pw=accept:"+agentPassword) {
			t.Fatalf("%s's own retry: %v %q", name, err, text(res))
		}
	}
}

// TestCallCarriesTransportAndPrincipal: the call dispatch receives names the
// transport and principal it arrived with, in each era.
func TestCallCarriesTransportAndPrincipal(t *testing.T) {
	h := newHTTPHarness(t, httpSetup{})
	var mu sync.Mutex
	var got []call
	route := h.proxy.routes["netdev-ssh-mcp.run_show_command"]
	// A receiving middleware sees each tools/call as the tool handler will,
	// and builds the call newCall hands to dispatch.
	h.proxy.server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if r, ok := req.(*mcp.CallToolRequest); ok {
				c, _ := newCall(route, r)
				mu.Lock()
				got = append(got, c)
				mu.Unlock()
			}
			return next(ctx, method, req)
		}
	})
	local, _ := connectAgent(t, h.proxy, eraSetup{agent: v2025, upstream: v2026}, &promptLog{})
	ctx := context.Background()
	for _, cs := range []*mcp.ClientSession{
		h.connect(t, v2025, tokAlice, nil),
		h.connect(t, v2026, tokBob, nil),
		local,
	} {
		if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01"}}); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := []stateBinding{{transportHTTP, "alice"}, {transportHTTP, "bob"}, {transportStdio, ""}}
	if len(got) != len(want) {
		t.Fatalf("saw %d calls, want %d", len(got), len(want))
	}
	for i, c := range got {
		if c.binding() != want[i] {
			t.Errorf("call %d: transport %q principal %q, want %+v", i, c.transport, c.principal, want[i])
		}
	}
}

// TestProgressRelayPerSession: three agent sessions (a stateful session and
// a stateless request over the listener, and the local agent) call the same
// upstream at once with the same progressToken. Each relay belongs to its
// own request, the upstream sees three distinct tokens of netguard's, and
// each agent gets only its own call's progress. Each call holds its result
// until its agent has had all three notifications, since one sent just
// before a result may be dispatched after it and dropped (8.4).
func TestProgressRelayPerSession(t *testing.T) {
	arrived := make(chan struct{}, 3)
	start := make(chan struct{})
	release := map[string]chan struct{}{"alice": make(chan struct{}), "bob": make(chan struct{}), "local": make(chan struct{})}
	tagged := func(s *mcp.Server) {
		s.AddTool(&mcp.Tool{Name: "progress_tagged", InputSchema: objectSchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var a struct {
				Who string `json:"who"`
			}
			_ = json.Unmarshal(req.Params.Arguments, &a)
			arrived <- struct{}{}
			select {
			case <-start:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			for i := 1; i <= 3; i++ {
				_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: req.Params.GetProgressToken(), Progress: float64(i), Message: a.Who})
			}
			select {
			case <-release[a.Who]:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return textResult(a.Who), nil
		})
	}
	h := newHTTPHarness(t, httpSetup{extra: tagged})
	up := h.proxy.upstreams[testServer]
	logs := map[string]*progressLog{"alice": newProgressLog(), "bob": newProgressLog(), "local": newProgressLog()}
	withProgress := func(l *progressLog) *mcp.ClientOptions {
		return &mcp.ClientOptions{ProgressNotificationHandler: l.record}
	}
	local, _ := connectAgent(t, h.proxy, eraSetup{agent: v2025, upstream: v2026, progress: logs["local"]}, &promptLog{})
	agents := map[string]*mcp.ClientSession{
		"alice": h.connect(t, v2025, tokAlice, withProgress(logs["alice"])),
		"bob":   h.connect(t, v2026, tokBob, withProgress(logs["bob"])),
		"local": local,
	}

	var wg sync.WaitGroup
	results := make(map[string]string)
	var mu sync.Mutex
	for who, cs := range agents {
		wg.Go(func() {
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
				Meta: mcp.Meta{"progressToken": "p"}, Name: "netdev-ssh-mcp.progress_tagged", Arguments: map[string]any{"who": who},
			})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				results[who] = "error: " + err.Error()
				return
			}
			results[who] = text(res)
		})
	}
	for range agents {
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			close(start)
			t.Fatal("the three calls did not all reach the upstream")
		}
	}

	// All three are in flight: three relays, three tokens, three owners.
	up.mu.Lock()
	owners := map[stateBinding]string{}
	for tok, r := range up.progress {
		if tok != r.upToken || tok == "p" {
			t.Errorf("relay mapped under %q has token %q", tok, r.upToken)
		}
		owners[stateBinding{r.transport, r.principal}] = r.sessionKey
	}
	up.mu.Unlock()
	if len(owners) != 3 {
		t.Fatalf("relays %v, want one per agent request", owners)
	}
	for b, prefix := range map[stateBinding]string{
		{transportHTTP, "alice"}: "s",
		{transportHTTP, "bob"}:   requestKeyPrefix,
		{transportStdio, ""}:     localKeyPrefix,
	} {
		if key, ok := owners[b]; !ok || !strings.HasPrefix(key, prefix) {
			t.Errorf("relay of %+v owned by session %q, want a %q key", b, key, prefix)
		}
	}
	close(start)
	for who, l := range logs {
		l.waitN(t, 3)
		close(release[who])
	}
	wg.Wait()

	for who, l := range logs {
		if results[who] != who {
			t.Errorf("%s's result %q", who, results[who])
		}
		got := l.all()
		if len(got) != 3 {
			t.Errorf("%s got %d notifications, want its own 3", who, len(got))
		}
		for _, n := range got {
			if n.ProgressToken != "p" || n.Message != "[from netdev-ssh-mcp] "+who {
				t.Errorf("%s got progress %v %q, which is not its own", who, n.ProgressToken, n.Message)
			}
		}
	}
	seen := map[any]bool{}
	for _, c := range h.rec.all() {
		if c.Name == "progress_tagged" {
			if c.ProgressToken == "p" || seen[c.ProgressToken] {
				t.Errorf("upstream token %v is the agent's or shared", c.ProgressToken)
			}
			seen[c.ProgressToken] = true
		}
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.progress) != 0 {
		t.Errorf("%d relays outlive their calls", len(up.progress))
	}
}

// TestWatchProgressNeverSharesToken: a relay whose token is already mapped
// draws a fresh one; the relay already mapped keeps its token, and ending
// either removes only its own mapping.
func TestWatchProgressNeverSharesToken(t *testing.T) {
	u := &upstream{name: testServer}
	mk := func(key string) *progressRelay {
		return newProgressRelay(context.Background(), call{up: u, agent: agentPeer{session: &mcp.ServerSession{}}, progressToken: "p", sessionKey: key}, time.Now, 0)
	}
	a, b := mk("s-a"), mk("s-b")
	b.upToken = a.upToken
	u.watchProgress(a)
	u.watchProgress(b)
	if b.upToken == a.upToken || u.progress[a.upToken] != a || u.progress[b.upToken] != b {
		t.Fatalf("token shared or replaced: a=%q b=%q", a.upToken, b.upToken)
	}
	stale := mk("s-c")
	stale.upToken = a.upToken
	u.unwatchProgress(stale) // not the relay mapped under a's token
	if u.progress[a.upToken] != a {
		t.Fatal("ending another relay removed a's mapping")
	}
	u.unwatchProgress(b)
	u.unwatchProgress(a)
	if len(u.progress) != 0 {
		t.Fatalf("%d mappings left", len(u.progress))
	}
}
