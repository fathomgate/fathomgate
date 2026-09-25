// SPDX-License-Identifier: FSL-1.1-ALv2

package proxy

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestListenerCallWithoutExtra (L1 in the security review of T0.48): a call
// that arrives over the listener but reaches the tool handler with no
// Extra, as it would if a go-sdk release stopped copying the HTTP request
// into it, is refused, in both eras, and never binds as the local agent's
// {stdio, ""}. Only the listener's mark on the context can tell it apart:
// without the mark it would read as stdio and be forwarded. The local agent
// on the same proxy is not affected.
func TestListenerCallWithoutExtra(t *testing.T) {
	h := newHTTPHarness(t, httpSetup{})
	var stripped atomic.Int32
	h.proxy.server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if r, ok := req.(*mcp.CallToolRequest); ok && r.Extra != nil {
				r.Extra = nil
				stripped.Add(1)
			}
			return next(ctx, method, req)
		}
	})
	ctx := context.Background()
	args := map[string]any{"host": "lab-sw-01", "command": "show version"}
	for _, era := range []string{v2025, v2026} {
		cs := h.connect(t, era, tokAlice, nil)
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", era, err)
		}
		if !res.IsError || !strings.Contains(text(res), "fathomgate refused netdev-ssh-mcp.run_show_command: the request arrived over the HTTP listener without an authenticated principal") {
			t.Fatalf("%s: a listener call with no Extra was not refused: %q", era, text(res))
		}
	}
	if n := stripped.Load(); n != 2 {
		t.Fatalf("stripped Extra from %d calls, want 2", n)
	}
	if calls := h.rec.all(); len(calls) != 0 {
		t.Fatalf("the upstream saw %d refused calls", len(calls))
	}

	local, _ := connectAgent(t, h.proxy, eraSetup{agent: v2025, upstream: v2026}, &promptLog{})
	res, err := local.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: args})
	if err != nil || res.IsError {
		t.Fatalf("local agent: %v %q", err, text(res))
	}
	if calls := h.rec.all(); len(calls) != 1 {
		t.Fatalf("the upstream saw %d calls, want the local agent's one", len(calls))
	}
}

// TestUpstreamExited: the channel closes when the upstream's session ends on
// its own, and not when Close ends it.
func TestUpstreamExited(t *testing.T) {
	ctx := context.Background()
	start := func(t *testing.T) (*Proxy, *mcp.ServerSession) {
		t.Helper()
		up := fakeUpstream(&recorder{}, nil)
		upSrvT, upCliT := mcp.NewInMemoryTransports()
		ss, err := up.Connect(ctx, upSrvT, nil)
		if err != nil {
			t.Fatal(err)
		}
		p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: reuse(upCliT)}}, Options{Version: "test"})
		if err != nil {
			t.Fatal(err)
		}
		return p, ss
	}

	t.Run("on its own", func(t *testing.T) {
		p, ss := start(t)
		defer func() { _ = p.Close() }()
		select {
		case <-p.UpstreamExited():
			t.Fatal("closed while the upstream runs")
		default:
		}
		_ = ss.Close()
		select {
		case <-p.UpstreamExited():
		case <-time.After(5 * time.Second):
			t.Fatal("not closed after the upstream's session ended")
		}
	})

	t.Run("by Close", func(t *testing.T) {
		p, _ := start(t)
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-p.UpstreamExited():
			t.Fatal("closed by Proxy.Close")
		default:
		}
	})
}
