// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fathomgate/fathomgate/internal/proxy"
)

func TestCheckListenEnvironment(t *testing.T) {
	t.Parallel()
	env := func(set bool) lookupEnvFunc {
		return func(k string) (string, bool) { return "", set && k == "MCPGODEBUG" }
	}
	if err := checkListenEnvironment(env(false)); err != nil {
		t.Fatal(err)
	}
	if err := checkListenEnvironment(env(true)); !errors.Is(err, proxy.ErrMCPGODEBUG) || !strings.Contains(err.Error(), "MCPGODEBUG") {
		t.Fatalf("error %v", err)
	}
}

func TestNewHTTPServer(t *testing.T) {
	t.Parallel()
	s := newHTTPServer(http.NotFoundHandler(), io.NopCloser(nil), shutdownGrace, nil)
	if shutdownGrace != 5*time.Second || maxConnections != 128 || firstHeaderTimeout != 3*time.Second {
		t.Fatalf("grace %v, connection cap %d, first header timeout %v", shutdownGrace, maxConnections, firstHeaderTimeout)
	}
	if s.MaxHeaderBytes != 64<<10 || s.ReadHeaderTimeout != 10*time.Second || s.IdleTimeout != 120*time.Second || s.ReadTimeout != 0 || s.WriteTimeout != 0 {
		t.Fatalf("server limits %+v", s)
	}
}

func TestLimitListener(t *testing.T) {
	t.Parallel()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := limitListener(inner, 2)
	accepted := make(chan net.Conn, 3)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()
	clients := make([]net.Conn, 0, 3)
	for range 3 {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
	}
	first, second := <-accepted, <-accepted
	// A negative check: the third connection is already dialled (it sits in
	// the kernel backlog), so a broken cap would accept it within
	// microseconds; 100 ms is ample and nothing positive can be awaited.
	select {
	case <-accepted:
		t.Fatal("a third connection was accepted past the cap")
	case <-time.After(100 * time.Millisecond):
	}
	_ = first.Close()
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("closing a connection did not free a slot")
	}
	_ = second.Close()
	_ = l.Close()
	for range accepted {
	}
	for _, c := range clients {
		_ = c.Close()
	}
}

// TestLimitListenerPanicsBelowOne (G6 in the review of PR #68): a cap below
// one would block every Accept forever; it is a programmer error.
func TestLimitListenerPanicsBelowOne(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("limitListener(l, %d) did not panic", n)
				}
			}()
			_ = limitListener(nil, n)
		}()
	}
}

// TestShutdownWithStatefulGET (G2 in the review of PR #68): with a 2025-era
// session's GET stream open, graceful Shutdown returns promptly, because
// newHTTPServer closes the proxy on shutdown, which closes the session and
// ends the stream. Without the hook Shutdown waits for its deadline. The
// shutdown grace (J4) does not wait for a GET stream: only other requests
// in flight hold it.
func TestShutdownWithStatefulGET(t *testing.T) {
	ctx := context.Background()
	up := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "0"}, nil)
	up.AddTool(&mcp.Tool{Name: "echo", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
	})
	upSrvT, upCliT := mcp.NewInMemoryTransports()
	if _, err := up.Connect(ctx, upSrvT, nil); err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(ctx, []proxy.Upstream{{Server: "fake", NewTransport: func() mcp.Transport { return upCliT }}}, proxy.Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	token := "FAKE-listener-token-0123456789abcdef0123"
	h, err := p.HTTPHandler(proxy.HTTPOptions{Tokens: map[string][]byte{"agent": []byte(token)}})
	if err != nil {
		_ = p.Close()
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = p.Close()
		t.Fatal(err)
	}
	srv := newHTTPServer(h, p, shutdownGrace, nil)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(limitListener(inner, maxConnections)) }()
	url := "http://" + inner.Addr().String() + proxy.HTTPPath
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	post := func(body, sid string) (status int, session string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
			req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Mcp-Session-Id")
	}
	status, sid := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}`, "") //nolint:misspell // MCP wire method name
	if status != 200 || sid == "" {
		t.Fatalf("initialise: status %d, session %q", status, sid)
	}
	post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, sid) //nolint:misspell // MCP wire method name

	getReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getReq.Header.Set("Accept", "text/event-stream")
	getReq.Header.Set("Mcp-Session-Id", sid)
	getReq.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	get, err := client.Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = get.Body.Close() }()
	if get.StatusCode != 200 {
		t.Fatalf("GET stream: status %d", get.StatusCode)
	}

	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := srv.Shutdown(sctx); err != nil {
		t.Fatalf("Shutdown with a stateful GET open: %v after %v", err, time.Since(start))
	}
	<-srv.hookDone
	if d := time.Since(start); d >= shutdownGrace {
		t.Fatalf("Shutdown waited %v for a GET stream", d)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close after Shutdown: %v", err)
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve: %v", err)
	}
}
