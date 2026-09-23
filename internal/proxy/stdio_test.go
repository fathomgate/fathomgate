package proxy

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeUpstreamEnv makes the test binary act as a stdio upstream, so the
// Command path (a real child process over stdin/stdout) is exercised
// without any external server.
const fakeUpstreamEnv = "NETGUARD_TEST_FAKE_UPSTREAM"

func TestMain(m *testing.M) {
	if os.Getenv(fakeUpstreamEnv) == "1" {
		runFakeStdioUpstream()
		return
	}
	os.Exit(m.Run())
}

// runFakeStdioUpstream serves the fake upstream on stdio. Its "exit" tool
// ends the process without answering, like a crashing upstream.
func runFakeStdioUpstream() {
	s := fakeUpstream(&recorder{}, nil)
	s.AddTool(&mcp.Tool{Name: "exit", InputSchema: objectSchema}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		os.Exit(3)
		return nil, nil
	})
	s.AddTool(&mcp.Tool{Name: "env", InputSchema: objectSchema}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: os.Getenv("NETGUARD_TEST_UPSTREAM_VAR")}}}, nil
	})
	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestStdioUpstreamRoundTripAndExit(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("no test executable: %v", err)
	}
	ctx := context.Background()
	cmd := Command{
		Path: exe,
		Args: []string{"-test.run=^$"},
		Env:  []string{fakeUpstreamEnv + "=1", "NETGUARD_TEST_UPSTREAM_VAR=FAKE-from-operator"},
	}
	startCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	p, err := New(startCtx, []Upstream{{Server: testServer, Transport: cmd.Transport()}}, Options{})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	agSrvT, agCliT := mcp.NewInMemoryTransports()
	runDone := make(chan error, 1)
	go func() { runDone <- p.Run(ctx, agSrvT) }()
	agent, err := mcp.NewClient(&mcp.Implementation{Name: "agent"}, nil).Connect(ctx, agCliT, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01", "command": "show version"}})
	if err != nil || res.IsError || !strings.Contains(text(res), "show version") {
		t.Fatalf("round trip over stdio: %v %q", err, text(res))
	}
	res, err = agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.env"})
	if err != nil || text(res) != "FAKE-from-operator" {
		t.Fatalf("upstream env: %v %q", err, text(res))
	}

	// The upstream process dies mid-call.
	res, err = agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.exit"})
	if err != nil {
		t.Fatalf("want a tool error when the upstream dies mid-call, got %v", err)
	}
	if !res.IsError || !strings.Contains(text(res), "upstream netdev-ssh-mcp is not running") {
		t.Fatalf("mid-call exit: %q", text(res))
	}
	select {
	case <-p.upstreams[testServer].done:
	case <-time.After(10 * time.Second):
		t.Fatal("proxy did not notice the upstream process exit")
	}
	res, err = agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.get_config"})
	if err != nil || !res.IsError {
		t.Fatalf("call after exit: %v %q", err, text(res))
	}

	_ = agent.Close()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close after upstream exit: %v", err)
	}
}
