// SPDX-License-Identifier: FSL-1.1-ALv2

package proxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/gate"
	"github.com/fathomgate/fathomgate/internal/inventory"
	"github.com/fathomgate/fathomgate/internal/policy"
	"github.com/fathomgate/fathomgate/internal/proxy"
)

// internal/gate is the proxy's Gate (M1-20 passes it in Options.Gate).
var _ proxy.Gate = (*gate.Gate)(nil)

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

// realGate is internal/gate over the repo's profiles, policy name and
// example inventory.
func realGate(t *testing.T, policyName string) *gate.Gate {
	t.Helper()
	profiles, err := classify.LoadProfileDir(repoPath("profiles"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(repoPath("policies", "examples", policyName+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := inventory.LoadFile(repoPath("inventory.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := f.Chain()
	if err != nil {
		t.Fatal(err)
	}
	g, err := gate.New(gate.Config{Policy: pol, Profiles: profiles, Inventory: inv})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// upstreamLog records which tools an upstream was called with.
type upstreamLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *upstreamLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, s)
}

func (l *upstreamLog) n() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.calls)
}

func schema(props []string, required ...string) map[string]any {
	p := map[string]any{}
	for _, name := range props {
		p[name] = map[string]any{"type": "string"}
	}
	s := map[string]any{"type": "object", "properties": p}
	if len(required) > 0 {
		r := make([]any, len(required))
		for i, name := range required {
			r[i] = name
		}
		s["required"] = r
	}
	return s
}

// upstreamServer is an in-memory upstream whose tools echo their name and
// the arguments they received.
func upstreamServer(t *testing.T, name string, log *upstreamLog, tools map[string]map[string]any) proxy.Upstream {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "fake-" + name, Version: "0"}, nil)
	for tool, sch := range tools {
		s.AddTool(&mcp.Tool{Name: tool, InputSchema: sch}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			log.add(tool + " " + string(req.Params.Arguments))
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ran " + tool + " " + string(req.Params.Arguments)}}}, nil
		})
	}
	st, ct := mcp.NewInMemoryTransports()
	if _, err := s.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	used := false
	return proxy.Upstream{Server: name, NewTransport: func() mcp.Transport {
		if used {
			return nil
		}
		used = true
		return ct
	}}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestRealGateThroughProxy runs internal/gate behind the proxy, with the
// repo's eos-mcp and netdev-ssh-mcp profiles, prod-approval and the example
// inventory: allow, deny, hold and cannot run reach the agent as ADR 0026
// words them, a refused call makes no upstream call, the advertised schema
// drops what the profile does not name, and every call logs one decision
// line.
func TestRealGateThroughProxy(t *testing.T) {
	ctx := context.Background()
	eosLog, netdevLog := &upstreamLog{}, &upstreamLog{}
	ups := []proxy.Upstream{
		upstreamServer(t, "eos-mcp", eosLog, map[string]map[string]any{
			"get_version": schema([]string{"hostname", "config_path"}, "hostname"),
			"push_config": schema([]string{"hostname", "config_lines", "dry_run", "commit_timer", "session_name", "config_path"}, "hostname", "config_lines"),
		}),
		upstreamServer(t, "netdev-ssh-mcp", netdevLog, map[string]map[string]any{
			"run_show_command": schema([]string{"host", "command", "port", "device_type", "username"}, "host", "command"),
		}),
	}
	buf := &syncBuf{}
	logger := slog.New(slog.NewTextHandler(buf, nil))
	p, err := proxy.New(ctx, ups, proxy.Options{Version: "test", Logger: logger, Gate: realGate(t, "prod-approval")})
	if err != nil {
		t.Fatal(err)
	}
	agSrv, agCli := mcp.NewInMemoryTransports()
	runDone := make(chan error, 1)
	go func() { runDone <- p.Run(ctx, agSrv) }()
	agent, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(ctx, agCli, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = agent.Close()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return")
		}
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})

	// tools/list: only the named arguments are offered.
	lt, err := agent.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"eos-mcp.get_version":             `{"additionalProperties":false,"properties":{"hostname":{"type":"string"}},"required":["hostname"],"type":"object"}`,
		"eos-mcp.push_config":             `{"additionalProperties":false,"properties":{"commit_timer":{"type":"string"},"config_lines":{"type":"string"},"dry_run":{"type":"string"},"hostname":{"type":"string"}},"required":["hostname","config_lines"],"type":"object"}`,
		"netdev-ssh-mcp.run_show_command": `{"additionalProperties":false,"properties":{"command":{"type":"string"},"device_type":{"type":"string"},"host":{"type":"string"},"port":{"type":"string"}},"required":["host","command"],"type":"object"}`,
	}
	for _, tl := range lt.Tools {
		b, _ := json.Marshal(tl.InputSchema)
		if string(b) != want[tl.Name] {
			t.Errorf("%s schema %s\nwant %s", tl.Name, b, want[tl.Name])
		}
	}

	for _, tc := range []struct {
		name, tool string
		args       any
		want       string // "" when forwarded
	}{
		{"allow", "netdev-ssh-mcp.run_show_command", map[string]any{"host": "core-rtr-01", "command": "show version"}, ""},
		{"deny exec", "netdev-ssh-mcp.run_show_command", map[string]any{"host": "core-rtr-01", "command": "reload"},
			"fathomgate denied netdev-ssh-mcp.run_show_command: rule no-exec (class EXEC_ARBITRARY): EXEC_ARBITRARY is denied: the call runs commands outside the read allow-list or outside configuration mode"},
		{"deny unknown target", "eos-mcp.get_version", map[string]any{"hostname": "core-x.attacker.example"},
			"fathomgate denied eos-mcp.get_version: rule default:unknown_target (class READ_OPERATIONAL): target not in inventory"},
		{"deny unnamed argument", "eos-mcp.get_version", map[string]any{"hostname": "core-rtr-01", "config_path": "/proc/self/environ"},
			"fathomgate denied eos-mcp.get_version: rule default:bad_arguments (class READ_OPERATIONAL): an argument is not named in the server profile for this tool"},
		{"deny refused argument", "netdev-ssh-mcp.run_show_command", map[string]any{"host": "core-rtr-01", "command": "show version", "username": "admin"},
			"fathomgate denied netdev-ssh-mcp.run_show_command: rule default:bad_arguments (class READ_OPERATIONAL): an argument is not named in the server profile for this tool"},
		{"deny duplicate key", "eos-mcp.get_version", json.RawMessage(`{"hostname":"core-rtr-01","hostname":"core-x.attacker.example"}`),
			"fathomgate denied eos-mcp.get_version: rule default:bad_arguments (class READ_OPERATIONAL): the arguments must be one JSON object, in UTF-8, with no key given twice"},
		{"hold", "eos-mcp.push_config", map[string]any{"hostname": "core-rtr-01", "config_lines": []any{"hostname core-rtr-01"}},
			"fathomgate held eos-mcp.push_config: rule prod-core-needs-approval (class WRITE_CONFIG): needs approval, and approvals aren't available yet, so this call was not run."},
		{"cannot run", "eos-mcp.push_config", map[string]any{"hostname": "lab-sw-01", "config_lines": []any{"hostname lab-sw-01"}},
			"fathomgate cannot run eos-mcp.push_config: rule lab-writes-free (class WRITE_CONFIG): obligation dry_run cannot be met until change-safety drivers exist"},
	} {
		before := eosLog.n() + netdevLog.n()
		res, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		after := eosLog.n() + netdevLog.n()
		var got string
		if len(res.Content) == 1 {
			if tx, ok := res.Content[0].(*mcp.TextContent); ok {
				got = tx.Text
			}
		}
		if tc.want == "" {
			if res.IsError || after != before+1 {
				t.Errorf("%s: isError=%v %q, upstream calls %d", tc.name, res.IsError, got, after-before)
			}
			continue
		}
		if !res.IsError || got != tc.want {
			t.Errorf("%s:\n got %v %q\nwant %q", tc.name, res.IsError, got, tc.want)
		}
		if after != before {
			t.Errorf("%s: a refused call reached the upstream", tc.name)
		}
	}

	// max_devices is 5 in prod-approval: five distinct devices pass, a
	// device already touched passes again, a sixth distinct one does not.
	for i, host := range []string{"core-rtr-02", "border-rtr-01", "dc-spine-01", "dc-leaf-01", "core-rtr-01", "acc-sw-01"} {
		res, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "eos-mcp.get_version", Arguments: map[string]any{"hostname": host}})
		if err != nil {
			t.Fatal(err)
		}
		// core-rtr-01 was touched by the allowed call above.
		wantDenied := i == 5
		if res.IsError != wantDenied {
			t.Errorf("get_version %s (#%d): isError=%v", host, i, res.IsError)
		}
		if wantDenied {
			if tx, _ := res.Content[0].(*mcp.TextContent); tx == nil || tx.Text != "fathomgate denied eos-mcp.get_version: rule default:session.max_devices (class READ_OPERATIONAL): this session would touch more devices than its cap allows" {
				t.Errorf("sixth device: %+v", res.Content)
			}
		}
	}

	lines := 0
	for _, l := range strings.Split(buf.String(), "\n") {
		if !strings.Contains(l, "msg=decision") {
			continue
		}
		lines++
		// Target names are logged once validated (ADR 0026); argument
		// values, commands and payloads never are.
		for _, leak := range []string{"/proc/self/environ", "show version", "reload", "hostname core-rtr-01", "admin"} {
			if strings.Contains(l, leak) {
				t.Errorf("decision line quotes an argument value %q: %s", leak, l)
			}
		}
	}
	if lines != 14 {
		t.Errorf("%d decision lines, want 14 (one per call)", lines)
	}
}

// TestRealGateLogInjection: an argument name with a newline is refused and
// stays on the decision line (threat model, log injection).
func TestRealGateLogInjection(t *testing.T) {
	ctx := context.Background()
	up := upstreamServer(t, "eos-mcp", &upstreamLog{}, map[string]map[string]any{"get_version": schema([]string{"hostname"})})
	buf := &syncBuf{}
	p, err := proxy.New(ctx, []proxy.Upstream{up}, proxy.Options{Logger: slog.New(slog.NewTextHandler(buf, nil)), Gate: realGate(t, "read-only")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() }) // runs last
	agSrv, agCli := mcp.NewInMemoryTransports()
	runCtx, stop := context.WithCancel(ctx)
	runDone := make(chan error, 1)
	go func() { runDone <- p.Run(runCtx, agSrv) }()
	// Joined before p.Close: cancel Run, then wait for it.
	t.Cleanup(func() {
		stop()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return")
		}
	})
	agent, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(ctx, agCli, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = agent.Close() })
	res, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "eos-mcp.get_version", Arguments: map[string]any{
		"hostname": "core-rtr-01", "x\ntime=0 level=ERROR msg=forged": "1",
	}})
	if err != nil || !res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, "msg=forged") && !strings.Contains(l, "msg=decision") {
			t.Errorf("an argument name started a log line: %q", l)
		}
	}
}
