// SPDX-License-Identifier: FSL-1.1-ALv2

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fathomgate/fathomgate/internal/classify"
	fgate "github.com/fathomgate/fathomgate/internal/gate"
	"github.com/fathomgate/fathomgate/internal/gate/gatetest"
	"github.com/fathomgate/fathomgate/internal/inventory"
	"github.com/fathomgate/fathomgate/internal/policy"
)

// overheadGate is internal/gate over the repo profiles, prod-approval and
// inventory.example.yaml, and the device names of that inventory.
func overheadGate(t *testing.T) (*fgate.Gate, []string) {
	t.Helper()
	root := func(parts ...string) string { return filepath.Join(append([]string{"..", ".."}, parts...)...) }
	profiles, err := classify.LoadProfileDir(root("profiles"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(root("policies", "examples", "prod-approval.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := inventory.LoadFile(root("inventory.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := f.Chain()
	if err != nil {
		t.Fatal(err)
	}
	g, err := fgate.New(fgate.Config{Policy: pol, Profiles: profiles, Inventory: inv})
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(f.Devices))
	for i, d := range f.Devices {
		names[i] = d.Name
	}
	return g, names
}

// noopUpstreams are one in-memory upstream per server of cases, each with
// the cases' tools, every one answering "ok" at once. The schemas name
// every argument the cases send, so the gated proxy's narrowed schema
// matches what the agent sends.
func noopUpstreams(t *testing.T, cases []gatetest.Case) []Upstream {
	t.Helper()
	props := map[string]map[string]map[string]any{} // server -> tool -> properties
	for _, c := range cases {
		var args map[string]any
		if err := json.Unmarshal(c.Args, &args); err != nil {
			t.Fatal(err)
		}
		if props[c.Server] == nil {
			props[c.Server] = map[string]map[string]any{}
		}
		if props[c.Server][c.Tool] == nil {
			props[c.Server][c.Tool] = map[string]any{}
		}
		for k := range args {
			props[c.Server][c.Tool][k] = map[string]any{}
		}
	}
	ups := make([]Upstream, 0, len(props))
	for _, server := range slices.Sorted(maps.Keys(props)) {
		s := mcp.NewServer(&mcp.Implementation{Name: "noop-" + server, Version: "0"}, nil)
		for tool, p := range props[server] {
			s.AddTool(&mcp.Tool{Name: tool, InputSchema: map[string]any{"type": "object", "properties": p}},
				func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
				})
		}
		st, ct := mcp.NewInMemoryTransports()
		if _, err := s.Connect(context.Background(), st, nil); err != nil {
			t.Fatal(err)
		}
		ups = append(ups, Upstream{Server: server, NewTransport: reuse(ct)})
	}
	return ups
}

// overheadProxy is a proxy over no-op upstreams, gated by g (nil for the
// M0 pass-through), with an agent connected over an in-memory transport.
// The decision lines go to a text handler at Info that discards them, so
// each line is still formatted as serve formats it.
func overheadProxy(t *testing.T, cases []gatetest.Case, g Gate) (*Proxy, *mcp.ClientSession) {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	opts := Options{Version: "test", Logger: logger}
	if g != nil {
		opts.Gate = g
	}
	p, err := New(ctx, noopUpstreams(t, cases), opts)
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
	return p, agent
}

// overCap is a worst case one byte over the proxy's argument cap: the
// proxy refuses it before Decide, without parsing it. The extra byte is in
// a string value, not whitespace, because the agent's encoder compacts the
// arguments.
func overCap(t *testing.T, worst []gatetest.Case) gatetest.Case {
	t.Helper()
	c := worst[0]
	const key = `,"pad":""` // the added bytes around the padding
	pad := maxArgumentBytes + 1 - len(c.Args) - len(key)
	args := slices.Concat(c.Args[:len(c.Args)-1], []byte(`,"pad":"`), bytes.Repeat([]byte{'a'}, pad), []byte(`"}`))
	var compact bytes.Buffer
	if err := json.Compact(&compact, args); err != nil || compact.Len() != maxArgumentBytes+1 {
		t.Fatalf("over-cap arguments: %d bytes compacted, %v", compact.Len(), err)
	}
	return gatetest.Case{Name: "arguments one byte over the 64 KiB cap", Server: c.Server, Tool: c.Tool, Args: args,
		Effect: "deny", Rule: ruleBadArguments, Worst: true}
}

// TestDispatchOverhead pins the PRD's M1 overhead budget (M1-23) on the
// proxy's dispatch path, in process, with internal/gate over the repo
// profiles, prod-approval and inventory.example.yaml, and no-op upstreams.
//
// The added latency is decideAndRespond, what gated runs before it
// forwards or refuses a call: the argument cap, the counter key's lock and
// counters, Decide (twice when a target is already counted), the
// re-encoding of the arguments, the decision line and, for a refusal, the
// tool error. The p99 over the typical corpus must stay under the budget in
// every run; each worst case's p50 is enforced only with
// FATHOMGATE_OVERHEAD_STRICT=1 (gatetest.CheckWorst), and under -race the
// worst cases are checked for their verdict only. The session counters are
// those of one stdio agent that has already made every typical call, the
// steady state.
//
// As a check on that stage timing, every call is also sent end to end
// through an agent session, once to the gated proxy and once to a
// pass-through proxy (no Gate) over the same no-op upstreams; the logged
// difference is the latency the gate adds as the agent sees it. Its p99 is
// logged, not checked: it is set by the in-memory transport's scheduling
// jitter, which is as large on the pass-through proxy (on Windows its p99
// alone is about 10 ms for a call the gate decides in microseconds). The
// p50 of the typical corpus's differences must stay under the budget. The
// worst cases are not sent end to end under -short or -race.
func TestDispatchOverhead(t *testing.T) {
	g, names := overheadGate(t)
	worst, err := gatetest.Worst(names)
	if err != nil {
		t.Fatal(err)
	}
	typical := gatetest.Typical()
	worst = append(worst, overCap(t, worst))
	all := slices.Concat(typical, worst)
	gated, gatedAgent := overheadProxy(t, all, g)
	_, passAgent := overheadProxy(t, all, nil)
	ctx := context.Background()
	typicalRounds, worstRounds, warm := gatetest.Rounds()
	gatetest.Header(t, gatetest.WhatProxy)

	calls := make([]call, len(all))
	for i, tc := range all {
		r, ok := gated.routes[prefixName(tc.Server, tc.Tool)]
		if !ok {
			t.Fatalf("%s: no route for %s.%s", tc.Name, tc.Server, tc.Tool)
		}
		calls[i] = call{up: r.up, tool: r.tool, arguments: tc.Args, agent: agentPeer{version: "2025-11-25"}, transport: transportStdio}
	}
	stage := func(i int) (effect, rule string) {
		d, refused, err := gated.decideAndRespond(ctx, calls[i])
		if err != nil {
			t.Fatal(err)
		}
		if (refused == nil) != d.v.Forward {
			t.Fatalf("%s: forward=%v with refusal %v", all[i].Name, d.v.Forward, refused)
		}
		return d.v.Effect, d.v.RuleID
	}
	// Twice, so the second pass sees the steady-state counters.
	for range 2 {
		for i, tc := range all {
			if effect, rule := stage(i); effect != tc.Effect || rule != tc.Rule {
				t.Fatalf("%s: got %s %s, want %s %s", tc.Name, effect, rule, tc.Effect, tc.Rule)
			}
		}
	}

	// 1. The decision stage.
	k := 0
	samples := gatetest.Time(typicalRounds*len(typical), warm*len(typical), func() {
		stage(k % len(typical))
		k++
	})
	gatetest.CheckTypical(t, gatetest.WhatProxy, "typical corpus", samples)
	if gatetest.TimeWorst() {
		for i := len(typical); i < len(all); i++ {
			gatetest.CheckWorst(t, gatetest.WhatProxy, all[i].Name, gatetest.Time(worstRounds, warm, func() { stage(i) }))
		}
	} else {
		t.Logf("%s: worst cases checked for their verdict only under -race", gatetest.WhatProxy)
	}

	// 2. End to end, gated against pass-through, paired call by call.
	params := make([]*mcp.CallToolParams, len(all))
	for i, tc := range all {
		params[i] = &mcp.CallToolParams{Name: prefixName(tc.Server, tc.Tool), Arguments: tc.Args}
	}
	send := func(cs *mcp.ClientSession, i int) time.Duration {
		start := time.Now()
		res, err := cs.CallTool(ctx, params[i])
		d := time.Since(start)
		if err != nil {
			t.Fatalf("%s: %v", all[i].Name, err)
		}
		if cs == passAgent && res.IsError {
			t.Fatalf("%s: the pass-through proxy refused the call", all[i].Name)
		}
		return d
	}
	endToEnd := func(what string, idx []int, rounds int) (diffs []time.Duration) {
		withGate, without := make([]time.Duration, 0, len(idx)*rounds), make([]time.Duration, 0, len(idx)*rounds)
		for range warm {
			for _, i := range idx {
				send(gatedAgent, i)
				send(passAgent, i)
			}
		}
		for r := range rounds {
			for _, i := range idx {
				var a, b time.Duration
				if r%2 == 0 { // alternate which proxy goes first
					a, b = send(gatedAgent, i), send(passAgent, i)
				} else {
					b, a = send(passAgent, i), send(gatedAgent, i)
				}
				withGate, without = append(withGate, a), append(without, b)
				diffs = append(diffs, a-b)
			}
		}
		t.Logf("proxy end to end: %s: gated p50 %v p99 %v; pass-through p50 %v p99 %v",
			what, gatetest.Quantile(withGate, 0.50), gatetest.Quantile(withGate, 0.99),
			gatetest.Quantile(without, 0.50), gatetest.Quantile(without, 0.99))
		return diffs
	}
	idx := make([]int, len(typical))
	for i := range idx {
		idx[i] = i
	}
	const added = "proxy end to end, added (gated minus pass-through)"
	diffs := endToEnd("typical corpus", idx, max(typicalRounds/10, 20))
	p50, p99 := gatetest.Quantile(diffs, 0.50), gatetest.Quantile(diffs, 0.99)
	t.Logf("%s: typical corpus: n=%d p50 %v p99 %v", added, len(diffs), p50, p99)
	if p50 > gatetest.Limit() {
		t.Errorf("%s: typical corpus: p50 %v over the budget %v", added, p50, gatetest.Limit())
	}
	if testing.Short() || gatetest.RaceEnabled {
		return
	}
	for i := len(typical); i < len(all); i++ {
		diffs := endToEnd(all[i].Name, []int{i}, max(worstRounds/5, 5))
		t.Logf("%s: %s: p50 %v p99 %v", added, all[i].Name, gatetest.Quantile(diffs, 0.50), gatetest.Quantile(diffs, 0.99))
	}
}
