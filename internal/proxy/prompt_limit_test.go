package proxy

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestPromptLimitAcrossRounds: a stateless upstream that asks four prompts
// per round, forever, gets two rounds (8 prompts) and then a refusal: the
// 10-prompt limit counts prompts across every round of a call, whether
// netguard asks a stateful agent itself or a stateless agent drives the
// rounds through the sealed requestState.
func TestPromptLimitAcrossRounds(t *testing.T) {
	const perRound = 4
	wide := func(s *mcp.Server) {
		s.AddTool(&mcp.Tool{Name: "ask_wide", InputSchema: objectSchema}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			n := 0
			_, _ = fmt.Sscanf(req.Params.RequestState, "round-%d", &n)
			reqs := mcp.InputRequestMap{}
			for i := range perRound {
				reqs[fmt.Sprintf("r%dq%d", n, i)] = promptFor("pw")
			}
			return &mcp.CallToolResult{InputRequests: reqs, RequestState: fmt.Sprintf("round-%d", n+1)}, nil
		})
	}
	for _, agentEra := range []string{v2025, v2026} {
		t.Run("agent "+agentEra, func(t *testing.T) {
			h := newEraHarness(t, eraSetup{agent: agentEra, upstream: v2026, extra: wide})
			res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask_wide"})
			if err != nil {
				t.Fatal(err)
			}
			if !res.IsError || !strings.Contains(text(res), "more than 10 prompts in one call") {
				t.Fatalf("result %v %q", res.IsError, text(res))
			}
			if got, want := len(h.prompts.all()), 2*perRound; got != want {
				t.Fatalf("agent saw %d prompts, want %d (no half round past the limit)", got, want)
			}
		})
	}
}

// TestAskAgentSharesPromptSlot: netguard's own prompts to a stateful agent
// (askAgent) take the same per-call slot and count as a stateful
// upstream's elicitation/create, so neither path can open a prompt beside
// the other or add up past the limit.
func TestAskAgentSharesPromptSlot(t *testing.T) {
	ctx := context.Background()
	p := &Proxy{logger: discardLogger()}
	up := &upstream{name: testServer}
	c := call{up: up, tool: "ask"}
	reqs := mcp.InputRequestMap{"pw": &mcp.ElicitParams{Message: "m"}}

	f := up.begin(ctx, c, 0)
	defer up.end(f, time.Time{}, time.Time{})
	if err := up.startPrompt(f); err != nil { // an elicitation/create prompt is open
		t.Fatal(err)
	}
	_, stop, err := p.askAgent(ctx, c, f, reqs)
	if err != nil || stop == nil || !strings.Contains(text(stop), "another prompt from this upstream is still open for this call") {
		t.Fatalf("askAgent beside an open prompt: %v %q", err, text(stop))
	}
	up.endPrompt(f)

	g := up.begin(ctx, c, maxPromptsPerCall) // earlier rounds used the limit
	defer up.end(g, time.Time{}, time.Time{})
	_, stop, err = p.askAgent(ctx, c, g, reqs)
	if err != nil || stop == nil || !strings.Contains(text(stop), "more than 10 prompts in one call") {
		t.Fatalf("askAgent past the limit: %v %q", err, text(stop))
	}
	if err := up.startPrompt(g); err == nil {
		t.Fatal("elicitation/create got a slot past the limit")
	}
}
