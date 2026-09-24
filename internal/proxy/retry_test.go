// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Retry handling (T0.18; profile-schema section 8.2). fathomgate forwards only
// answers to prompts it relayed, bound by its sealed requestState. What it
// does not recognise it ignores (SEP-2322), and never forwards; a
// requestState that is present but fails a check is still -32602
// (TestMRTRWire).

// unsolicited is an agent's answer to a prompt fathomgate never relayed. Its
// value must never reach the upstream.
const unsolicited = "FAKE-unsolicited-answer"

func unsolicitedResponses() mcp.InputResponseMap {
	return mcp.InputResponseMap{
		"pw":                 &mcp.ElicitResult{Action: "accept", Content: map[string]any{"password": unsolicited}},
		"unknown_extra_key":  &mcp.ElicitResult{Action: "accept", Content: map[string]any{"password": unsolicited}},
		"another_unexpected": &mcp.ElicitResult{Action: "decline"},
	}
}

// TestUnsolicitedInputResponses: inputResponses without a requestState are
// ignored and the call goes up as a first call, in every era pair. The
// upstream asks again, and the agent is asked the way its era allows; the
// agent's unsolicited answer never reaches the upstream.
func TestUnsolicitedInputResponses(t *testing.T) {
	for _, e := range eras {
		t.Run("agent "+e.agent+" upstream "+e.upstream, func(t *testing.T) {
			h := newEraHarness(t, eraSetup{agent: e.agent, upstream: e.upstream, manualMRTR: true})
			res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{
				Name: "netdev-ssh-mcp.ask", InputResponses: unsolicitedResponses(),
			})
			if err != nil {
				t.Fatalf("want the call to go up, got %v", err)
			}
			calls := h.rec.all()
			if len(calls) == 0 || calls[0].Name != "ask" {
				t.Fatalf("upstream saw %+v, want the call", calls)
			}
			if calls[0].Responses != "" || calls[0].RequestState != "" {
				t.Fatalf("first upstream call carried responses %q state %q, want a first call", calls[0].Responses, calls[0].RequestState)
			}
			for _, c := range calls {
				if strings.Contains(c.Responses, unsolicited) || strings.Contains(c.Responses, "unknown_extra_key") {
					t.Fatalf("an unsolicited answer reached the upstream: %s", c.Responses)
				}
			}
			switch {
			case e.agent == v2026 && e.upstream == v2025:
				// ADR 0014: a stateful upstream's prompt to a stateless agent.
				if !res.IsError || !strings.Contains(text(res), "ADR 0014") {
					t.Fatalf("want the ADR 0014 refusal, got %v %q", res.IsError, text(res))
				}
			case e.agent == v2026:
				// Re-asked in MRTR form, relabelled, under a fresh envelope.
				ep, _ := res.InputRequests["pw"].(*mcp.ElicitParams)
				if !res.NeedsInput() || ep == nil || ep.Message != labelledPrompt || !strings.HasPrefix(res.RequestState, statePrefix) {
					t.Fatalf("want a relabelled input_required, got %q %+v", text(res), res)
				}
			default:
				// A stateful agent is asked with elicitation/create and its
				// real answer, not the unsolicited one, goes up.
				if res.IsError || !strings.Contains(text(res), "pw=accept:"+agentPassword) {
					t.Fatalf("result %v %q", res.IsError, text(res))
				}
				if n := len(h.prompts.all()); n != 1 {
					t.Fatalf("agent was asked %d times, want 1", n)
				}
			}
		})
	}
}

// TestRetryIgnoresUnknownIDs: under a valid requestState, answers to ids
// that are not outstanding are dropped; the outstanding ones cross. Only a
// stateless agent holds a requestState, and only a stateless upstream asks
// one in MRTR form (ADR 0014), so this is the 2026 x 2026 pair.
func TestRetryIgnoresUnknownIDs(t *testing.T) {
	h := newEraHarness(t, eraSetup{agent: v2026, upstream: v2026, manualMRTR: true})
	ctx := context.Background()
	args := map[string]any{"host": "core-rtr-01"}
	first, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: args})
	if err != nil || !first.NeedsInput() {
		t.Fatalf("first: %v %q", err, text(first))
	}

	// Extra ids beside the outstanding one: dropped, and the call completes.
	responses := unsolicitedResponses()
	responses["pw"] = &mcp.ElicitResult{Action: "accept", Content: map[string]any{"password": agentPassword}}
	res, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: args, RequestState: first.RequestState, InputResponses: responses})
	if err != nil || res.IsError || res.NeedsInput() || !strings.Contains(text(res), "pw=accept:"+agentPassword) {
		t.Fatalf("retry with extra ids: %v %q", err, text(res))
	}
	calls := h.rec.all()
	last := calls[len(calls)-1]
	if last.RequestState != "up-state-pw" || strings.Contains(last.Responses, "unknown_extra_key") || strings.Contains(last.Responses, "another_unexpected") {
		t.Fatalf("upstream saw %+v", last)
	}

	// Only unknown ids: nothing is answered, so the upstream asks again and
	// the agent gets a fresh input_required.
	res, err = h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: args, RequestState: first.RequestState,
		InputResponses: mcp.InputResponseMap{"zz": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"password": unsolicited}}}})
	if err != nil || !res.NeedsInput() || res.RequestState == first.RequestState {
		t.Fatalf("retry with only unknown ids: %v %q", err, text(res))
	}
	calls = h.rec.all()
	last = calls[len(calls)-1]
	if last.RequestState != "up-state-pw" || last.Responses != "" {
		t.Fatalf("upstream saw %+v, want its state and no answers", last)
	}
}

// TestNewCallClearsUnsolicited (S5): the call dispatch receives, where the
// M1 pipeline and audit plug in, carries no answers unless the agent sent
// fathomgate's requestState with them (invariant 6).
func TestNewCallClearsUnsolicited(t *testing.T) {
	r := route{up: &upstream{name: testServer}, tool: "ask"}
	for _, tc := range []struct {
		name        string
		state       string
		wantAnswers int
		wantIgnored int
	}{
		{"no requestState", "", 0, 3},
		{"with requestState", statePrefix + "x", 3, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{
				Name: "netdev-ssh-mcp.ask", RequestState: tc.state, InputResponses: unsolicitedResponses(),
			}}
			c, ignored := newCall(r, req)
			if len(c.inputResponses) != tc.wantAnswers || ignored != tc.wantIgnored || c.requestState != tc.state {
				t.Fatalf("dispatch would see %d answers (state %q), %d ignored; want %d, %d",
					len(c.inputResponses), c.requestState, ignored, tc.wantAnswers, tc.wantIgnored)
			}
		})
	}
}
