// SPDX-License-Identifier: FSL-1.1-ALv2

package proxy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tests for M1-32 (2): a server-initiated elicitation/create from an
// upstream fathomgate connected with server/discover is refused, with no
// policy and no profile (ADR 0008).

// rawElicitTool is the tool during whose call rawElicit sends its prompt.
const rawElicitTool = "ask_raw"

// rawElicit sends a server-initiated elicitation/create on the upstream's
// side of the connection when it reads a tools/call for rawElicitTool, and
// hands the answer it gets to answers. go-sdk's server will not send one on
// a stateless session, so this stands in for an upstream that does it
// anyway; go-sdk's client (fathomgate's side) accepts it in either era.
type rawElicit struct {
	mcp.Transport
	answers chan *jsonrpc.Response
}

func (t rawElicit) Connect(ctx context.Context) (mcp.Connection, error) {
	c, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	id, err := jsonrpc.MakeID("FAKE-raw-elicit")
	if err != nil {
		return nil, err
	}
	return &rawElicitConn{Connection: c, id: id, answers: t.answers}, nil
}

type rawElicitConn struct {
	mcp.Connection
	id      jsonrpc.ID
	answers chan<- *jsonrpc.Response
}

func (c *rawElicitConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	for {
		m, err := c.Connection.Read(ctx)
		if err != nil {
			return nil, err
		}
		if r, ok := m.(*jsonrpc.Response); ok && r.ID == c.id {
			c.answers <- r
			continue
		}
		if r, ok := m.(*jsonrpc.Request); ok && r.IsCall() && r.Method == "tools/call" && strings.Contains(string(r.Params), `"`+rawElicitTool+`"`) {
			params, err := json.Marshal(promptFor("pw"))
			if err != nil {
				return nil, err
			}
			if err := c.Write(ctx, &jsonrpc.Request{ID: c.id, Method: "elicitation/create", Params: params}); err != nil {
				return nil, err
			}
		}
		return m, nil
	}
}

// TestDiscoveredUpstreamElicitationRefused: an upstream connected with
// server/discover (2026-07-28) that sends elicitation/create during a call
// gets a refusal naming the reason and ADR 0008, and the prompt never
// reaches the agent, whichever era the agent speaks. The same prompt from
// an upstream connected with the initialise handshake (2025-11-25) is still
// relayed to a stateful agent (profile-schema 8.4). No policy is set: this
// is the path M1-19's refusal under a policy does not cover.
func TestDiscoveredUpstreamElicitationRefused(t *testing.T) {
	const refusal = "fathomgate refused an input request (elicitation) from upstream netdev-ssh-mcp during " + rawElicitTool + ": " +
		"this upstream was connected with server/discover (the stateless era), where input requests come as input_required results, " +
		"so a server-initiated prompt from it is not relayed; see ADR 0008"
	cases := []struct {
		agent, upstream string
		relayed         bool
	}{
		{agent: v2025, upstream: v2026},
		{agent: v2026, upstream: v2026},
		{agent: v2025, upstream: v2025, relayed: true},
	}
	for _, tc := range cases {
		t.Run(tc.agent+"/"+tc.upstream, func(t *testing.T) {
			answers := make(chan *jsonrpc.Response, 1)
			tool := func(s *mcp.Server) {
				s.AddTool(&mcp.Tool{Name: rawElicitTool, InputSchema: objectSchema}, func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					select {
					case r := <-answers:
						got := "an answer: " + string(r.Result)
						if r.Error != nil {
							got = "an error: " + r.Error.Error()
						}
						return textResult("upstream got " + got), nil
					case <-time.After(5 * time.Second):
						return textResult("upstream got nothing"), nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				})
			}
			wrap := func(st mcp.Transport) mcp.Transport { return rawElicit{st, answers} }
			h := newEraHarness(t, eraSetup{agent: tc.agent, upstream: tc.upstream, extra: tool, upstreamWrap: wrap})
			wantEra := eraStateful
			if tc.upstream == v2026 {
				wantEra = eraStateless
			}
			up := h.proxy.upstreams[testServer]
			if up.era != wantEra || up.handshake.Load() != (tc.upstream == v2025) {
				t.Fatalf("upstream era %s handshake %v, want %s", up.era, up.handshake.Load(), wantEra)
			}
			res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: testServer + "." + rawElicitTool, Arguments: map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			got := text(res)
			if tc.relayed {
				if len(h.prompts.all()) != 1 || !strings.HasPrefix(got, "upstream got an answer: ") || strings.Contains(got, "refused") {
					t.Fatalf("handshake upstream: prompts %d, result %q; want the prompt relayed", len(h.prompts.all()), got)
				}
				return
			}
			if n := len(h.prompts.all()); n != 0 {
				t.Fatalf("an upstream prompt reached the agent (%d)", n)
			}
			// The upstream's error carries the refusal; the agent's result
			// carries it once more, appended by fathomgate.
			if !strings.HasPrefix(got, "upstream got an error: ") || strings.Count(got, refusal) != 2 {
				t.Errorf("result %q\nwant the upstream's error and fathomgate's note, each with %q", got, refusal)
			}
		})
	}
}
