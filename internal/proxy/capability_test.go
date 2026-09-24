package proxy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestUndeclaredCapabilities: the proxy declares tools only, so every method
// of prompts, resources, logging and completions is method-not-found in
// both eras, rather than an empty list that suggests an empty capability.
func TestUndeclaredCapabilities(t *testing.T) {
	type call func(ctx context.Context, s *mcp.ClientSession) error
	methods := []struct {
		method string
		call   call
		legacy bool // only a stateful agent can send it
	}{
		{"prompts/list", func(ctx context.Context, s *mcp.ClientSession) error { _, err := s.ListPrompts(ctx, nil); return err }, false},
		{"prompts/get", func(ctx context.Context, s *mcp.ClientSession) error {
			_, err := s.GetPrompt(ctx, &mcp.GetPromptParams{Name: "x"})
			return err
		}, false},
		{"resources/list", func(ctx context.Context, s *mcp.ClientSession) error { _, err := s.ListResources(ctx, nil); return err }, false},
		{"resources/templates/list", func(ctx context.Context, s *mcp.ClientSession) error {
			_, err := s.ListResourceTemplates(ctx, nil)
			return err
		}, false},
		{"resources/read", func(ctx context.Context, s *mcp.ClientSession) error {
			_, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "file:///etc/passwd"})
			return err
		}, false},
		{"completion/complete", func(ctx context.Context, s *mcp.ClientSession) error {
			_, err := s.Complete(ctx, &mcp.CompleteParams{Ref: &mcp.CompleteReference{Type: "ref/prompt", Name: "x"}, Argument: mcp.CompleteParamsArgument{Name: "a", Value: "b"}})
			return err
		}, false},
		{"logging/setLevel", func(ctx context.Context, s *mcp.ClientSession) error {
			return s.SetLoggingLevel(ctx, &mcp.SetLoggingLevelParams{Level: "debug"}) //nolint:staticcheck // SA1019: the deprecated method must be refused
		}, true},
	}
	for _, agentEra := range []string{v2025, v2026} {
		t.Run("agent "+agentEra, func(t *testing.T) {
			h := newEraHarness(t, eraSetup{agent: agentEra, upstream: v2026})
			for _, m := range methods {
				if m.legacy && agentEra == v2026 {
					continue
				}
				t.Run(m.method, func(t *testing.T) {
					err := m.call(context.Background(), h.agent)
					var werr *jsonrpc.Error
					if !errors.As(err, &werr) || werr.Code != jsonrpc.CodeMethodNotFound {
						t.Fatalf("want -32601, got %v", err)
					}
				})
			}
			// Tools still work.
			if _, err := h.agent.ListTools(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestStatefulAgentSeesNoStatelessMeta: nothing of the 2026-07-28 era's
// self-description (io.modelcontextprotocol/ keys in _meta) reaches a
// 2025-11-25 agent, whichever era the upstream speaks, even when the
// upstream puts it in its results.
func TestStatefulAgentSeesNoStatelessMeta(t *testing.T) {
	for _, upEra := range []string{v2025, v2026} {
		t.Run("upstream "+upEra, func(t *testing.T) {
			h := newEraHarness(t, eraSetup{agent: v2025, upstream: upEra})
			ctx := context.Background()
			for _, name := range []string{"netdev-ssh-mcp.with_meta", "netdev-ssh-mcp.run_show_command", "netdev-ssh-mcp.ask"} {
				res, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{"host": "lab-sw-01"}})
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if len(res.Meta) != 0 {
					t.Errorf("%s: result _meta %v reached a 2025 agent", name, res.Meta)
				}
			}
			if _, err := h.agent.ListTools(ctx, nil); err != nil {
				t.Fatal(err)
			}
			for _, raw := range h.tap.all() {
				if strings.Contains(raw, "io.modelcontextprotocol/") {
					t.Errorf("2026-era _meta on the wire to a 2025 agent: %s", raw)
				}
			}
		})
	}
}
