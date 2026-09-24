package proxy

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestStartupErrorsEscaped: an upstream that fails the handshake or
// tools/list with control characters in its message cannot put them on the
// operator's terminal. netguard serve prints New's error to stderr, and
// go-sdk's jsonrpc.Error returns the upstream's message verbatim.
func TestStartupErrorsEscaped(t *testing.T) {
	const evil = "boom\x1b[31m\nnetguard: fake line" + rlo
	cases := []struct {
		name  string
		fail  []string
		phase string
	}{
		{"handshake", []string{"server/discover", "initialize"}, "connect"}, //nolint:misspell // MCP wire method name, not prose
		{"tools/list", []string{"tools/list"}, "tools/list"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			srv := fakeUpstream(&recorder{}, nil)
			srv.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
				return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
					if slices.Contains(tc.fail, method) {
						return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: evil}
					}
					return next(ctx, method, req)
				}
			})
			st, ct := mcp.NewInMemoryTransports()
			ss, err := srv.Connect(ctx, st, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ss.Close() })

			p, err := New(ctx, []Upstream{{Server: testServer, Transport: ct}}, Options{})
			if err == nil {
				_ = p.Close()
				t.Fatal("New succeeded against a failing upstream")
			}
			msg := err.Error()
			if !strings.Contains(msg, "proxy: upstream netdev-ssh-mcp: "+tc.phase+": ") {
				t.Fatalf("error %q does not name the phase", msg)
			}
			for _, raw := range []string{"\x1b", "\n", rlo} {
				if strings.Contains(msg, raw) {
					t.Errorf("startup error carries raw %q: %q", raw, msg)
				}
			}
			if !strings.Contains(msg, `boom`+bs+`u001b[31m`+bs+`u000anetguard: fake line`) {
				t.Errorf("escaped upstream text missing: %q", msg)
			}
			// The chain is intact for callers that inspect it.
			var werr *jsonrpc.Error
			if !errors.As(err, &werr) || werr.Message != evil {
				t.Errorf("errors.As lost the upstream error: %v", werr)
			}
		})
	}
}
