package proxy

import (
	"io"
	"os"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Command describes a stdio upstream: the process the proxy spawns and talks
// to over its stdin and stdout.
type Command struct {
	// Path is the executable. A bare name is looked up on PATH; MCP hosts
	// that launch with an empty PATH need an absolute path here.
	Path string
	// Args are passed to the executable verbatim; no shell is involved.
	Args []string
	// Env entries (KEY=VALUE) are appended to the proxy's own environment,
	// so they override inherited values. Upstream credentials belong here or
	// in the inherited environment; nothing from the agent is ever added.
	Env []string
	// Stderr receives the upstream's stderr. Nil discards it. It must not be
	// the proxy's stdout.
	Stderr io.Writer
}

// Transport returns a go-sdk CommandTransport for c. The process starts when
// the transport is connected (in [New]) and is stopped by [Proxy.Close].
func (c Command) Transport() *mcp.CommandTransport {
	cmd := exec.Command(c.Path, c.Args...) //nolint:gosec // G204: the upstream command is operator configuration, not agent input.
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stderr = c.Stderr
	return &mcp.CommandTransport{Command: cmd}
}
