package proxy

import (
	"errors"
	"fmt"
	"strings"
)

// separator joins a server prefix and an upstream tool name toward the agent:
// "<server>.<tool>". See docs/specs/profile-schema.md section 8.
const separator = "."

// maxToolName is the MCP limit on a tool name (1 to 128 characters).
const maxToolName = 128

// ValidateServerName reports whether s can be used as a tool prefix. A server
// name is the profile's `server` key: ASCII letters, digits, '_' and '-'. It
// may not contain the separator, so the first '.' in a prefixed name always
// ends the prefix, whatever the upstream tool name contains. The name
// "netguard" (in any case) is reserved, so no upstream prompt can carry the
// label "[from netguard]".
func ValidateServerName(s string) error {
	if s == "" {
		return errors.New("server name is empty")
	}
	for _, r := range s {
		if !isNameRune(r) || r == '.' {
			return fmt.Errorf("server name %q: only ASCII letters, digits, '_' and '-' are allowed", s)
		}
	}
	if asciiEqualFold(s, Name) {
		return fmt.Errorf("server name %q is reserved for the proxy itself", s)
	}
	return nil
}

// validUpstreamToolName reports whether an upstream tool name is safe to
// re-expose. The upstream is untrusted: a name outside the MCP character set
// (control characters, ANSI escapes, spaces, look-alike Unicode) is refused
// rather than passed on, and the prefixed name must fit the MCP length limit.
func validUpstreamToolName(server, tool string) error {
	if tool == "" {
		return errors.New("empty tool name")
	}
	for _, r := range tool {
		if !isNameRune(r) {
			return fmt.Errorf("tool name %q: character %q is outside [A-Za-z0-9_.-]", tool, r)
		}
	}
	if n := len(server) + len(separator) + len(tool); n > maxToolName {
		return fmt.Errorf("tool name %q: prefixed name is %d characters, the limit is %d", tool, n, maxToolName)
	}
	return nil
}

func isNameRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
		r == '_' || r == '-' || r == '.'
}

// prefixName returns the agent-facing name of an upstream tool.
func prefixName(server, tool string) string {
	return server + separator + tool
}

// splitName splits an agent-facing name into server and upstream tool name at
// the first separator. ok is false when there is no separator or either side
// is empty.
func splitName(name string) (server, tool string, ok bool) {
	server, tool, ok = strings.Cut(name, separator)
	if !ok || server == "" || tool == "" {
		return "", "", false
	}
	return server, tool, true
}
