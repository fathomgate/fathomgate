package proxy

import (
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// waitDelay bounds how long reaping the upstream waits for its stderr pipe
// to drain after the process exits; a grandchild that inherited the pipe
// must not hang shutdown.
const waitDelay = 2 * time.Second

// Command describes a stdio upstream: the process the proxy spawns and talks
// to over its stdin and stdout.
//
// Lifetime: the process starts when [New] connects the transport. On
// [Proxy.Close] go-sdk closes its stdin and waits up to 5 seconds for it to
// exit, then sends SIGTERM and waits another 5 seconds, then kills it. On
// Windows SIGTERM cannot be sent, so it goes straight to Kill after the first
// 5 seconds. Only the direct child is signalled: grandchildren (the Python
// server behind `uvx`, the Node server behind `npx`) are not killed and may
// outlive the proxy if they ignore the closed stdin. If [New] fails after the
// process started, the process is killed at once.
type Command struct {
	// Path is the executable. A bare name is looked up on the proxy's PATH;
	// MCP hosts that launch with an empty PATH need an absolute path here.
	Path string
	// Args are passed to the executable verbatim; no shell is involved.
	Args []string
	// Env entries (KEY=VALUE) are added to the upstream's environment after
	// the allow-listed variables inherited from the proxy (see baseEnv) and
	// the Secrets, so they override the allow-list. They are for settings
	// that are not secret; nothing from the agent is ever added.
	Env []string
	// Stderr receives the upstream's stderr, one line at a time, each line
	// prefixed with StderrPrefix and with control characters escaped. Nil
	// discards it. It must not be the proxy's stdout.
	Stderr io.Writer
	// StderrPrefix starts every stderr line, for example
	// "upstream netdev-ssh-mcp: ".
	StderrPrefix string
	// Secrets are variables passed to the upstream (`--upstream-env-pass`).
	// Each is added to the upstream's environment as NAME=value when the
	// process is built, after the allow-list and before Env, so the value
	// is never in Env or anything else a Command prints. Every occurrence
	// of a value of at least MinSecretLen bytes, exact or in one of the
	// forms encodedForms lists, is replaced by "[redacted:NAME]" in the
	// upstream's stderr (on the raw bytes, before the line is split or
	// escaped) and in the upstream's JSON-RPC error messages relayed to the
	// agent. Shorter values are not scrubbed. Tool results are not
	// scrubbed (M2, redaction at the response serialiser).
	//
	// The transport Transport builds does hold the values: its
	// Command.Env (the *exec.Cmd's) carries NAME=value in the clear, as the
	// child's environment must. Never log, print or serialise that
	// transport or its Cmd; in particular the M4 audit writer must never
	// record it.
	Secrets []Secret
}

// Transport returns a go-sdk CommandTransport for c. Its Command.Env holds
// the Secrets' values (see Secrets): never log or serialise it.
func (c Command) Transport() *mcp.CommandTransport {
	cmd := exec.Command(c.Path, c.Args...) //nolint:gosec // G204: the upstream command is operator configuration, not agent input.
	env := baseEnv(os.Environ(), runtime.GOOS)
	for _, s := range c.Secrets {
		env = append(env, s.Name()+"="+s.val())
	}
	env = append(env, c.Env...)
	cmd.Env = env
	red := NewRedactor(c.Secrets)
	// With secrets, a lineWriter is installed even when stderr is
	// discarded: it carries the Redactor that redactorOf finds.
	if c.Stderr != nil || red != nil {
		w := c.Stderr
		if w == nil {
			w = io.Discard
		}
		cmd.Stderr = &lineWriter{w: w, prefix: c.StderrPrefix, red: red, scrub: red.newStream()}
	}
	cmd.WaitDelay = waitDelay
	return &mcp.CommandTransport{Command: cmd}
}

// Variables an upstream inherits from the proxy. Everything else, including
// the proxy's own NETGUARD_* settings and any credential in its environment,
// is withheld unless passed with Command.Env (`--upstream-env`,
// `--upstream-env-pass`).
// The LC_ names are the POSIX locale categories; no wildcard.
var (
	unixEnvAllow = []string{
		"PATH", "HOME", "USER", "LANG", "TMPDIR",
		"LC_ALL", "LC_COLLATE", "LC_CTYPE", "LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME",
	}
	windowsEnvAllow = []string{"PATH", "SystemRoot", "SystemDrive", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PATHEXT", "COMSPEC"}
)

// baseEnv returns the entries of environ an upstream inherits on goos: on
// Unix PATH, HOME, USER, LANG, TMPDIR and the POSIX LC_ categories, matched
// exactly; on Windows PATH, SystemRoot, SystemDrive, TEMP, TMP, USERPROFILE,
// APPDATA, LOCALAPPDATA, PATHEXT and COMSPEC, matched ASCII
// case-insensitively.
func baseEnv(environ []string, goos string) []string {
	var out []string
	for _, kv := range environ {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue // includes Windows' hidden "=C:=C:\..." entries
		}
		if envAllowed(k, goos) {
			out = append(out, kv)
		}
	}
	return out
}

func envAllowed(k, goos string) bool {
	if goos == "windows" {
		for _, a := range windowsEnvAllow {
			if asciiEqualFold(k, a) {
				return true
			}
		}
		return false
	}
	for _, a := range unixEnvAllow {
		if k == a {
			return true
		}
	}
	return false
}

// asciiEqualFold compares ASCII case-insensitively. Unlike strings.EqualFold
// it does not apply Unicode folding, so "\u017fystemRoot" (long s) is not
// "SystemRoot".
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
