package proxy

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// maxRelayedMessage caps an upstream error message relayed to the agent.
const maxRelayedMessage = 512

// relayUpstreamError turns an upstream JSON-RPC error into the error the agent
// sees. The message is untrusted: it is labelled "upstream <server>: ", has
// control characters escaped and is capped at maxRelayedMessage bytes. The
// upstream's data is dropped. Only the standard JSON-RPC codes that cannot be
// confused with the proxy's own answers pass through; everything else,
// including -32602 (which the proxy reserves for unknown tools), becomes
// -32603.
func relayUpstreamError(server string, werr *jsonrpc.Error) *jsonrpc.Error {
	code := werr.Code
	switch code {
	case jsonrpc.CodeParseError, jsonrpc.CodeInvalidRequest, jsonrpc.CodeMethodNotFound, jsonrpc.CodeInternalError:
	default:
		code = jsonrpc.CodeInternalError
	}
	return &jsonrpc.Error{
		Code:    code,
		Message: "upstream " + server + ": " + escapeControl(werr.Message, maxRelayedMessage),
	}
}

// isControl reports C0 controls (including ESC, tab and newline), DEL and C1
// controls.
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// escapeControl replaces control characters with the six-character text
// \uXXXX, and invalid UTF-8 with the same escape for U+FFFD, so untrusted
// text cannot move the cursor, colour a terminal or forge a new log line.
// With limit > 0 the result is cut at a character boundary to at most limit
// bytes, followed by "...".
func escapeControl(s string, limit int) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		var piece string
		switch {
		case r == utf8.RuneError && size == 1:
			piece = "\\ufffd"
		case isControl(r):
			piece = fmt.Sprintf(`\u%04x`, r)
		default:
			piece = s[i : i+size]
		}
		if limit > 0 && b.Len()+len(piece) > limit {
			b.WriteString("...")
			break
		}
		b.WriteString(piece)
		i += size
	}
	return b.String()
}

// maxStderrLine bounds how much of an unterminated upstream stderr line is
// buffered before it is written out on its own.
const maxStderrLine = 4096

// lineWriter prefixes every line written to it and escapes control
// characters in the line. It holds a partial line until its newline arrives
// (or maxStderrLine bytes accumulate); a final line without a newline is
// lost when the process exits. Writes never fail, so a broken log sink
// cannot stall the upstream's stderr.
type lineWriter struct {
	mu     sync.Mutex
	w      io.Writer
	prefix string
	buf    []byte
}

func (l *lineWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			l.buf = append(l.buf, p...)
			if len(l.buf) >= maxStderrLine {
				l.emit()
			}
			break
		}
		l.buf = append(l.buf, p[:i]...)
		p = p[i+1:]
		l.emit()
	}
	return n, nil
}

func (l *lineWriter) emit() {
	line := strings.TrimSuffix(string(l.buf), "\r")
	l.buf = l.buf[:0]
	_, _ = io.WriteString(l.w, l.prefix+escapeControl(line, 0)+"\n")
}
