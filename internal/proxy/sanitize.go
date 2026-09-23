package proxy

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode"
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

// isControl reports characters that must not reach a terminal, log or model
// verbatim: C0 controls (including ESC, tab and newline), DEL, C1 controls,
// format characters (Cf: bidi embeddings and overrides U+202A-U+202E and
// isolates U+2066-U+2069, zero-width space U+200B, BOM) and the line and
// paragraph separators U+2028 and U+2029 (Zl, Zp).
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
		unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
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
// characters in the line. It holds a partial line until its newline arrives,
// maxStderrLine bytes accumulate (cut back to a whole UTF-8 character), or
// Flush is called. Writes never fail, so a broken log sink cannot stall the
// upstream's stderr.
type lineWriter struct {
	mu     sync.Mutex
	w      io.Writer
	prefix string
	buf    []byte
	split  bool // the current line was already cut at maxStderrLine
}

func (l *lineWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		chunk := p
		if i >= 0 {
			chunk = p[:i]
		}
		l.buf = append(l.buf, chunk...)
		for len(l.buf) >= maxStderrLine {
			l.emitPrefix(runeCut(l.buf[:maxStderrLine]))
			l.split = true
		}
		if i < 0 {
			break
		}
		p = p[i+1:]
		// A line cut at the limit whose remainder is empty has already
		// been written in full; do not add an empty line for its newline.
		if len(l.buf) > 0 || !l.split {
			l.emit()
		}
		l.split = false
	}
	return n, nil
}

// Flush writes out a partial line, if any, as a line of its own.
func (l *lineWriter) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buf) > 0 {
		l.emit()
	}
	l.split = false
}

// emit writes the whole buffer as one line.
func (l *lineWriter) emit() { l.emitPrefix(len(l.buf)) }

// emitPrefix writes buf[:n] as one line and keeps the rest.
func (l *lineWriter) emitPrefix(n int) {
	line := strings.TrimSuffix(string(l.buf[:n]), "\r")
	l.buf = append(l.buf[:0], l.buf[n:]...)
	_, _ = io.WriteString(l.w, l.prefix+escapeControl(line, 0)+"\n")
}

// runeCut returns how much of b can be emitted without splitting a UTF-8
// character at its end: len(b), or the start of a trailing incomplete
// character. Invalid bytes are not held back.
func runeCut(b []byte) int {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) && i > 0 {
				return i
			}
			break
		}
	}
	return len(b)
}
