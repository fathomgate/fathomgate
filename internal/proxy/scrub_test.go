package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

const canary = "FAKE-canary-7Qx2"

// sec builds a Secret list from name, value pairs.
func sec(nv ...string) []Secret {
	var out []Secret
	for i := 0; i+1 < len(nv); i += 2 {
		out = append(out, NewSecret(nv[i], nv[i+1]))
	}
	return out
}

func TestScrubber(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		secrets []Secret
		writes  []string
		want    string // after a final flush
	}{
		{name: "exact value", secrets: sec("PW", canary), writes: []string{"pw=" + canary + " ok\n"}, want: "pw=[redacted:PW] ok\n"},
		{name: "every occurrence", secrets: sec("PW", canary), writes: []string{canary + canary + "x" + canary}, want: "[redacted:PW][redacted:PW]x[redacted:PW]"},
		{name: "split across writes", secrets: sec("PW", canary), writes: []string{"a FAKE-can", "ary-", "7Qx2 b\n"}, want: "a [redacted:PW] b\n"},
		{name: "near miss is kept", secrets: sec("PW", canary), writes: []string{"FAKE-canary-7Qx", "3\n"}, want: "FAKE-canary-7Qx3\n"},
		{name: "longest first", secrets: sec("SHORT", "FAKE-ab", "LONG", "FAKE-abcdef"), writes: []string{"FAKE-abcdef FAKE-abX\n"}, want: "[redacted:LONG] [redacted:SHORT]X\n"},
		{name: "longest first across writes", secrets: sec("SHORT", "FAKE-ab", "LONG", "FAKE-abcdef"), writes: []string{"FAKE-ab", "cd", "ef\n"}, want: "[redacted:LONG]\n"},
		{name: "shorter one when longer does not complete", secrets: sec("SHORT", "FAKE-ab", "LONG", "FAKE-abcdef"), writes: []string{"FAKE-ab", "cdX\n"}, want: "[redacted:SHORT]cdX\n"},
		{name: "3-byte value not scrubbed", secrets: sec("PIN", "abc"), writes: []string{"abc\n"}, want: "abc\n"},
		{name: "4-byte value scrubbed", secrets: sec("PIN", "abcd"), writes: []string{"xabcdx\n"}, want: "x[redacted:PIN]x\n"},
		{name: "value with a newline", secrets: sec("KEY", "FAKE-line1\nline2"), writes: []string{"k: FAKE-line1\n", "line2\n"}, want: "k: [redacted:KEY]\n"},
		{name: "truncated tail of 4+ bytes at the end", secrets: sec("PW", canary), writes: []string{"died: FAKE-can"}, want: "died: [redacted:PW]"},
		{name: "truncated tail under 4 bytes at the end", secrets: sec("PW", canary), writes: []string{"died: FAK"}, want: "died: FAK"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sc := NewRedactor(tc.secrets).newStream()
			var got strings.Builder
			for _, w := range tc.writes {
				if sc == nil {
					got.WriteString(w)
					continue
				}
				got.Write(sc.write([]byte(w), false))
			}
			if sc != nil {
				got.Write(sc.write(nil, true))
			}
			if got.String() != tc.want {
				t.Fatalf("got %q\nwant %q", got.String(), tc.want)
			}
		})
	}
}

func TestNewRedactorNilWithoutEligibleValues(t *testing.T) {
	t.Parallel()
	if r := NewRedactor(sec("A", "x", "B", "abc")); r != nil {
		t.Fatal("values under MinSecretLen gave a Redactor")
	}
	var r *Redactor
	if r.Redact("x") != "x" || r.newStream() != nil {
		t.Fatal("nil Redactor changed its input")
	}
}

// Byte-at-a-time delivery, split at every position: the value is never
// released, whole or in part.
func TestScrubberEverySplit(t *testing.T) {
	t.Parallel()
	red := NewRedactor(sec("PW", canary))
	in := "before " + canary + " middle " + canary + "\n"
	want := "before [redacted:PW] middle [redacted:PW]\n"
	for cut := 0; cut <= len(in); cut++ {
		sc := red.newStream()
		got := string(sc.write([]byte(in[:cut]), false)) + string(sc.write([]byte(in[cut:]), false)) + string(sc.write(nil, true))
		if got != want {
			t.Fatalf("cut at %d: got %q", cut, got)
		}
	}
	sc := red.newStream()
	var got strings.Builder
	for i := 0; i < len(in); i++ {
		got.Write(sc.write([]byte{in[i]}, false))
	}
	got.Write(sc.write(nil, true))
	if got.String() != want {
		t.Fatalf("byte at a time: got %q", got.String())
	}
}

func newScrubbingWriter(out *strings.Builder, prefix string, secrets []Secret) *lineWriter {
	red := NewRedactor(secrets)
	return &lineWriter{w: out, prefix: prefix, red: red, scrub: red.newStream()}
}

func TestLineWriterScrubsBeforeEscaping(t *testing.T) {
	t.Parallel()
	// A value with control characters and a backslash: if escaping ran
	// first, the escaped text would no longer match the value.
	esc := "FAKE\x1b[31m\\pw\t"
	var out strings.Builder
	w := newScrubbingWriter(&out, "upstream s: ", sec("PW", esc, "TOKEN", canary))
	in := "x " + esc + " y " + canary + "\n"
	for i := 0; i < len(in); i++ {
		_, _ = w.Write([]byte{in[i]})
	}
	_, _ = w.Write([]byte("tail " + canary[:8]))
	w.Flush()
	want := "upstream s: x [redacted:PW] y [redacted:TOKEN]\nupstream s: tail [redacted:TOKEN]\n"
	if out.String() != want {
		t.Fatalf("got %q\nwant %q", out.String(), want)
	}
}

// E3: Flush ends the stream. The tail it released cannot be completed by a
// later write that would print the rest of the value.
func TestLineWriterFlushIsTerminal(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	w := newScrubbingWriter(&out, "", sec("PW", "FAKE-hunter2"))
	_, _ = w.Write([]byte("pw=FAK"))
	w.Flush()
	if n, err := w.Write([]byte("E-hunter2\n")); n != len("E-hunter2\n") || err != nil {
		t.Fatalf("Write after Flush = %d, %v; want it accepted and dropped", n, err)
	}
	w.Flush()
	if strings.Contains(out.String(), "hunter2") {
		t.Fatalf("value released across Flush: %q", out.String())
	}
	if out.String() != "pw=FAK\n" {
		t.Fatalf("got %q", out.String())
	}
	// Without secrets too: nothing after Flush.
	out.Reset()
	w = &lineWriter{w: &out}
	_, _ = w.Write([]byte("a\n"))
	w.Flush()
	_, _ = w.Write([]byte("late\n"))
	if out.String() != "a\n" {
		t.Fatalf("write after Flush reached the sink: %q", out.String())
	}
}

// A value straddling the 4096-byte cut is scrubbed before the cut, so no
// half of it reaches either line.
func TestLineWriterScrubsAcrossLineCut(t *testing.T) {
	t.Parallel()
	long := "FAKE-" + strings.Repeat("s", 5000) // longer than maxStderrLine
	for _, pad := range []int{0, maxStderrLine - 8, maxStderrLine - 1, maxStderrLine} {
		var out strings.Builder
		w := newScrubbingWriter(&out, "", sec("PW", canary, "KEY", long))
		_, _ = w.Write([]byte(strings.Repeat("x", pad) + canary + long + "\n"))
		w.Flush()
		if strings.Contains(out.String(), "FAKE") {
			t.Fatalf("pad %d: a value (or part of one) survived: %d bytes out", pad, out.Len())
		}
		// The cut may fall inside a marker (cosmetic: no value byte is
		// on either side), so count markers with the lines joined.
		joined := strings.ReplaceAll(out.String(), "\n", "")
		if strings.Count(joined, "[redacted:PW]") != 1 || strings.Count(joined, "[redacted:KEY]") != 1 {
			t.Fatalf("pad %d: markers missing: %q", pad, out.String()[max(0, out.Len()-64):])
		}
	}
}

// An upstream that logs the value inside a quoted or encoded string is
// scrubbed on the stream, before escaping doubles its backslashes.
func TestLineWriterScrubsEncodedForms(t *testing.T) {
	t.Parallel()
	v := `FAKE-q"u\o<t>é &/?` + "\t\x07\U0001F511"
	js, _ := json.Marshal(map[string]string{"password": v})
	plainBS := `FAKE-back\slash`
	lines := map[string]string{
		"go %q":           fmt.Sprintf("%q", v),
		"QuoteToASCII":    strconv.QuoteToASCII(v),
		"json":            string(js),
		"python json":     `{"password": "` + jsonASCII(v) + `"}`,
		"query escape":    "https://x/?pw=" + url.QueryEscape(v),
		"path escape":     "https://x/" + url.PathEscape(v),
		"python bytes":    "b'" + pyByteEscape(v, true) + "'",
		"python str repr": "'" + pyByteEscape(v, false) + "'",
		"repr backslash":  "'" + strings.ReplaceAll(plainBS, `\`, `\\`) + "'",
	}
	for name, line := range lines {
		var out strings.Builder
		w := newScrubbingWriter(&out, "upstream s: ", sec("PW", v, "BS", plainBS))
		_, _ = w.Write([]byte(line + "\n"))
		w.Flush()
		if strings.Contains(out.String(), "FAKE") || !strings.Contains(out.String(), "[redacted:") {
			t.Errorf("%s: %q relayed as %q", name, line, out.String())
		}
	}
}

// E4: no formatting path prints a Secret's value.
func TestSecretNeverFormatsItsValue(t *testing.T) {
	t.Parallel()
	s := NewSecret("DEVICE_PASSWORD", canary)
	c := Command{Path: "x", Env: []string{"DEVICE_USERNAME=netops"}, Secrets: []Secret{s}}
	type holder struct {
		name    string
		secrets []Secret // unexported: fmt cannot call Secret's methods here
	}
	h := holder{name: "h", secrets: []Secret{s}}
	values := map[string]any{"Secret": s, "*Secret": &s, "[]Secret": []Secret{s}, "Command": c, "*Command": &c, "holder": h, "*holder": &h}
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%10.3v"} {
			if got := fmt.Sprintf(verb, v); strings.Contains(got, canary) || strings.Contains(got, fmt.Sprintf("%x", canary)) {
				t.Errorf("%s of %s printed the value: %s", verb, name, got)
			}
		}
	}
	for name, v := range map[string]any{"Secret": s, "[]Secret": []Secret{s}, "Command": Command{Path: "x", Secrets: []Secret{s}}} {
		b, err := json.Marshal(v)
		if err != nil || strings.Contains(string(b), canary) {
			t.Errorf("json.Marshal(%s) = %s, %v", name, b, err)
		}
	}
	var buf bytes.Buffer
	for _, h := range []slog.Handler{slog.NewJSONHandler(&buf, nil), slog.NewTextHandler(&buf, nil)} {
		slog.New(h).Info("m", "secret", s, "secrets", []Secret{s}, "command", c)
	}
	if strings.Contains(buf.String(), canary) || !strings.Contains(buf.String(), "[redacted:DEVICE_PASSWORD]") {
		t.Errorf("slog: %s", buf.String())
	}
	if s.Name() != "DEVICE_PASSWORD" || s.val() != canary {
		t.Error("NewSecret lost the name or value")
	}
}

// Secrets reach the child's environment at exec time only, after the
// allow-list and before Env, and a discarded stderr still carries the
// Redactor for relayed errors.
func TestCommandSecretsEnvAndRedactor(t *testing.T) {
	t.Parallel()
	ct := Command{Path: "x", Env: []string{"DEVICE_USERNAME=netops"}, Secrets: sec("DEVICE_PASSWORD", canary)}.Transport()
	env := ct.Command.Env
	i := slices.Index(env, "DEVICE_PASSWORD="+canary)
	j := slices.Index(env, "DEVICE_USERNAME=netops")
	if i < 0 || j < 0 || i > j {
		t.Fatalf("child env order: %q", env)
	}
	if redactorOf(ct) == nil {
		t.Fatal("no Redactor on a Command with secrets and nil Stderr")
	}
	if redactorOf(Command{Path: "x"}.Transport()) != nil {
		t.Fatal("Redactor on a Command without secrets")
	}
}

// E5: an upstream JSON-RPC error relayed to the agent has passed values
// redacted before escaping and the 512-byte cap, so the cap cannot cut a
// value in half.
func TestRelayUpstreamErrorRedacts(t *testing.T) {
	t.Parallel()
	red := NewRedactor(sec("PW", canary))
	for _, msg := range []string{
		"login failed with " + canary,
		fmt.Sprintf("login failed %q", canary),
		strings.Repeat("x", maxRelayedMessage-20) + canary + " tail",
		strings.Repeat("\x1b", 100) + canary,
	} {
		got := relayUpstreamError("s", &jsonrpc.Error{Code: -32603, Message: msg}, red).Message
		if strings.Contains(got, "FAKE") {
			t.Errorf("relayed %q", got)
		}
	}
	if got := relayUpstreamError("s", &jsonrpc.Error{Code: -32603, Message: canary}, nil).Message; !strings.Contains(got, canary) {
		t.Errorf("nil Redactor changed the message: %q", got)
	}
}

func TestRedact(t *testing.T) {
	t.Parallel()
	v := `FAKE-q"u\ote` + "\x07"
	red := NewRedactor(sec("PW", v, "PIN", "abc"))
	quoted := strconv.Quote(v)
	for _, in := range []string{
		"raw " + v,
		"escaped " + escapeControl(v, 0),
		"quoted " + quoted,
		"slog msg=" + quoted,
		"escaped quoted " + escapeControl(quoted, 0),
		"url " + url.QueryEscape(v),
	} {
		got := red.Redact(in)
		if strings.Contains(got, "FAKE") || !strings.Contains(got, "[redacted:PW]") {
			t.Errorf("Redact(%q) = %q", in, got)
		}
	}
	if got := red.Redact("pin abc"); got != "pin abc" {
		t.Errorf("short value scrubbed: %q", got)
	}
}
