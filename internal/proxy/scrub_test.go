package proxy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

const canary = "FAKE-canary-7Qx2"

func TestScrubber(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		secrets []Secret
		writes  []string
		want    string // after a final flush
	}{
		{name: "exact value", secrets: []Secret{{"PW", canary}}, writes: []string{"pw=" + canary + " ok\n"}, want: "pw=[redacted:PW] ok\n"},
		{name: "every occurrence", secrets: []Secret{{"PW", canary}}, writes: []string{canary + canary + "x" + canary}, want: "[redacted:PW][redacted:PW]x[redacted:PW]"},
		{name: "split across writes", secrets: []Secret{{"PW", canary}}, writes: []string{"a FAKE-can", "ary-", "7Qx2 b\n"}, want: "a [redacted:PW] b\n"},
		{name: "near miss is kept", secrets: []Secret{{"PW", canary}}, writes: []string{"FAKE-canary-7Qx", "3\n"}, want: "FAKE-canary-7Qx3\n"},
		{name: "longest first", secrets: []Secret{{"SHORT", "FAKE-ab"}, {"LONG", "FAKE-abcdef"}}, writes: []string{"FAKE-abcdef FAKE-abX\n"}, want: "[redacted:LONG] [redacted:SHORT]X\n"},
		{name: "longest first across writes", secrets: []Secret{{"SHORT", "FAKE-ab"}, {"LONG", "FAKE-abcdef"}}, writes: []string{"FAKE-ab", "cd", "ef\n"}, want: "[redacted:LONG]\n"},
		{name: "shorter one when longer does not complete", secrets: []Secret{{"SHORT", "FAKE-ab"}, {"LONG", "FAKE-abcdef"}}, writes: []string{"FAKE-ab", "cdX\n"}, want: "[redacted:SHORT]cdX\n"},
		{name: "3-byte value not scrubbed", secrets: []Secret{{"PIN", "abc"}}, writes: []string{"abc\n"}, want: "abc\n"},
		{name: "4-byte value scrubbed", secrets: []Secret{{"PIN", "abcd"}}, writes: []string{"xabcdx\n"}, want: "x[redacted:PIN]x\n"},
		{name: "value with a newline", secrets: []Secret{{"KEY", "FAKE-line1\nline2"}}, writes: []string{"k: FAKE-line1\n", "line2\n"}, want: "k: [redacted:KEY]\n"},
		{name: "truncated tail of 4+ bytes at the end", secrets: []Secret{{"PW", canary}}, writes: []string{"died: FAKE-can"}, want: "died: [redacted:PW]"},
		{name: "truncated tail under 4 bytes at the end", secrets: []Secret{{"PW", canary}}, writes: []string{"died: FAK"}, want: "died: FAK"},
		{name: "no secrets eligible", secrets: []Secret{{"A", "x"}}, writes: []string{"x\n"}, want: "x\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sc := newScrubber(tc.secrets)
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

// Byte-at-a-time delivery, split at every position: the value is never
// released, whole or in part.
func TestScrubberEverySplit(t *testing.T) {
	t.Parallel()
	in := "before " + canary + " middle " + canary + "\n"
	want := "before [redacted:PW] middle [redacted:PW]\n"
	for cut := 0; cut <= len(in); cut++ {
		sc := newScrubber([]Secret{{"PW", canary}})
		got := string(sc.write([]byte(in[:cut]), false)) + string(sc.write([]byte(in[cut:]), false)) + string(sc.write(nil, true))
		if got != want {
			t.Fatalf("cut at %d: got %q", cut, got)
		}
	}
	sc := newScrubber([]Secret{{"PW", canary}})
	var got strings.Builder
	for i := 0; i < len(in); i++ {
		got.Write(sc.write([]byte{in[i]}, false))
	}
	got.Write(sc.write(nil, true))
	if got.String() != want {
		t.Fatalf("byte at a time: got %q", got.String())
	}
}

func TestLineWriterScrubsBeforeEscaping(t *testing.T) {
	t.Parallel()
	// A value with control characters and a backslash: if escaping ran
	// first, the escaped text would no longer match the value.
	esc := "FAKE\x1b[31m\\pw\t"
	var out strings.Builder
	w := &lineWriter{w: &out, prefix: "upstream s: ", scrub: newScrubber([]Secret{{"PW", esc}, {"TOKEN", canary}})}
	for i := 0; i < len("x "+esc+" y "+canary+"\n"); i++ {
		_, _ = w.Write([]byte{("x " + esc + " y " + canary + "\n")[i]})
	}
	_, _ = w.Write([]byte("tail " + canary[:8]))
	w.Flush()
	want := "upstream s: x [redacted:PW] y [redacted:TOKEN]\nupstream s: tail [redacted:TOKEN]\n"
	if out.String() != want {
		t.Fatalf("got %q\nwant %q", out.String(), want)
	}
}

// A value straddling the 4096-byte cut is scrubbed before the cut, so no
// half of it reaches either line.
func TestLineWriterScrubsAcrossLineCut(t *testing.T) {
	t.Parallel()
	long := "FAKE-" + strings.Repeat("s", 5000) // longer than maxStderrLine
	for _, pad := range []int{0, maxStderrLine - 8, maxStderrLine - 1, maxStderrLine} {
		var out strings.Builder
		w := &lineWriter{w: &out, prefix: "", scrub: newScrubber([]Secret{{"PW", canary}, {"KEY", long}})}
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

func TestSecretNeverFormatsItsValue(t *testing.T) {
	t.Parallel()
	s := Secret{Name: "DEVICE_PASSWORD", Value: canary}
	c := Command{Path: "x", Secrets: []Secret{s}}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(f, s); strings.Contains(got, canary) {
			t.Errorf("%s of Secret printed the value: %s", f, got)
		}
		if got := fmt.Sprintf(f, c.Secrets); strings.Contains(got, canary) {
			t.Errorf("%s of []Secret printed the value: %s", f, got)
		}
	}
}

// An upstream that logs the value inside a quoted string (Go %q, a JSON log
// line, Python's json.dumps or repr) is scrubbed on the stream, before
// escaping doubles its backslashes.
func TestLineWriterScrubsEncodedForms(t *testing.T) {
	t.Parallel()
	v := `FAKE-q"u\o<t>é` + "\t\U0001F511"
	goQ := fmt.Sprintf("%q", v)
	goASCII := strconv.QuoteToASCII(v)
	js, _ := json.Marshal(map[string]string{"password": v})
	pyJSON := `{"password": "` + jsonASCII(v) + `"}`
	plainBS := `FAKE-back\slash`
	for _, line := range []string{"go " + goQ, "ascii " + goASCII, "json " + string(js), "python " + pyJSON, "repr '" + strings.ReplaceAll(plainBS, `\`, `\\`) + "'"} {
		var out strings.Builder
		w := &lineWriter{w: &out, prefix: "upstream s: ", scrub: newScrubber([]Secret{{"PW", v}, {"BS", plainBS}})}
		_, _ = w.Write([]byte(line + "\n"))
		w.Flush()
		if strings.Contains(out.String(), "FAKE") || !strings.Contains(out.String(), "[redacted:") {
			t.Errorf("%q relayed as %q", line, out.String())
		}
	}
}

func TestRedactSecrets(t *testing.T) {
	t.Parallel()
	v := `FAKE-q"u\ote` + "\x07"
	secrets := []Secret{{"PW", v}, {"PIN", "abc"}}
	quoted := strconv.Quote(v)
	for _, in := range []string{
		"raw " + v,
		"escaped " + escapeControl(v, 0),
		"quoted " + quoted,
		"slog msg=" + quoted,
	} {
		got := RedactSecrets(in, secrets)
		if strings.Contains(got, "FAKE") {
			t.Errorf("RedactSecrets(%q) = %q", in, got)
		}
		if !strings.Contains(got, "[redacted:PW]") {
			t.Errorf("RedactSecrets(%q) = %q, want the marker", in, got)
		}
	}
	if got := RedactSecrets("pin abc", secrets); got != "pin abc" {
		t.Errorf("short value scrubbed: %q", got)
	}
	if got := RedactSecrets("nothing here", nil); got != "nothing here" {
		t.Errorf("no secrets: %q", got)
	}
}
