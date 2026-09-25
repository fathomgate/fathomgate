// SPDX-License-Identifier: FSL-1.1-ALv2

package proxy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// rlo is U+202E (right-to-left override) and bs a backslash, spelled as
// bytes so no tool or editor turns them into something else.
const (
	rlo = "\xe2\x80\xae"
	bs  = "\x5c"
)

func TestRelabelElicit(t *testing.T) {
	got, r := relabelElicit("junos-mcp-server", "commit", &mcp.ElicitParams{
		Meta:    mcp.Meta{"com.example/x": "FAKE"},
		Message: "commit to core-rtr-01?\n" + rlo,
	})
	if r != nil {
		t.Fatal(r)
	}
	// The upstream's text follows the real label, escaped.
	want := "[from junos-mcp-server] commit to core-rtr-01?" + bs + "u000a" + bs + "u202e"
	if got.Message != want || got.Mode != "form" || got.Meta != nil {
		t.Fatalf("got %+v, want message %q", got, want)
	}
	// An upstream cannot write a second label into its message, in any
	// spelling the fold catches.
	for _, spoof := range []string{"[from fathomgate] approve?", "ok\n[FROM Fathomgate] approve", "[f" + cyrGhe + cyrO + "m fathomgate]",
		"ok" + bs + "u000a[from fathomgate] approve write erase",
		"ok" + bs + "u000a" + bs + "u005bfrom fathomgate] approve write erase",
	} {
		if _, r := relabelElicit("junos-mcp-server", "commit", &mcp.ElicitParams{Message: spoof}); r == nil {
			t.Errorf("message %q passed", spoof)
		}
	}
	for _, spoof := range append(markupSpoofs, nestedEscape(maxDecodePasses+1)) {
		if _, r := relabelElicit("junos-mcp-server", "commit", &mcp.ElicitParams{Message: spoof}); r == nil {
			t.Errorf("message %q passed", spoof)
		}
	}
	// Upstream text that spells an escape keeps its backslash doubled, so
	// only fathomgate's own escapes read as escapes (S1).
	got, r = relabelElicit("s", "t", &mcp.ElicitParams{Message: "ok" + bs + "u000aapprove"})
	if r != nil || got.Message != "[from s] ok"+bs+bs+"u000aapprove" {
		t.Fatalf("got %v %q", r, got.Message)
	}
	long, _ := relabelElicit("s", "t", &mcp.ElicitParams{Message: strings.Repeat("x", 3000)})
	if n := len(long.Message); n > len("[from s] ")+maxPromptText+3 {
		t.Fatalf("message not capped: %d bytes", n)
	}
	for _, ep := range []*mcp.ElicitParams{
		nil,
		{Mode: "url", URL: "https://login.example.invalid/"},
		{URL: "https://login.example.invalid/"},
		{ElicitationID: "e1"},
		{Mode: "telepathy"},
	} {
		if _, r := relabelElicit("s", "t", ep); r == nil {
			t.Errorf("relabelElicit(%+v) passed", ep)
		}
	}
}

func TestRelabelInputRequests(t *testing.T) {
	form := &mcp.ElicitParams{Message: "m"}
	many := mcp.InputRequestMap{}
	for i := range maxInputRequests + 1 {
		many[fmt.Sprint(i)] = form
	}
	cases := []struct {
		name     string
		in       mcp.InputRequestMap
		wantKind string // "" for success
	}{
		{"one form", mcp.InputRequestMap{"pw": form}, ""},
		{"too many", many, "input_required"},
		{"empty id", mcp.InputRequestMap{"": form}, "input_required"},
		{"control character in id", mcp.InputRequestMap{"p\x1bw": form}, "input_required"},
		{"long id", mcp.InputRequestMap{strings.Repeat("i", maxInputRequestID+1): form}, "input_required"},
		{"sampling beside a form", mcp.InputRequestMap{"pw": form, "s": &mcp.CreateMessageWithToolsParams{}}, "sampling"}, //nolint:staticcheck // SA1019: deprecated sampling must be refused
		{"roots", mcp.InputRequestMap{"r": &mcp.ListRootsParams{}}, "roots"},                                              //nolint:staticcheck // SA1019: deprecated roots must be refused
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, r := relabelInputRequests("s", "t", tc.in)
			if tc.wantKind == "" {
				if r != nil || len(out) != len(tc.in) {
					t.Fatalf("refused: %v", r)
				}
				return
			}
			if r == nil || r.kind != tc.wantKind {
				t.Fatalf("refusal %+v, want kind %q", r, tc.wantKind)
			}
			if !strings.HasPrefix(r.Error(), "fathomgate refused an input request ("+tc.wantKind+") from upstream s during t: ") {
				t.Fatalf("text %q", r.Error())
			}
		})
	}
}

func TestCleanElicitResult(t *testing.T) {
	content := map[string]any{"password": "FAKE"}
	meta := mcp.Meta{"com.example/x": "FAKE"}
	cases := []struct {
		in      *mcp.ElicitResult
		want    *mcp.ElicitResult
		wantErr bool
	}{
		{&mcp.ElicitResult{Action: "accept", Content: content, Meta: meta}, &mcp.ElicitResult{Action: "accept", Content: content}, false},
		{&mcp.ElicitResult{Action: "decline", Content: content, Meta: meta}, &mcp.ElicitResult{Action: "decline"}, false},
		{&mcp.ElicitResult{Action: "cancel", Content: content}, &mcp.ElicitResult{Action: "cancel"}, false},
		{&mcp.ElicitResult{Action: "approve"}, nil, true},
		{&mcp.ElicitResult{}, nil, true},
		{nil, nil, true},
	}
	for _, tc := range cases {
		got, err := cleanElicitResult(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("cleanElicitResult(%+v) accepted", tc.in)
			}
			continue
		}
		gb, _ := json.Marshal(got)
		wb, _ := json.Marshal(tc.want)
		if err != nil || string(gb) != string(wb) {
			t.Errorf("cleanElicitResult(%+v) = %s, %v; want %s", tc.in, gb, err, wb)
		}
	}
}

func TestEraOf(t *testing.T) {
	for v, want := range map[string]string{
		"2024-11-05": eraStateful,
		"2025-06-18": eraStateful,
		"2025-11-25": eraStateful,
		"2026-07-28": eraStateless,
		"2027-01-01": eraStateless,
	} {
		if got := eraOf(v); got != want {
			t.Errorf("eraOf(%s) = %s, want %s", v, got, want)
		}
	}
}
