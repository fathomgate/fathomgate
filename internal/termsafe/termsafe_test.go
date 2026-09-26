// SPDX-License-Identifier: FSL-1.1-ALv2

package termsafe

import (
	"testing"
	"unicode/utf8"
)

// The expected values below spell every backslash out ("\\x1b"), so the
// source file holds no raw control or bidi character.

func TestQuote(t *testing.T) {
	cases := map[string]string{
		"lab-sw-01":         "lab-sw-01",
		"":                  "",
		"a b":               "a b",
		"nothere\x1b[31m.x": "\"nothere\\x1b[31m.x\"",
		"x\ny":              "\"x\\ny\"",
		"caf\u00e9":         "\"caf\\u00e9\"",
		"\u202eevil":        "\"\\u202eevil\"",
		"del\x7f":           "\"del\\x7f\"",
	}
	for in, want := range cases {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
	if got := List([]string{"a", "b\x07"}); got != "[\"a\" \"b\\a\"]" {
		t.Errorf("List = %s", got)
	}
	if got := List(nil); got != "[]" {
		t.Errorf("List(nil) = %s", got)
	}
}

func TestText(t *testing.T) {
	cases := map[string]string{
		"plain text: ok":                      "plain text: ok",
		"line one\n  line two\tend":           "line one\n  line two\tend",
		"inventory: \"nothere\x1b[31m.yaml\"": "inventory: \"nothere\\x1b[31m.yaml\"",
		"bell\x07 cr\r":                       "bell\\a cr\\r",
		"c1\u0085 csi\u009b":                  "c1\\u0085 csi\\u009b",
		"bidi \u202eevil\u2066x\u2069":        "bidi \\u202eevil\\u2066x\\u2069",
		"marks \u200e\u200f\u061c":            "marks \\u200e\\u200f\\u061c",
		"sep \u2028 \u2029":                   "sep \\u2028 \\u2029",
		"caf\u00e9 \u4e2d":                    "caf\u00e9 \u4e2d",
		"del\x7f":                             "del\\x7f",
		"bad utf8 \xff":                       "bad utf8 \ufffd",
		"bad utf8 and escape \xff\x1b":        "bad utf8 and escape \ufffd\\x1b",
	}
	for in, want := range cases {
		got := Text(in)
		if got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
		for _, r := range got {
			if Unsafe(r) {
				t.Errorf("Text(%q) still holds %U", in, r)
			}
		}
		if !utf8.ValidString(got) {
			t.Errorf("Text(%q) is not valid UTF-8", in)
		}
	}
}

func FuzzText(f *testing.F) {
	for _, s := range []string{"", "a\x1b[2Jb", "\u202e\u2028\n\t", "\xff\xfe"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := Text(s)
		for _, r := range got {
			if Unsafe(r) {
				t.Fatalf("Text(%q) = %q holds %U", s, got, r)
			}
		}
		if !utf8.ValidString(got) {
			t.Fatalf("Text(%q) = %q is not valid UTF-8", s, got)
		}
		q := Quote(s)
		for i := 0; i < len(q); i++ {
			if q[i] < 0x20 || q[i] >= 0x7f {
				t.Fatalf("Quote(%q) = %q holds byte %#x", s, q, q[i])
			}
		}
	})
}
