// SPDX-License-Identifier: FSL-1.1-ALv2

// Package termsafe keeps text that fathomgate did not write from reaching a
// terminal or CI log as control sequences. It is the one helper the CLI and
// internal/policytest use (security review of PR #197, L1), so the two
// cannot quote differently.
//
// Two tools:
//
//   - Quote and List quote one value, or a list of values, that came from a
//     file, an argument or a directory listing: a case name, an argument
//     name, a target, a path. Printable ASCII is shown as is; anything else
//     is shown Go-quoted with every non-ASCII character escaped.
//   - Text is the last line of defence at a sink: it escapes every C0
//     control (line feed and tab included), DEL, the C1 controls, the
//     Unicode line and paragraph separators and the bidirectional
//     formatting characters anywhere in a whole message, such as an error
//     about to be printed, so the message stays on one line and no value in
//     it can forge another (security re-review of PR #199, R1). Text that
//     must span lines, such as internal/configfile's fix commands, travels
//     beside the error (configfile.Hint) and is printed line by line.
package termsafe

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Quote returns s unchanged when it is printable ASCII, and Go-quoted with
// strconv.QuoteToASCII otherwise.
func Quote(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return strconv.QuoteToASCII(s)
		}
	}
	return s
}

// QuoteEach quotes every element with strconv.QuoteToASCII, printable or
// not, so a list of names reads the same whatever it holds.
func QuoteEach(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strconv.QuoteToASCII(s)
	}
	return out
}

// List is QuoteEach in brackets, separated by spaces: ["a" "b"].
func List(in []string) string {
	return "[" + strings.Join(QuoteEach(in), " ") + "]"
}

// Text escapes, in a whole message, every rune Unsafe reports, and leaves
// the rest as it is. The result is one line.
func Text(s string) string {
	clean := utf8.ValidString(s)
	for _, r := range s {
		if Unsafe(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for _, r := range s {
		if !Unsafe(r) {
			b.WriteRune(r)
			continue
		}
		q := strconv.QuoteRuneToASCII(r) // a quoted escape: backslash x1b, backslash u202e
		b.WriteString(q[1 : len(q)-1])
	}
	return b.String()
}

// Unsafe reports whether r must not reach a terminal raw inside a message:
// a C0 control (line feed and tab included), DEL, a C1 control, the line
// and paragraph separators, and the bidirectional formatting characters
// (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069). Text writes
// an invalid UTF-8 byte as U+FFFD, so no raw byte of a broken sequence gets
// through.
func Unsafe(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x2028 || r == 0x2029:
		return true
	case r == 0x061c || r == 0x200e || r == 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}
