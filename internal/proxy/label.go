package proxy

import (
	"strconv"
	"strings"
	"unicode"
)

// Origin-label spoofing. netguard labels every upstream prompt
// "[from <server>] "; an upstream must not be able to write text that a
// human reads as a second label ("[from netguard] approve this"). So every
// string an upstream puts in a prompt is refused if, after folding, it
// contains "[from".
//
// The fold is a small, standard-library-only stand-in for NFKC plus
// confusable skeletons (golang.org/x/text would be a new dependency):
//
//   - characters that render as nothing or as blank space are removed:
//     Unicode white space, format characters (Cf: zero-width, bidi),
//     combining marks (Mn, Me: accents and enclosing marks stacked on a
//     letter), and the blank fillers U+115F, U+1160, U+3164, U+FFA0 and the
//     blank braille pattern U+2800. So "[ from", "[<ZWSP>from" and
//     "[fr<U+0301>om" all fold to "[from";
//   - letters are lower-cased (unicode.ToLower);
//   - fullwidth ASCII (U+FF01-U+FF5E) maps to ASCII;
//   - Cyrillic and Greek letters that look like Latin letters, and Latin
//     small capitals (U+1D00 block, U+A730, U+0280 and kin), map to those
//     letters (lookalike below);
//   - bracket look-alikes map to "[".
//
// Before that, text is decoded the way a reader or renderer would show it
// (decodeAll): backslash escapes (u and four hex digits, U and eight, x and
// two, u{...}), HTML character references (decimal, hex, and the named
// brackets plus amp, lt and gt) and percent-encoding, repeated until
// nothing changes, failing closed past maxDecodePasses. Then HTML tags and
// ASCII markup punctuation (markup below) are removed, so "[*from*",
// "[`from`" and "[<b>from</b>" read as "[from". This errs toward refusing:
// prose such as "100%5B" or "[a_from" can be refused, and that is accepted.
//
// Known limits, recorded in SECURITY.md: this is not full NFKC or UTS #39.
// Mathematical alphanumerics (U+1D400 block), precomposed accented letters
// that only NFD would split (U+0155 is not folded to r), letters from other
// scripts, superscript and circled letters, and homoglyphs that only a
// particular font produces pass it. So do encodings it does not decode:
// other HTML named references (&lpar;, &Hat;, ...), octal and named
// backslash escapes (backslash 133, backslash N{LEFT SQUARE BRACKET}),
// quoted-printable (=5B), LaTeX (backslash lbrack), base64 and similar
// transforms, and a label split across two fields that a client shows side
// by side. The label on the message, the form title and every property
// title is the second layer.

// lookalike maps a lower-case rune that renders like a Latin letter or "["
// to that ASCII character.
var lookalike = map[rune]rune{
	// Cyrillic
	0x0430: 'a', 0x0441: 'c', 0x0435: 'e', 0x0456: 'i', 0x0458: 'j',
	0x043A: 'k', 0x043C: 'm', 0x043E: 'o', 0x0440: 'p', 0x0433: 'r',
	0x0455: 's', 0x0442: 't', 0x0443: 'y', 0x0445: 'x', 0x0501: 'd',
	0x04CF: 'l', 0x0457: 'i', 0x0493: 'f',
	// Greek
	0x03B1: 'a', 0x03B5: 'e', 0x03B9: 'i', 0x03BA: 'k', 0x03BC: 'm',
	0x03BD: 'v', 0x03BF: 'o', 0x03C1: 'p', 0x03C4: 't', 0x03C5: 'u',
	0x03C7: 'x', 0x03F2: 'c', 0x03DD: 'f',
	// Latin look-alikes and small capitals
	0x0131: 'i', 0x017F: 'f', 0x0192: 'f', 0x1E9D: 'f',
	0x1D00: 'a', 0x0299: 'b', 0x1D04: 'c', 0x1D05: 'd', 0x1D07: 'e',
	0xA730: 'f', 0x0262: 'g', 0x029C: 'h', 0x026A: 'i', 0x1D0A: 'j',
	0x1D0B: 'k', 0x029F: 'l', 0x1D0D: 'm', 0x0274: 'n', 0x1D0F: 'o',
	0x1D18: 'p', 0x0280: 'r', 0xA731: 's', 0x1D1B: 't', 0x1D1C: 'u',
	0x1D20: 'v', 0x1D21: 'w', 0x028F: 'y', 0x1D22: 'z',
	// Brackets
	0x2045: '[', 0x27E6: '[', 0x3010: '[', 0x3014: '[', 0x3016: '[',
	0x3018: '[', 0x301A: '[', 0x2772: '[', 0x298B: '[', 0x298D: '[',
	0x298F: '[', 0x2E22: '[', 0x2E24: '[', 0xFE5D: '[', 0xFF3B: '[',
	0x23A1: '[', 0x23A3: '[', 0x2308: '[', 0x230A: '[', 0xFE47: '[',
	0x300C: '[', 0x300E: '[', 0xFF62: '[', 0xFE41: '[', 0xFE43: '[',
}

// blankFillers render as nothing or as blank space but are letters or
// symbols, not Unicode white space.
var blankFillers = map[rune]bool{
	0x115F: true, // Hangul choseong filler
	0x1160: true, // Hangul jungseong filler
	0x3164: true, // Hangul filler
	0xFFA0: true, // halfwidth Hangul filler
	0x2800: true, // braille pattern blank
}

// foldLabel returns s as a reader would see it, for the "[from" check:
// encodings decoded (decodeAll), HTML tags and ASCII markup punctuation
// removed, invisible and blank characters removed, lower-cased, and with
// fullwidth and look-alike characters mapped to ASCII.
func foldLabel(s string) string {
	f, _ := fold(s)
	return f
}

// fold is foldLabel plus whether decoding settled within maxDecodePasses.
func fold(s string) (string, bool) {
	s, settled := decodeAll(s)
	s = stripTags(s)
	var b strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.In(r, unicode.Cf, unicode.Mn, unicode.Me) || blankFillers[r] || markup[r] {
			continue
		}
		r = unicode.ToLower(r)
		if r >= 0xFF01 && r <= 0xFF5E {
			r = unicode.ToLower(r - 0xFEE0)
		}
		if a, ok := lookalike[r]; ok {
			r = a
		}
		if markup[r] {
			continue
		}
		b.WriteRune(r)
	}
	return b.String(), settled
}

// hasOriginLabel reports whether s reads as an origin label: it contains
// "[from" after foldLabel. Text whose encodings are nested deeper than
// maxDecodePasses fails closed: it counts as a label.
func hasOriginLabel(s string) bool {
	f, settled := fold(s)
	return !settled || strings.Contains(f, "[from")
}

// backslash starts an escape sequence (ASCII 92).
const backslash = 92

// markup is ASCII punctuation that markdown or HTML renders as formatting
// rather than text, or that escapes the next character: emphasis and code
// (* _ ` ~), tag and entity delimiters (< > / &), markdown's escape (the
// backslash) and table and heading marks (| #). It is removed before the
// "[from" check, so "[*from*", "[`from`" and a markdown-escaped bracket
// still read as labels. "[" and "]" are kept: they are what is looked for.
var markup = map[rune]bool{
	'*': true, '_': true, '`': true, '~': true,
	'<': true, '>': true, '/': true, '&': true,
	backslash: true, '|': true, '#': true,
}

// maxTag bounds how long an HTML tag stripTags removes may be.
const maxTag = 256

// stripTags removes HTML tags: a "<" followed within maxTag bytes by ">"
// with no "<" between, and everything between them. So "[<b>from</b>"
// reads as "[from".
func stripTags(s string) string {
	if !strings.Contains(s, "<") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '<' {
			end := strings.IndexAny(s[i+1:min(len(s), i+1+maxTag)], "<>")
			if end >= 0 && s[i+1+end] == '>' {
				i += end + 2
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// maxDecodePasses bounds decodeAll. Text still changing after it fails
// closed (hasOriginLabel).
const maxDecodePasses = 8

// decodeAll decodes the encodings a reader or renderer might show as other
// characters, pass after pass until nothing changes, so a nested encoding
// (an escaped backslash followed by u005b, or an HTML-escaped ampersand
// before #91;) still unwraps to "[". It reports whether the text settled
// within maxDecodePasses. It is used only to decide whether text reads as
// an origin label, never for output.
func decodeAll(s string) (string, bool) {
	for range maxDecodePasses {
		next, changed := decodePass(s)
		if !changed {
			return s, true
		}
		s = next
	}
	_, changed := decodePass(s)
	return s, !changed
}

// namedRefs are the HTML named character references decoded, matched
// ASCII case-insensitively: the brackets, and the three that spell other
// encodings (&amp;#91; is &#91;).
var namedRefs = map[string]rune{
	"lsqb": '[', "lbrack": '[', "rsqb": ']', "rbrack": ']',
	"amp": '&', "lt": '<', "gt": '>',
}

// decodePass decodes one layer, left to right. Sequences it knows:
//
//   - backslash u and four hex digits, backslash U and eight, backslash x
//     and two, and backslash u{...} with one to six hex digits;
//   - HTML character references: ampersand, #, one to seven decimal digits
//     or x and one to six hex digits, and ampersand plus a name from
//     namedRefs; the closing ";" is optional, as browsers allow;
//   - percent-encoding: % and two hex digits.
//
// A sequence that is not well formed, or decodes past U+10FFFF, is left as
// it is. A sequence after an escaped backslash is decoded all the same:
// refusing more is the safe side.
func decodePass(s string) (string, bool) {
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); {
		if r, n := decodeAt(s[i:]); n > 0 {
			b.WriteRune(r)
			i += n
			changed = true
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), changed
}

// decodeAt decodes one sequence at the start of s, returning the rune and
// the bytes consumed, or 0 bytes if s does not start with one.
func decodeAt(s string) (rune, int) {
	if len(s) < 2 {
		return 0, 0
	}
	switch s[0] {
	case backslash:
		switch s[1] {
		case 'u':
			if len(s) > 2 && s[2] == '{' {
				if end := strings.IndexByte(s[3:min(len(s), 10)], '}'); end > 0 {
					return hexRune(s[3:3+end], 3+end+1)
				}
				return 0, 0
			}
			return hexRune(prefix(s[2:], 4), 6)
		case 'U':
			return hexRune(prefix(s[2:], 8), 10)
		case 'x':
			return hexRune(prefix(s[2:], 2), 4)
		}
	case '%':
		return hexRune(prefix(s[1:], 2), 3)
	case '&':
		return htmlRef(s)
	}
	return 0, 0
}

// prefix returns the first n bytes of s, or "" if s is shorter.
func prefix(s string, n int) string {
	if len(s) < n {
		return ""
	}
	return s[:n]
}

// hexRune parses digits as hex and returns the rune and n, or 0, 0.
func hexRune(digits string, n int) (rune, int) {
	if digits == "" {
		return 0, 0
	}
	v, err := strconv.ParseUint(digits, 16, 32)
	if err != nil || v > unicode.MaxRune {
		return 0, 0
	}
	return rune(v), n
}

// htmlRef decodes an HTML character reference at the start of s (which
// starts with the ampersand).
func htmlRef(s string) (rune, int) {
	if len(s) > 2 && s[1] == '#' {
		base, start, max := 10, 2, 7
		if s[2] == 'x' || s[2] == 'X' {
			base, start, max = 16, 3, 6
		}
		end := start
		for end < len(s) && end-start < max && isDigit(s[end], base) {
			end++
		}
		if end == start {
			return 0, 0
		}
		v, err := strconv.ParseUint(s[start:end], base, 32)
		if err != nil || v > unicode.MaxRune {
			return 0, 0
		}
		if end < len(s) && s[end] == ';' {
			end++
		}
		return rune(v), end
	}
	// The longest known name the letters start with, so "&lbrackfrom"
	// (no ";") still decodes.
	letters := 1
	for letters < len(s) && letters <= maxRefName && isLetter(s[letters]) {
		letters++
	}
	for end := letters; end > 1; end-- {
		if r, ok := namedRefs[strings.ToLower(s[1:end])]; ok {
			if end < len(s) && s[end] == ';' {
				end++
			}
			return r, end
		}
	}
	return 0, 0
}

// maxRefName is the longest name in namedRefs ("lbrack", "rbrack").
const maxRefName = 6

func isDigit(c byte, base int) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case base == 16 && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'):
		return true
	}
	return false
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
