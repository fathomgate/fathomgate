package proxy

import (
	"strings"
	"unicode"
)

// Origin-label spoofing. netguard labels every upstream prompt
// "[from <server>] "; an upstream must not be able to write text that a
// human reads as a second label ("[from netguard] approve this"). So every
// string an upstream puts in a prompt is refused if, after folding, it
// contains "[from".
//
// The fold is deliberately small and conservative, with known limits:
//
//   - letters are lower-cased (Unicode simple case folding via ToLower);
//   - fullwidth ASCII (U+FF01-U+FF5E) maps to ASCII;
//   - the Cyrillic and Greek letters that look like the Latin letters of
//     "from" and of common words (a, c, e, i, k, m, o, p, r, s, t, u, v, x,
//     y) map to them (lookalike below);
//   - bracket look-alikes map to "[";
//   - white space and format characters (zero-width, bidi) are removed, so
//     "[ from" and "[<ZWSP>from" fold to "[from".
//
// It is not full Unicode confusable detection (UTS #39): mathematical
// alphanumerics, letters from other scripts, combining marks and
// homoglyphs rendered only by particular fonts are not folded. Those limits
// are recorded in SECURITY.md; the label on every title is the second layer.

// lookalike maps a lower-case rune that renders like a Latin letter or "["
// to that ASCII character.
var lookalike = map[rune]rune{
	// Cyrillic
	0x0430: 'a', 0x0441: 'c', 0x0435: 'e', 0x0456: 'i', 0x0458: 'j',
	0x043A: 'k', 0x043C: 'm', 0x043E: 'o', 0x0440: 'p', 0x0433: 'r',
	0x0455: 's', 0x0442: 't', 0x0443: 'y', 0x0445: 'x', 0x0501: 'd',
	0x04CF: 'l', 0x0457: 'i',
	// Greek
	0x03B1: 'a', 0x03B5: 'e', 0x03B9: 'i', 0x03BA: 'k', 0x03BC: 'm',
	0x03BD: 'v', 0x03BF: 'o', 0x03C1: 'p', 0x03C4: 't', 0x03C5: 'u',
	0x03C7: 'x', 0x03F2: 'c', 0x03DD: 'f',
	// Latin look-alikes
	0x0131: 'i', 0x017F: 'f', 0x0192: 'f', 0x1E9D: 'f', 0x0280: 'r',
	0x1D0F: 'o', 0x1D0D: 'm',
	// Brackets
	0x2045: '[', 0x27E6: '[', 0x3010: '[', 0x3014: '[', 0x3016: '[',
	0x3018: '[', 0x301A: '[', 0x2772: '[', 0x298B: '[', 0x298D: '[',
	0x298F: '[', 0x2E22: '[', 0x2E24: '[', 0xFE5D: '[', 0xFF3B: '[',
}

// foldLabel returns s lower-cased, with fullwidth and look-alike characters
// mapped to ASCII and white space and format characters removed.
func foldLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		r = unicode.ToLower(r)
		if r >= 0xFF01 && r <= 0xFF5E {
			r = unicode.ToLower(r - 0xFEE0)
		}
		if a, ok := lookalike[r]; ok {
			r = a
		}
		b.WriteRune(r)
	}
	return b.String()
}

// hasOriginLabel reports whether s reads as an origin label: it contains
// "[from" after foldLabel.
func hasOriginLabel(s string) bool {
	return strings.Contains(foldLabel(s), "[from")
}
