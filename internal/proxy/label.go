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
// Known limits, recorded in SECURITY.md: this is not full NFKC or UTS #39.
// Mathematical alphanumerics (U+1D400 block), precomposed accented letters
// that only NFD would split (U+0155 is not folded to r), letters from other
// scripts, superscript and circled letters, and homoglyphs that only a
// particular font produces pass it. The label on the message, the form title
// and every property title is the second layer.

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

// foldLabel returns s with invisible and blank characters removed,
// lower-cased, and with fullwidth and look-alike characters mapped to ASCII.
func foldLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.In(r, unicode.Cf, unicode.Mn, unicode.Me) || blankFillers[r] {
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
