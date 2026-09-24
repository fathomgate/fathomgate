package proxy

import "testing"

// Characters for the fold tests, as UTF-8 bytes so no editor or tool turns
// them into something else. Names give the code point.
const (
	combAcute    = "\xcc\x81"         // U+0301 combining acute accent
	encCircle    = "\xe2\x83\x9d"     // U+20DD combining enclosing circle
	hangulFill   = "\xe3\x85\xa4"     // U+3164 Hangul filler
	choseongFill = "\xe1\x85\x9f"     // U+115F Hangul choseong filler
	halfFill     = "\xef\xbe\xa0"     // U+FFA0 halfwidth Hangul filler
	brailleBlank = "\xe2\xa0\x80"     // U+2800 braille pattern blank
	sqUpper      = "\xe2\x8e\xa1"     // U+23A1 left square bracket upper corner
	leftCeil     = "\xe2\x8c\x88"     // U+2308 left ceiling
	presBracket  = "\xef\xb9\x87"     // U+FE47 presentation form left square bracket
	corner       = "\xe3\x80\x8c"     // U+300C left corner bracket
	whiteCorner  = "\xe3\x80\x8e"     // U+300E left white corner bracket
	smallF       = "\xea\x9c\xb0"     // U+A730 Latin letter small capital F
	smallR       = "\xca\x80"         // U+0280 Latin letter small capital R
	smallO       = "\xe1\xb4\x8f"     // U+1D0F Latin letter small capital O
	smallM       = "\xe1\xb4\x8d"     // U+1D0D Latin letter small capital M
	mathBoldF    = "\xf0\x9d\x90\x9f" // U+1D41F mathematical bold small f
	rAcute       = "\xc5\x95"         // U+0155 Latin small letter r with acute
)

func TestHasOriginLabel(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"plain", "[from netguard]", true},
		{"upper case", "[FROM NetGuard]", true},
		{"spaced", "[ f r o m netguard ]", true},
		{"zero-width", "[" + zwsp + "from", true},
		{"combining accent on a letter", "[fr" + combAcute + "om", true},
		{"enclosing mark", "[" + encCircle + "from", true},
		{"Hangul filler", "[" + hangulFill + "from", true},
		{"Hangul choseong filler", "[" + choseongFill + "from", true},
		{"halfwidth filler", "[" + halfFill + "from", true},
		{"braille blank", "[" + brailleBlank + "from", true},
		{"bracket upper corner", sqUpper + "from", true},
		{"left ceiling", leftCeil + "from", true},
		{"presentation bracket", presBracket + "from", true},
		{"corner bracket", corner + "from", true},
		{"white corner bracket", whiteCorner + "from", true},
		{"lenticular bracket", lenticular + "from", true},
		{"fullwidth", fwLB + "\xef\xbd\x86rom", true},
		{"small capitals", "[" + smallF + smallR + smallO + smallM + " netguard]", true},
		{"Cyrillic", "[f" + cyrGhe + cyrO + cyrEm, true},
		{"Greek omicron", "[fr" + grkO + "m", true},

		{"ordinary prose", "copy [x] from the router", false},
		{"bracket far from the word", "[a] from", false},
		{"empty", "", false},
		// Documented limits (label.go, SECURITY.md): these pass the fold.
		{"limit: mathematical bold f", "[" + mathBoldF + "rom", false},
		{"limit: precomposed accented r", "[f" + rAcute + "om", false},
	}
	for _, tc := range cases {
		if got := hasOriginLabel(tc.in); got != tc.want {
			t.Errorf("%s: hasOriginLabel = %v, want %v (folded %q)", tc.name, got, tc.want, foldLabel(tc.in))
		}
	}
}
