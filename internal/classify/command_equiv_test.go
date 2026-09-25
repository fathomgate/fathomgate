// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"regexp"
	"strings"
	"testing"
)

// The regular expressions that blocked and hasShellMeta replaced in M1-39,
// kept as the reference both must agree with. They ran on the command
// lower-cased, with its words joined by one space.
var (
	blocklistRegexp = regexp.MustCompile(`(?:^|\s)(?:configure|conf(?:i(?:g(?:u(?:re?)?)?)?)?\s+t(?:e(?:r(?:m(?:i(?:n(?:al?)?)?)?)?)?)?|edit|set|delete|rollback|commit|wr(?:i(?:te?)?)?|write-file|read-file|copy|rel(?:o(?:ad?)?)?|reboot|shutdown|clear|reset|format|erase|debug|undebug|request\s+system|zeroize|admin\s+(?:save|reboot)|tclsh|bash|python|guestshell|start\s+shell)(?:\s|$)`)
	shellMetaRegexp = regexp.MustCompile(`[|<>;&"'{}*?\[\]~` + "`" + `\x5c]|\$\S`)
)

// equivSeeds are commands around every blocklist word and pair, their
// abbreviations one letter short and long, and every shell metacharacter.
var equivSeeds = []string{
	"show version", "show configure", "show conf t", "show conf terminal", "show con t",
	"show confi te", "show config term", "show configu termi", "show configur termin",
	"show configure termina", "show configure terminals", "show configures t", "show conf tx",
	"show edit", "show set", "show delete", "show rollback", "show commit", "show w", "show wr",
	"show wri", "show writ", "show write", "show writes", "show write-file x", "show read-file x",
	"show copy", "show re", "show rel", "show relo", "show reloa", "show reload", "show reloads",
	"show reboot", "show shutdown", "show clear", "show reset", "show format", "show erase",
	"show debug", "show undebug", "show request system", "show request systems", "show request",
	"show zeroize", "show admin save", "show admin reboot", "show admin saves", "show admin",
	"show tclsh", "show bash", "show python", "show guestshell", "show start shell",
	"show start shells", "show start", "show interfaces reset-reason", "show no-shutdown",
	"conf t", "configure", "write", "request system reboot", "start shell sh",
	"show a | b", "show a<b", "show a>b", "show a;b", "show a&b", `show "a"`, "show 'a'",
	"show {a}", "show a*", "show a?", "show [a]", "show ~a", "show `a`", `show a\b`,
	"show regexp _65000$", "show a$b", "show $ a", "show $", "show a$\tb", "show a$\x0bb",
	"show a$\xffb", "show a$\rb", "show a$\nb", "show a$\fb",
}

// normalisedWords is the command as classifyCommand hands it to the two
// checks: lower-cased, split into words, the words joined by one space.
func normalisedWords(cmd string) (fields []string, c string) {
	fields = strings.Fields(strings.ToLower(cmd))
	return fields, strings.Join(fields, " ")
}

// TestBlocklistWordsMatchRegexp and FuzzBlocklistWords check blocked
// against the regular expression it replaced, on every command that
// reaches the blocklist (printable ASCII, checkBytes passed).
func TestBlocklistWordsMatchRegexp(t *testing.T) {
	t.Parallel()
	for _, s := range equivSeeds {
		checkBlocklistEquiv(t, s)
	}
}

// FuzzBlocklistWords fuzzes blocked against blocklistRegexp on any
// command that passes checkBytes, seeded with equivSeeds.
func FuzzBlocklistWords(f *testing.F) {
	for _, s := range equivSeeds {
		f.Add(s)
	}
	f.Fuzz(checkBlocklistEquiv)
}

func checkBlocklistEquiv(t *testing.T, cmd string) {
	if checkBytes(cmd) != "" {
		return
	}
	fields, c := normalisedWords(cmd)
	if got, want := blocked(fields), blocklistRegexp.MatchString(c); got != want {
		t.Errorf("%q: blocked %v, the regexp %v", c, got, want)
	}
}

// TestShellMetaMatchesRegexp and FuzzShellMeta check hasShellMeta against
// the regular expression it replaced, on any string: it must agree beyond
// the printable ASCII a command is held to by then.
func TestShellMetaMatchesRegexp(t *testing.T) {
	t.Parallel()
	for _, s := range equivSeeds {
		checkShellMetaEquiv(t, s)
	}
}

// FuzzShellMeta fuzzes hasShellMeta against shellMetaRegexp on any string,
// seeded with equivSeeds.
func FuzzShellMeta(f *testing.F) {
	for _, s := range equivSeeds {
		f.Add(s)
	}
	f.Fuzz(checkShellMetaEquiv)
}

func checkShellMetaEquiv(t *testing.T, s string) {
	if got, want := hasShellMeta(s), shellMetaRegexp.MatchString(s); got != want {
		t.Errorf("%q: hasShellMeta %v, the regexp %v", s, got, want)
	}
}
