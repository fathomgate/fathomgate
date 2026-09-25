// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// oldClassifyCommand is classifyCommand as it was before M1-39, frozen: the
// same steps in the same order, with the blocklist and shell-metacharacter
// checks as the regular expressions blocked and hasShellMeta replaced
// (blocklistRegexp and shellMetaRegexp in command_equiv_test.go). The other
// checks (checkBytes, blocklistStart, isConfigRead, monitorCountOK,
// allowPrefix) are shared: M1-39 did not change them. The differential
// below holds classifyCommand to it, class and check id, on every input.
func oldClassifyCommand(cmd string) (Class, string) {
	if len(cmd) > maxCommandLen {
		return ExecArbitrary, checkTooLong
	}
	raw := strings.Trim(cmd, " \t")
	if check := checkBytes(raw); check != "" {
		return ExecArbitrary, check
	}
	fields := strings.Fields(strings.ToLower(raw))
	if len(fields) == 0 {
		return ExecArbitrary, checkEmpty
	}
	c := strings.Join(fields, " ")
	if shellMetaRegexp.MatchString(c) {
		return ExecArbitrary, checkShellMeta
	}
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "-") {
			return ExecArbitrary, checkLeadingDash
		}
	}
	if blocklistStart.MatchString(c) || blocklistRegexp.MatchString(c) {
		return ExecArbitrary, checkBlocklist
	}
	if isConfigRead(fields) {
		return ReadConfig, ""
	}
	if fields[0] == "monitor" && len(fields) > 1 && fields[1] == "traffic" && !monitorCountOK(fields) {
		return ExecArbitrary, checkNoCount
	}
	if allowPrefix.MatchString(c) {
		return ReadOperational, ""
	}
	return ExecArbitrary, checkAllowPrefix
}

// diffHandCases are the security review's hand cases for the differential
// (PR #185): separators and brackets around a verb, whitespace variants and
// near-miss abbreviations of "conf t", shell expansions, and characters that
// look like whitespace or letters but are not ASCII.
var diffHandCases = []string{
	"reload;", "(reload)", "show (reload)", "show reload;",
	"conf\tt", "conf  t", "conf \t t", "show conf\tt", "show conf  t", "show conf \t\tterminal",
	"con t", "show con t", "configurez t", "show configurez t", "conf terminalx", "show conf terminalx",
	"show ${IFS}", "show a${IFS}b", "show $'x'", "show a$\x0bb", "show a$", "show a$ b",
	"show reload", "show version ", "reload ", "show reload",
	"ｓｈｏｗ version", "show ｒｅｌｏａｄ", "shоw version",
	"SHOW RELOAD", "Show Conf T", "show WRITE-FILE x", "show Request System",
	"", " ", "\t", "show", "show\t", "reload", "write", "wr", "show start shell", "show admin save",
}

// diffCorpus is every string literal in this package's test files, each
// also as "show <s>" and "show x <s> y", plus diffHandCases. Reading the
// literals from the source keeps the corpus growing with the tests.
func diffCorpus(t testing.TB) []string {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("test files: %v %v", files, err)
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil || len(s) > maxCommandLen+16 {
				return true
			}
			add(s)
			add("show " + s)
			add("show x " + s + " y")
			return true
		})
	}
	for _, s := range diffHandCases {
		add(s)
		add("show " + s)
		add("show x " + s + " y")
	}
	return out
}

func checkDiff(t *testing.T, cmd string) {
	gotClass, gotCheck := classifyCommand(cmd)
	wantClass, wantCheck := oldClassifyCommand(cmd)
	if gotClass != wantClass || gotCheck != wantCheck {
		t.Errorf("%q: %s (%s), before M1-39 %s (%s)", cmd, gotClass, gotCheck, wantClass, wantCheck)
	}
}

// TestClassifyCommandMatchesOld is the whole-function differential over the
// corpus, a permanent tier 1 case (security review of PR #185).
func TestClassifyCommandMatchesOld(t *testing.T) {
	t.Parallel()
	corpus := diffCorpus(t)
	if len(corpus) < 1000 {
		t.Fatalf("corpus has %d commands; the test files' literals are missing", len(corpus))
	}
	for _, cmd := range corpus {
		checkDiff(t, cmd)
	}
}

// FuzzClassifyCommandMatchesOld fuzzes classifyCommand against
// oldClassifyCommand, class and check id, seeded with the corpus.
func FuzzClassifyCommandMatchesOld(f *testing.F) {
	for _, s := range diffCorpus(f) {
		f.Add(s)
	}
	f.Fuzz(checkDiff)
}
