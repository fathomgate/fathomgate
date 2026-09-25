// SPDX-License-Identifier: FSL-1.1-ALv2

package inventory

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const sampleYAML = `
devices:
  - name: core-rtr-01
    role: core
    site: dfw1
    tags: [prod]
    status: active
  - name: lab-leaf-01
    role: leaf
    site: lab
    tags: [lab]
roles:
  - match: "^core-|^border-"
    role: core
  - match: "^lab-"
    tags: [lab]
  - match: "-dfw1-"
    site: dfw1
`

func TestStaticResolve(t *testing.T) {
	f, err := ParseFile([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStatic(f.Devices)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 2 {
		t.Fatalf("len %d", s.Len())
	}
	got, ok := s.Resolve("CORE-RTR-01")
	if !ok || got.Role != "core" || got.Site != "dfw1" || got.Status != "active" {
		t.Fatalf("resolve: %+v %v", got, ok)
	}
	if _, ok := s.Resolve("nope"); ok {
		t.Fatal("unknown name resolved")
	}
	if names := s.Targets(); names[0].Name != "core-rtr-01" || names[1].Name != "lab-leaf-01" {
		t.Fatalf("targets order %+v", names)
	}
	if _, err := NewStatic([]Target{{Name: "a"}, {Name: "A"}}); err == nil {
		t.Fatal("duplicate names should error")
	}
	if _, err := NewStatic([]Target{{Name: ""}}); err == nil {
		t.Fatal("empty name should error")
	}
	var nilStatic *StaticFile
	if _, ok := nilStatic.Resolve("x"); ok {
		t.Fatal("nil static should not resolve")
	}
}

func TestPatterns(t *testing.T) {
	f, err := ParseFile([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	ps, err := NewPatterns(f.Roles)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		want Target
		ok   bool
	}{
		{"border-rtr-02", Target{Name: "border-rtr-02", Role: "core"}, true},
		{"CORE-dfw1-03", Target{Name: "CORE-dfw1-03", Role: "core", Site: "dfw1"}, true},
		{"lab-spine-01", Target{Name: "lab-spine-01", Tags: []string{"lab"}}, true},
		{"acc-sw-01", Target{}, false},
	}
	for _, tc := range cases {
		got, ok := ps.Attributes(tc.name)
		if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %+v %v, want %+v %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
	if _, err := NewPatterns([]Pattern{{Match: "(", Role: "x"}}); err == nil {
		t.Fatal("bad regex should error")
	}
	if _, err := NewPatterns([]Pattern{{Match: "^x"}}); err == nil {
		t.Fatal("pattern setting nothing should error")
	}
	if _, err := NewPatterns([]Pattern{{Role: "x"}}); err == nil {
		t.Fatal("pattern without match should error")
	}
}

func TestChainOrder(t *testing.T) {
	f, err := ParseFile([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := f.Chain()
	if err != nil {
		t.Fatal(err)
	}
	// Static wins over pattern for a listed device.
	got, ok := chain.Resolve("lab-leaf-01")
	if !ok || got.Role != "leaf" || got.Site != "lab" || got.Source != SourceStatic {
		t.Fatalf("static should win: %+v", got)
	}
	// A pattern never resolves an unlisted device (ADR 0031).
	if got, ok = chain.Resolve("lab-leaf-09"); ok {
		t.Fatalf("a pattern made lab-leaf-09 known: %+v", got)
	}
	// Nothing resolves an unknown name; NetBox stub never answers; nil
	// providers are skipped.
	chain.Authorities = append(chain.Authorities, &NetBox{URL: "https://netbox.example"}, nil)
	chain.Enrichers = append(chain.Enrichers, nil)
	if _, ok := chain.Resolve("mystery"); ok {
		t.Fatal("unknown resolved")
	}
	if got, ok := chain.Resolve("core-rtr-01"); !ok || got.Role != "core" {
		t.Fatalf("nil providers broke the chain: %+v %v", got, ok)
	}
	// Func adapter.
	chain = Chain{Authorities: []Resolver{Func(func(n string) (Target, bool) { return Target{Name: n, Role: "fn"}, n == "fn-1" })}}
	if got, ok := chain.Resolve("fn-1"); !ok || got.Role != "fn" {
		t.Fatal("Func resolver failed")
	}
	// The zero Chain knows nothing.
	if _, ok := (Chain{}).Resolve("core-rtr-01"); ok {
		t.Fatal("empty chain resolved")
	}
}

func TestLoadChainAndWriteFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(p, []byte(sampleYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	chain, err := LoadChain(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := chain.Resolve("core-rtr-01"); !ok {
		t.Fatal("core-rtr-01 should resolve")
	}
	if _, err := LoadChain(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("missing file should error")
	}
	if _, err := ParseFile([]byte("devicez: []")); err == nil {
		t.Fatal("unknown key should error")
	}

	var buf bytes.Buffer
	f := &File{Devices: []Target{{Name: "a", Role: "core", Tags: []string{"x"}}}, Roles: []Pattern{{Match: "^b", Role: "b"}}}
	if err := WriteFile(&buf, f); err != nil {
		t.Fatal(err)
	}
	back, err := ParseFile(buf.Bytes())
	if err != nil {
		t.Fatalf("%v\n%s", err, buf.String())
	}
	if !reflect.DeepEqual(back, f) {
		t.Fatalf("round trip mismatch:\n%s", buf.String())
	}
}

func TestImportCSV(t *testing.T) {
	in := "\ufeffName,Role,Site,Tags,Status,Serial\n" +
		"core-rtr-01,core,dfw1,prod;critical,active,ABC123\n" +
		"lab-leaf-01,leaf,lab,\"lab, test\",planned,\n" +
		"\n" +
		"acc-sw-01,access,dfw1,,active\n"
	got, err := ImportCSV(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Target{
		{Name: "core-rtr-01", Role: "core", Site: "dfw1", Tags: []string{"prod", "critical"}, Status: "active"},
		{Name: "lab-leaf-01", Role: "leaf", Site: "lab", Tags: []string{"lab", "test"}, Status: "planned"},
		{Name: "acc-sw-01", Role: "access", Site: "dfw1", Tags: []string{}, Status: "active"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}

	// NetBox-style header names.
	got, err = ImportCSV(strings.NewReader("hostname,device_role,site_name\nx,core,dfw1\n"))
	if err != nil || len(got) != 1 || got[0].Role != "core" || got[0].Site != "dfw1" {
		t.Fatalf("aliases: %+v %v", got, err)
	}

	if _, err := ImportCSV(strings.NewReader("role,site\ncore,dfw1\n")); err == nil {
		t.Fatal("missing name column should error")
	}
	if _, err := ImportCSV(strings.NewReader("name,role\n,core\n")); err == nil {
		t.Fatal("empty name should error")
	}
	if _, err := ImportCSV(strings.NewReader("")); err == nil {
		t.Fatal("empty input should error")
	}
}

func TestSplitTags(t *testing.T) {
	if got := SplitTags(" a, b;c|d  e "); !reflect.DeepEqual(got, []string{"a", "b", "c", "d", "e"}) {
		t.Fatalf("%v", got)
	}
	if got := SplitTags(""); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

// exampleWithPatterns returns inventory.example.yaml with its commented-out
// roles: block (the last "# roles:" line and the comment lines after it)
// turned on.
func exampleWithPatterns(t *testing.T, raw []byte) []byte {
	t.Helper()
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	start := -1
	for i, l := range lines {
		if l == "# roles:" {
			start = i
		}
	}
	if start < 0 {
		t.Fatal("inventory.example.yaml has no commented-out roles: block")
	}
	var b strings.Builder
	b.WriteString(strings.Join(lines[:start], "\n"))
	b.WriteString("\n")
	for _, l := range lines[start:] {
		if !strings.HasPrefix(l, "#") {
			break
		}
		b.WriteString(strings.TrimPrefix(strings.TrimPrefix(l, "#"), " "))
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// TestRepoExampleInventory: the shipped example, once as shipped and once
// with its commented-out pattern block turned on (ADR 0031 test 2). The
// listed devices resolve either way, and no name the agent makes up does.
func TestRepoExampleInventory(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "inventory.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, withPatterns := range []bool{false, true} {
		t.Run(map[bool]string{false: "as shipped", true: "patterns on"}[withPatterns], func(t *testing.T) {
			b := raw
			if withPatterns {
				b = exampleWithPatterns(t, raw)
			}
			f, err := ParseFile(b)
			if err != nil {
				t.Fatalf("%v\n%s", err, b)
			}
			if withPatterns != (len(f.Roles) > 0) {
				t.Fatalf("patterns on %v, roles %d", withPatterns, len(f.Roles))
			}
			// Every pattern in the example matches a listed device, so
			// inventory lint passes it.
			if w := f.PatternWarnings(); len(w) != 0 {
				t.Fatalf("example pattern matches no listed device: %q", w)
			}
			chain, err := f.Chain()
			if err != nil {
				t.Fatal(err)
			}
			checkRepoExample(t, chain)
		})
	}
}

func checkRepoExample(t *testing.T, chain Chain) {
	t.Helper()
	for _, name := range []string{"core-rtr-01", "lab-leaf-01"} {
		if _, ok := chain.Resolve(name); !ok {
			t.Errorf("%s should resolve from the example inventory", name)
		}
	}
	// Lab devices are listed statically, so they carry the lab tag that
	// lab-open's lab-writes-free matches on.
	for _, name := range []string{"lab-leaf-01", "lab-spine-01", "lab-sw-01", "lab-sw-02", "lab-srl-01"} {
		tg, ok := chain.Resolve(name)
		if !ok || !slices.Contains(tg.Tags, "lab") {
			t.Errorf("%s: got %+v (known %v), want a static device tagged lab", name, tg, ok)
		}
	}
	// A name the agent makes up must never pick up the lab tag from a
	// pattern (security review of PR #154, H1): with it, lab-open would
	// allow a write to it.
	for _, name := range []string{"lab-ghost-99", "LAB-core-rtr-01", "lab-x@core-rtr-01", "lab-leaf-01.evil", "Lab-Sw-01x"} {
		if tg, _ := chain.Resolve(name); slices.Contains(tg.Tags, "lab") {
			t.Errorf("%s: resolved with tag lab (%+v); lab devices must be listed statically", name, tg)
		}
	}
	// None of these may resolve at all, with or without the patterns
	// (security review of PR #154, H1 and H2; ADR 0031): a pattern never
	// makes a name the agent sends known.
	for _, name := range []string{
		"ghost-99", "lab-x.attacker.example", "core-x.attacker.example", "fw-evil.example",
		"lab-ghost-99", "LAB-core-rtr-01", "lab-x@core-rtr-01", "lab-leaf-01.evil", "core-rtr-01.attacker.example",
	} {
		if tg, ok := chain.Resolve(name); ok {
			t.Errorf("%s: resolved as %+v; only devices listed by name may be known", name, tg)
		}
	}
}

// TestPatternWarnings: ADR 0031 decision 5. A pattern that matches no
// listed device is named in file order with the ADR's wording; a pattern
// that matches one (case-insensitively, as Resolve does) is not.
func TestPatternWarnings(t *testing.T) {
	f := &File{
		Devices: []Target{{Name: "Core-Rtr-01", Role: "core"}, {Name: "lab-sw-01", Role: "access"}},
		Roles: []Pattern{
			{Match: "^core-", Tags: []string{"prod"}},
			{Match: "^fw-", Role: "firewall"},
			{Match: "^lab-", Tags: []string{"lab"}},
			{Match: "^border-|^edge-", Role: "border"},
		},
	}
	got := f.PatternWarnings()
	want := []string{
		`inventory: roles[1] "^fw-" matches no listed device and makes nothing known (ADR 0031); list the device under devices`,
		`inventory: roles[3] "^border-|^edge-" matches no listed device and makes nothing known (ADR 0031); list the device under devices`,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("PatternWarnings() = %q, want %q", got, want)
	}
	if w := (&File{Devices: f.Devices}).PatternWarnings(); len(w) != 0 {
		t.Fatalf("no patterns: %q", w)
	}
}
