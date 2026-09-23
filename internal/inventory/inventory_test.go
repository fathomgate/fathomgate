package inventory

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
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
		{"border-rtr-02", Target{Name: "border-rtr-02", Role: "core", Status: "pattern"}, true},
		{"CORE-dfw1-03", Target{Name: "CORE-dfw1-03", Role: "core", Site: "dfw1", Status: "pattern"}, true},
		{"lab-spine-01", Target{Name: "lab-spine-01", Tags: []string{"lab"}, Status: "pattern"}, true},
		{"acc-sw-01", Target{}, false},
	}
	for _, tc := range cases {
		got, ok := ps.Resolve(tc.name)
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
	if !ok || got.Role != "leaf" || got.Site != "lab" {
		t.Fatalf("static should win: %+v", got)
	}
	// Pattern fills in unlisted devices.
	got, ok = chain.Resolve("lab-leaf-09")
	if !ok || got.Role != "" || !reflect.DeepEqual(got.Tags, []string{"lab"}) {
		t.Fatalf("pattern should resolve: %+v %v", got, ok)
	}
	// Nothing resolves an unknown name; NetBox stub never answers.
	chain = append(chain, &NetBox{URL: "https://netbox.example"}, nil)
	if _, ok := chain.Resolve("mystery"); ok {
		t.Fatal("unknown resolved")
	}
	// Func adapter.
	chain = Chain{Func(func(n string) (Target, bool) { return Target{Name: n, Role: "fn"}, n == "fn-1" })}
	if got, ok := chain.Resolve("fn-1"); !ok || got.Role != "fn" {
		t.Fatal("Func resolver failed")
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

func TestRepoExampleInventory(t *testing.T) {
	chain, err := LoadChain(filepath.Join("..", "..", "inventory.example.yaml"))
	if err != nil {
		t.Skip("inventory.example.yaml not present:", err)
	}
	for _, name := range []string{"core-rtr-01", "lab-leaf-01"} {
		if _, ok := chain.Resolve(name); !ok {
			t.Errorf("%s should resolve from the example inventory", name)
		}
	}
}
