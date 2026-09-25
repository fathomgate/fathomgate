// SPDX-License-Identifier: FSL-1.1-ALv2

package inventory

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// attackerPatterns are the patterns of ADR 0031 test 1: before ADR 0031 each
// made every attacker name below a known device.
var attackerPatterns = []Pattern{
	{Match: "^core-|^border-", Role: "core"},
	{Match: "^lab-", Tags: []string{"lab"}},
	{Match: "^fw-", Role: "firewall"},
}

// attackerNames are the names of the PR #154 review and ADR 0031 test 1.
var attackerNames = []string{
	"core-x.attacker.example",
	"core-rtr-01.attacker.example",
	"fw-evil.example",
	"lab-ghost-99",
	"LAB-core-rtr-01",
	"lab-x@core-rtr-01",
	"lab-leaf-01.evil",
	"ghost-99",
}

func mustChain(t testing.TB, f *File) Chain {
	t.Helper()
	c, err := f.Chain()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestPatternsAloneResolveNothing: ADR 0031 test 1. Patterns with no listed
// devices make no name known.
func TestPatternsAloneResolveNothing(t *testing.T) {
	t.Parallel()
	c := mustChain(t, &File{Roles: attackerPatterns})
	for _, name := range attackerNames {
		if got, ok := c.Resolve(name); ok || !reflect.DeepEqual(got, Target{}) {
			t.Errorf("%s: resolved as %+v (known %v); a pattern alone must not make a name known", name, got, ok)
		}
	}
	// The same names would match a pattern: the test is not vacuous.
	ps, err := NewPatterns(attackerPatterns)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range attackerNames {
		if name == "ghost-99" {
			continue
		}
		if len(ps.Matching(name)) == 0 {
			t.Errorf("%s matches no attacker pattern; the test lost its point", name)
		}
	}
}

// TestPatternsWithListedDevices: ADR 0031 test 2's first half. With the
// example's devices listed and the attacker patterns active, every attacker
// name is still unknown, and the listed names still resolve.
func TestPatternsWithListedDevices(t *testing.T) {
	t.Parallel()
	f, err := LoadFile("../../inventory.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f.Roles = append(f.Roles, attackerPatterns...)
	c := mustChain(t, f)
	for _, name := range attackerNames {
		if got, ok := c.Resolve(name); ok {
			t.Errorf("%s: resolved as %+v", name, got)
		}
	}
	for _, d := range f.Devices {
		got, ok := c.Resolve(d.Name)
		if !ok || got.Name != d.Name || got.Role != d.Role {
			t.Errorf("%s: %+v %v, want the listed record", d.Name, got, ok)
		}
	}
}

// TestEnrichment: ADR 0031 test 3 and inventory-schema section 2.
func TestEnrichment(t *testing.T) {
	t.Parallel()
	f := &File{
		Devices: []Target{
			{Name: "core-rtr-09", Site: "dfw1", Status: "active"},
			{Name: "core-acc-01", Role: "access", Tags: []string{"prod"}},
			{Name: "lab-sw-09"},
			{Name: "lab-core-01", Tags: []string{"lab", "canary"}},
		},
		Roles: []Pattern{
			{Match: "^core-|^border-", Role: "core", Site: "lon1", Tags: []string{"backbone"}},
			{Match: "^lab-", Tags: []string{"lab"}, Site: "lab"},
			{Match: "-core-", Role: "spine", Tags: []string{"backbone", "lab"}},
		},
	}
	c := mustChain(t, f)
	cases := []struct {
		name string
		want Target
	}{
		{
			// No role listed: the pattern fills it; the listed site wins.
			"core-rtr-09",
			Target{
				Name: "core-rtr-09", Role: "core", Site: "dfw1", Status: "active", Tags: []string{"backbone"}, Source: SourceStatic,
				Sources: &Sources{Name: SourceStatic, Role: SourcePattern, Site: SourceStatic, Status: SourceStatic, Tags: map[string]string{"backbone": SourcePattern}},
			},
		},
		{
			// A listed role is kept although ^core- sets core; the
			// listed tags are kept and the pattern's are added.
			"core-acc-01",
			Target{
				Name: "core-acc-01", Role: "access", Site: "lon1", Tags: []string{"prod", "backbone"}, Source: SourceStatic,
				Sources: &Sources{Name: SourceStatic, Role: SourceStatic, Site: SourcePattern, Tags: map[string]string{"prod": SourceStatic, "backbone": SourcePattern}},
			},
		},
		{
			// An untagged listed lab device gets the lab tag.
			"lab-sw-09",
			Target{
				Name: "lab-sw-09", Site: "lab", Tags: []string{"lab"}, Source: SourceStatic,
				Sources: &Sources{Name: SourceStatic, Site: SourcePattern, Tags: map[string]string{"lab": SourcePattern}},
			},
		},
		{
			// Two patterns match: the first in file order to set role
			// wins it (^lab- sets none, so -core- does); tags union with
			// no duplicates; a tag the device already has stays static.
			"lab-core-01",
			Target{
				Name: "lab-core-01", Role: "spine", Site: "lab", Tags: []string{"lab", "canary", "backbone"}, Source: SourceStatic,
				Sources: &Sources{Name: SourceStatic, Role: SourcePattern, Site: SourcePattern, Tags: map[string]string{"lab": SourceStatic, "canary": SourceStatic, "backbone": SourcePattern}},
			},
		},
	}
	for _, tc := range cases {
		got, ok := c.Resolve(tc.name)
		if !ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got  %+v %+v (known %v)\n want %+v %+v", tc.name, got, got.Sources, ok, tc.want, tc.want.Sources)
		}
	}
	// First pattern wins role when both set it.
	c2 := mustChain(t, &File{
		Devices: []Target{{Name: "border-x-01"}},
		Roles:   []Pattern{{Match: "^border-", Role: "border"}, {Match: "-x-", Role: "core", Tags: []string{"x"}}},
	})
	if got, _ := c2.Resolve("border-x-01"); got.Role != "border" || !slices.Equal(got.Tags, []string{"x"}) {
		t.Errorf("first pattern should win role: %+v", got)
	}
	// Enrichment runs on the listed name, and does not change the stored
	// record: resolving twice gives the same answer, and a caller that edits
	// the returned tags does not change the next answer.
	a, _ := c.Resolve("core-acc-01")
	a.Tags[0] = "mutated"
	a.Sources.Tags["prod"] = "mutated"
	b, _ := c.Resolve("core-acc-01")
	if !slices.Equal(b.Tags, []string{"prod", "backbone"}) || b.Sources.Tags["prod"] != SourceStatic {
		t.Errorf("stored record changed through a returned value: %+v %+v", b, b.Sources)
	}
}

// TestChainMergesAuthorities: inventory-schema section 2 across name
// authorities (the M2 chain). The first authority to list the name wins
// every field it sets and names the Source; a later one fills empty fields
// and adds tags; patterns run last; Stale is kept; no provider can report
// itself as pattern, and an enricher never sets status.
func TestChainMergesAuthorities(t *testing.T) {
	t.Parallel()
	first := Func(func(n string) (Target, bool) {
		return Target{Name: "sw-1", Role: "access", Tags: []string{"a"}, Source: "upstream:eos"}, n == "sw-1"
	})
	second := Func(func(n string) (Target, bool) {
		return Target{Name: "sw-1", Role: "core", Site: "dfw1", Status: "active", Tags: []string{"a", "b"}, Source: SourceSnapshot, Stale: true}, n == "sw-1"
	})
	liar := Func(func(n string) (Target, bool) {
		return Target{Name: n, Role: "liar", Source: SourcePattern}, n == "liar-1"
	})
	statusEnricher := enricherFunc(func(string) (Target, bool) {
		return Target{Status: "planned", Tags: []string{"c"}}, true
	})
	c := Chain{Authorities: []Resolver{liar, first, second}, Enrichers: []Enricher{statusEnricher}}
	got, ok := c.Resolve("sw-1")
	want := Target{
		Name: "sw-1", Role: "access", Site: "dfw1", Status: "active", Tags: []string{"a", "b", "c"}, Source: "upstream:eos", Stale: true,
		Sources: &Sources{Name: "upstream:eos", Role: "upstream:eos", Site: SourceSnapshot, Status: SourceSnapshot, Tags: map[string]string{"a": "upstream:eos", "b": SourceSnapshot, "c": SourcePattern}},
	}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v %+v\nwant %+v %+v", got, got.Sources, want, want.Sources)
	}
	got, ok = c.Resolve("liar-1")
	if !ok || got.Source == SourcePattern || got.Sources.Name == SourcePattern || got.Status == "planned" {
		t.Fatalf("an authority claimed pattern or an enricher set status: %+v %+v", got, got.Sources)
	}
	if got.Source != "resolver[0]" || got.Status != "" {
		t.Fatalf("liar: %+v", got)
	}
}

type enricherFunc func(string) (Target, bool)

func (f enricherFunc) Attributes(n string) (Target, bool) { return f(n) }

// TestStatusNeverPattern: ADR 0031 test 4 (the library half; the CLI half
// is in cmd/fathomgate). Status is device status, and Source never says
// pattern, for any name.
func TestStatusNeverPattern(t *testing.T) {
	t.Parallel()
	f, err := LoadFile("../../inventory.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f.Roles = append(f.Roles, attackerPatterns...)
	f.Devices = append(f.Devices, Target{Name: "lab-sw-09"}, Target{Name: "core-rtr-09"})
	c := mustChain(t, f)
	names := append(slices.Clone(attackerNames), "lab-sw-09", "core-rtr-09", "core-rtr-01", "lab-leaf-01")
	for _, n := range names {
		got, ok := c.Resolve(n)
		if got.Status == SourcePattern || got.Source == SourcePattern {
			t.Errorf("%s: status %q source %q", n, got.Status, got.Source)
		}
		if ok && (got.Sources == nil || got.Sources.Name != SourceStatic) {
			t.Errorf("%s: no per-field provenance: %+v", n, got.Sources)
		}
	}
	if got, _ := c.Resolve("lab-sw-09"); got.Status != "" || !slices.Contains(got.Tags, "lab") || got.Sources.Tags["lab"] != SourcePattern {
		t.Errorf("lab-sw-09: %+v %+v", got, got.Sources)
	}
}

// TestDeviceFileRefusesProvenance: source, sources and stale are set by the
// chain, never read from inventory.yaml. A file that tries is refused, so an
// operator cannot write a record that claims to be a snapshot or a pattern.
func TestDeviceFileRefusesProvenance(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"source: pattern", "stale: true", "sources: {role: static}"} {
		if _, err := ParseFile([]byte("devices:\n  - name: a\n    " + key + "\n")); err == nil {
			t.Errorf("%s: loaded", key)
		}
	}
}

// FuzzPatternsNeverResolveUnlisted: ADR 0031 test 6. For any name not in the
// static list, Resolve returns known false, whatever patterns are loaded; a
// listed name always resolves to its own record's name.
func FuzzPatternsNeverResolveUnlisted(f *testing.F) {
	for _, n := range attackerNames {
		f.Add(n, "^lab-", "^core-|^border-")
	}
	f.Add("core-rtr-01", ".*", "")
	f.Add("CORE-RTR-01", "(?i)core", "^$")
	f.Add("", ".", "^")
	f.Add("lab-sw-01 ", "lab", "sw")
	f.Add("lab-sw-01\x00", "\\x00", "^lab-sw-01$")
	listed := []Target{
		{Name: "core-rtr-01", Role: "core"},
		{Name: "lab-sw-01", Tags: []string{"lab"}},
		{Name: "acc-sw-01"},
	}
	f.Fuzz(func(t *testing.T, name, m1, m2 string) {
		var roles []Pattern
		for _, m := range []string{m1, m2, ".*", "^" + strings.ReplaceAll(name, "\\", "\\\\")} {
			if m == "" {
				continue
			}
			if _, err := compilePattern(m); err != nil {
				continue
			}
			roles = append(roles, Pattern{Match: m, Role: "fuzz", Tags: []string{"lab"}})
		}
		c, err := (&File{Devices: listed, Roles: roles}).Chain()
		if err != nil {
			t.Skip(err)
		}
		got, ok := c.Resolve(name)
		isListed := slices.ContainsFunc(listed, func(d Target) bool { return normalize(d.Name) == normalize(name) })
		if ok != isListed {
			t.Fatalf("Resolve(%q) known %v, listed %v (patterns %q): %+v", name, ok, isListed, []string{m1, m2}, got)
		}
		if !ok && !reflect.DeepEqual(got, Target{}) {
			t.Fatalf("Resolve(%q) unknown but carries %+v", name, got)
		}
		if ok && !slices.ContainsFunc(listed, func(d Target) bool { return d.Name == got.Name }) {
			t.Fatalf("Resolve(%q) returned name %q, not a listed one", name, got.Name)
		}
		if got.Source == SourcePattern || got.Status == SourcePattern {
			t.Fatalf("Resolve(%q) source %q status %q", name, got.Source, got.Status)
		}
	})
}
