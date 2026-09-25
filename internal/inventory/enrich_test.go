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
// authorities (the M2 chain; security review of PR #184, L1). The first
// authority to list the name supplies its name, tags and every field it
// sets, and names the Source. A later authority that lists the same device
// only fills an empty role, site or status and never adds tags (from M2 it
// may be an upstream's listing, untrusted data). A record for another name
// is ignored. Patterns run last; Stale is kept; no authority can report
// itself as pattern, and an enricher never sets status.
func TestChainMergesAuthorities(t *testing.T) {
	t.Parallel()
	first := Func(func(n string) (Target, bool) {
		return Target{Name: "sw-1", Role: "access", Tags: []string{"a"}, Source: "upstream:eos"}, n == "sw-1"
	})
	second := Func(func(n string) (Target, bool) {
		return Target{Name: "SW-1", Role: "core", Site: "dfw1", Status: "active", Tags: []string{"a", "b", "lab"}, Source: SourceSnapshot, Stale: true}, n == "sw-1"
	})
	// otherName answers every lookup with a record for a different
	// device; it must never contribute.
	otherName := Func(func(string) (Target, bool) {
		return Target{Name: "core-rtr-01", Role: "core", Site: "x", Status: "offline", Tags: []string{"lab"}, Source: "upstream:evil", Stale: true}, true
	})
	liar := Func(func(n string) (Target, bool) {
		return Target{Name: n, Role: "liar", Source: SourcePattern}, n == "liar-1"
	})
	statusEnricher := enricherFunc(func(string) (Target, bool) {
		return Target{Status: "planned", Tags: []string{"c"}}, true
	})
	c := Chain{Authorities: []Resolver{otherName, liar, first, otherName, second}, Enrichers: []Enricher{statusEnricher}}
	got, ok := c.Resolve("sw-1")
	want := Target{
		// Role from first; site and status filled by second; second's
		// tags b and lab are not added; c comes from the enricher.
		Name: "sw-1", Role: "access", Site: "dfw1", Status: "active", Tags: []string{"a", "c"}, Source: "upstream:eos", Stale: true,
		Sources: &Sources{Name: "upstream:eos", Role: "upstream:eos", Site: SourceSnapshot, Status: SourceSnapshot, Tags: map[string]string{"a": "upstream:eos", "c": SourcePattern}},
	}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v %+v\nwant %+v %+v", got, got.Sources, want, want.Sources)
	}
	got, ok = c.Resolve("liar-1")
	if !ok || got.Source == SourcePattern || got.Sources.Name == SourcePattern || got.Status == "planned" {
		t.Fatalf("an authority claimed pattern or an enricher set status: %+v %+v", got, got.Sources)
	}
	if got.Source != "resolver[1]" || got.Status != "" || got.Role != "liar" {
		t.Fatalf("liar: %+v", got)
	}
	// A different-name record alone never makes the name known.
	for _, n := range []string{"ghost-99", "lab-ghost-99", "core-rtr-01.attacker.example"} {
		if got, ok := (Chain{Authorities: []Resolver{otherName}}).Resolve(n); ok {
			t.Errorf("%s: known through a record for another name: %+v", n, got)
		}
	}
	// A later authority fills only what is still empty.
	empty := Func(func(n string) (Target, bool) { return Target{Name: n}, n == "sw-2" })
	full := Func(func(n string) (Target, bool) {
		return Target{Name: n, Role: "leaf", Site: "lab", Status: "planned", Tags: []string{"lab"}}, n == "sw-2"
	})
	got, ok = (Chain{Authorities: []Resolver{empty, full}}).Resolve("sw-2")
	if !ok || got.Role != "leaf" || got.Site != "lab" || got.Status != "planned" || len(got.Tags) != 0 ||
		got.Sources.Role != "resolver[1]" || got.Sources.Name != "resolver[0]" {
		t.Fatalf("empty-field fill: %+v %+v", got, got.Sources)
	}
}

type enricherFunc func(string) (Target, bool)

func (f enricherFunc) Attributes(n string) (Target, bool) { return f(n) }

// TestKnown: the exact-name rule of inventory-schema section 7 (security
// review of PR #184, L2). The static file matches case-insensitively, and
// strings.ToLower folds the Kelvin sign to k, so Resolve finds kvm-01 for
// "Kvm-01"; Known does not. The reviewer's gate probes are kept here.
func TestKnown(t *testing.T) {
	t.Parallel()
	c := mustChain(t, &File{
		Devices: []Target{{Name: "kvm-01", Role: "core"}, {Name: "lab-sw-09"}, {Name: "core-rtr-01", Role: "core"}},
		Roles:   attackerPatterns,
	})
	if _, ok := c.Resolve("Kvm-01"); !ok {
		t.Fatal("precondition: the static file no longer folds the Kelvin sign; revisit this test")
	}
	for _, n := range []string{
		"Kvm-01",           // Kelvin sign K
		"KVM-01",           // case variant
		"lab-ѕw-09",        // Cyrillic dze
		"lab-sw-09​",       // zero-width space
		"​lab-sw-09",       // leading zero-width space
		"lab-sw-09.",       // trailing dot
		" lab-sw-09",       // leading space
		"lab-sw-09 ",       // trailing space
		"core-rtr-01\x1b[", // escape
		"lab-ghost-99",     // pattern only
		"",
	} {
		if got, ok := Known(c, n); ok || !reflect.DeepEqual(got, Target{}) {
			t.Errorf("Known(%q) = %+v, true; want unknown", n, got)
		}
	}
	for _, n := range []string{"kvm-01", "lab-sw-09", "core-rtr-01"} {
		if got, ok := Known(c, n); !ok || got.Name != n {
			t.Errorf("Known(%q) = %+v, %v", n, got, ok)
		}
	}
	if got, _ := Known(c, "lab-sw-09"); !slices.Contains(got.Tags, "lab") {
		t.Errorf("Known dropped the enrichment: %+v", got)
	}
	if _, ok := Known(nil, "kvm-01"); ok {
		t.Error("nil resolver knows a name")
	}
}

// TestStatusNeverPattern: ADR 0031 test 4 (the library half; the CLI half
// is in cmd/fathomgate). Status carries only the device status a name
// authority's record gives: the chain never writes pattern into it or into
// Source, and a file cannot set status: pattern (security review of PR #184,
// N3).
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
	for _, status := range []string{"pattern", "Pattern", " PATTERN "} {
		ff, err := ParseFile([]byte("devices:\n  - {name: a, status: \"" + status + "\"}\n"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ff.Chain(); err == nil || !strings.Contains(err.Error(), "status") {
			t.Errorf("status %q loaded: %v", status, err)
		}
	}
}

// TestPatternEffects: security review of PR #184, L3. One line per listed
// device and pattern that changes it, with the device's own role where a
// pattern adds a tag or a different role; and it agrees with Chain.Resolve.
func TestPatternEffects(t *testing.T) {
	t.Parallel()
	f := &File{
		Devices: []Target{
			{Name: "lab-core-01", Role: "core"},
			{Name: "core-rtr-09", Site: "dfw1"},
			{Name: "acc-sw-01", Role: "access", Tags: []string{"lab"}},
		},
		Roles: []Pattern{
			{Match: "^core-|^border-", Role: "core", Site: "lon1"},
			{Match: "^lab-", Tags: []string{"lab"}},
			{Match: "-core-", Role: "spine", Tags: []string{"backbone"}},
			{Match: "^acc-", Tags: []string{"lab"}}, // already tagged: no line
			{Match: "(", Role: "x"},                 // does not compile: skipped
		},
	}
	want := []string{
		`inventory: devices[0] "lab-core-01": roles[1] "^lab-" adds tag lab; the device's own record says role core`,
		`inventory: devices[0] "lab-core-01": roles[2] "-core-" role spine not applied, adds tag backbone; the device's own record says role core`,
		`inventory: devices[1] "core-rtr-09": roles[0] "^core-|^border-" sets role core, site lon1 not applied`,
	}
	if got := f.PatternEffects(); !slices.Equal(got, want) {
		t.Fatalf("PatternEffects()\n got  %q\n want %q", got, want)
	}
	f.Roles = f.Roles[:4]
	c := mustChain(t, f)
	if got, _ := c.Resolve("lab-core-01"); got.Role != "core" || !slices.Equal(got.Tags, []string{"lab", "backbone"}) {
		t.Errorf("chain disagrees with PatternEffects: %+v", got)
	}
	if got, _ := c.Resolve("core-rtr-09"); got.Role != "core" || got.Site != "dfw1" {
		t.Errorf("chain disagrees with PatternEffects: %+v", got)
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
// listed name always resolves to its own record's name. Known, the rule the
// gate applies, is true exactly when the name is listed byte for byte
// (security review of PR #184, L2).
func FuzzPatternsNeverResolveUnlisted(f *testing.F) {
	for _, n := range attackerNames {
		f.Add(n, "^lab-", "^core-|^border-")
	}
	f.Add("core-rtr-01", ".*", "")
	f.Add("CORE-RTR-01", "(?i)core", "^$")
	f.Add("", ".", "^")
	f.Add("lab-sw-01 ", "lab", "sw")
	f.Add("lab-sw-01\x00", "\\x00", "^lab-sw-01$")
	// The security review's gate probes (PR #184).
	f.Add("Kvm-01", "^k", "vm")
	f.Add("lab-ѕw-01", "^lab-", "")
	f.Add("lab-sw-01​", "^lab-", "")
	f.Add("lab-sw-01.", "^lab-", "")
	f.Add(" lab-sw-01", "lab", "")
	listed := []Target{
		{Name: "core-rtr-01", Role: "core"},
		{Name: "lab-sw-01", Tags: []string{"lab"}},
		{Name: "acc-sw-01"},
		{Name: "kvm-01", Role: "core"},
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
		exact := slices.ContainsFunc(listed, func(d Target) bool { return d.Name == name })
		kt, known := Known(c, name)
		if known != exact || (known && kt.Name != name) || (!known && !reflect.DeepEqual(kt, Target{})) {
			t.Fatalf("Known(%q) = %+v, %v; listed exactly %v", name, kt, known, exact)
		}
	})
}
