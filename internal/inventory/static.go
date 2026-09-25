// SPDX-License-Identifier: FSL-1.1-ALv2

package inventory

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/fathomgate/fathomgate/internal/yamlstrict"
)

// File is the schema of inventory.yaml. It carries both the static device
// list and optional hostname patterns so one file can seed the whole chain.
type File struct {
	Devices []Target  `yaml:"devices,omitempty"`
	Roles   []Pattern `yaml:"roles,omitempty"`
}

// StaticFile resolves names from an in-memory device list.
type StaticFile struct {
	byName map[string]Target
}

// NewStatic builds a StaticFile from targets. Duplicate names (case-
// insensitive) are an error because two conflicting roles for one device
// would make the policy outcome depend on file order.
func NewStatic(targets []Target) (*StaticFile, error) {
	s := &StaticFile{byName: make(map[string]Target, len(targets))}
	for _, t := range targets {
		key := normalize(t.Name)
		if key == "" {
			return nil, fmt.Errorf("inventory: device without name")
		}
		if _, dup := s.byName[key]; dup {
			return nil, fmt.Errorf("inventory: duplicate device %q", t.Name)
		}
		// Status is device status. "pattern" was the pre-ADR 0031 marker
		// for a pattern-only hit; a record that claims it is refused so no
		// reader can mistake a listed device for one (review of PR #184, N3).
		if normalize(t.Status) == SourcePattern {
			return nil, fmt.Errorf("inventory: device %q: status pattern is not a device status", t.Name)
		}
		s.byName[key] = t
	}
	return s, nil
}

// Resolve implements Resolver. The static file is a name authority: a hit
// makes the name known, with Source static. The record's Tags are cloned so
// a caller cannot change the stored device.
func (s *StaticFile) Resolve(name string) (Target, bool) {
	if s == nil {
		return Target{}, false
	}
	t, ok := s.byName[normalize(name)]
	if !ok {
		return Target{}, false
	}
	t.Tags = slices.Clone(t.Tags)
	t.Source, t.Stale, t.Sources = SourceStatic, false, nil
	return t, true
}

// Len returns the number of devices.
func (s *StaticFile) Len() int { return len(s.byName) }

// Targets returns every device sorted by name.
func (s *StaticFile) Targets() []Target {
	out := make([]Target, 0, len(s.byName))
	for _, t := range s.byName {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return normalize(out[i].Name) < normalize(out[j].Name) })
	return out
}

// ParseFile decodes inventory.yaml.
func ParseFile(b []byte) (*File, error) {
	var f File
	if err := yamlstrict.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("inventory: parse: %w", err)
	}
	return &f, nil
}

// LoadFile reads and decodes inventory.yaml.
func LoadFile(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("inventory: read: %w", err)
	}
	f, err := ParseFile(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// LoadChain reads inventory.yaml and returns its Chain: the static devices as
// the name authority, the hostname patterns as the enricher.
func LoadChain(path string) (Chain, error) {
	f, err := LoadFile(path)
	if err != nil {
		return Chain{}, err
	}
	return f.Chain()
}

// Chain builds the resolver chain for a decoded file. The static device list
// is the only name authority; the hostname patterns only enrich a device it
// lists (ADR 0031).
func (f *File) Chain() (Chain, error) {
	static, err := NewStatic(f.Devices)
	if err != nil {
		return Chain{}, err
	}
	patterns, err := NewPatterns(f.Roles)
	if err != nil {
		return Chain{}, err
	}
	return Chain{Authorities: []Resolver{static}, Enrichers: []Enricher{patterns}}, nil
}

// PatternWarnings returns one line for each hostname pattern under roles:
// that matches no device listed under devices:, in file order (ADR 0031
// decision 5; the wording, with what to do, is design review's, PR #171):
// `inventory: roles[<i>] "<match>" matches no listed device and makes
// nothing known (ADR 0031); list the device under devices`. Such a pattern
// enriches nothing and resolves nothing (a pattern never makes a target
// known on its own), so an operator who wrote it probably expected
// something it does not do. It is a warning when `fathomgate serve` loads
// the file, so a stale pattern never stops the proxy, and an error in
// `fathomgate inventory lint`. A pattern that does not compile is skipped
// here; Chain reports it.
func (f *File) PatternWarnings() []string {
	var out []string
	for i, p := range f.Roles {
		if p.Match == "" {
			continue
		}
		re, err := compilePattern(p.Match)
		if err != nil {
			continue
		}
		hit := false
		for _, d := range f.Devices {
			if re.MatchString(d.Name) {
				hit = true
				break
			}
		}
		if !hit {
			out = append(out, fmt.Sprintf("inventory: roles[%d] %q matches no listed device and makes nothing known (ADR 0031); list the device under devices", i, p.Match))
		}
	}
	return out
}

// PatternEffects returns one line for each listed device and each pattern
// under roles: that changes it, in file order, saying what the pattern adds
// (security review of PR #184, L3). A role or tag a pattern gives counts for
// write rules (ADR 0031), so `fathomgate inventory lint` shows every one.
// Where the device's own record sets a role, a line says so, because a
// pattern that adds a tag such as lab to a device the operator listed as
// core is the misclassification to look for:
//
//	inventory: devices[3] "lab-core-01": roles[1] "^lab-" adds tag lab; the device's own record says role core
//
// A pattern whose role or site differs from the device's own is reported as
// not applied. Patterns that do not compile are skipped; Chain reports them.
func (f *File) PatternEffects() []string {
	type compiled struct {
		re *regexp.Regexp
		p  Pattern
	}
	var ps []compiled
	for _, p := range f.Roles {
		re, err := compilePattern(p.Match)
		if err != nil || p.Match == "" {
			ps = append(ps, compiled{})
			continue
		}
		ps = append(ps, compiled{re: re, p: p})
	}
	var out []string
	for j, d := range f.Devices {
		role, site, tags := d.Role, d.Site, slices.Clone(d.Tags)
		for i, c := range ps {
			if c.re == nil || !c.re.MatchString(d.Name) {
				continue
			}
			var effects []string
			conflict := false
			switch {
			case c.p.Role == "":
			case role == "":
				role = c.p.Role
				effects = append(effects, "sets role "+c.p.Role)
			case role != c.p.Role:
				effects = append(effects, "role "+c.p.Role+" not applied")
				conflict = conflict || d.Role != ""
			}
			switch {
			case c.p.Site == "":
			case site == "":
				site = c.p.Site
				effects = append(effects, "sets site "+c.p.Site)
			case site != c.p.Site:
				effects = append(effects, "site "+c.p.Site+" not applied")
			}
			for _, tag := range c.p.Tags {
				if slices.Contains(tags, tag) {
					continue
				}
				tags = append(tags, tag)
				effects = append(effects, "adds tag "+tag)
				conflict = conflict || d.Role != ""
			}
			if len(effects) == 0 {
				continue
			}
			line := fmt.Sprintf("inventory: devices[%d] %q: roles[%d] %q %s", j, d.Name, i, c.p.Match, strings.Join(effects, ", "))
			if conflict {
				line += "; the device's own record says role " + d.Role
			}
			out = append(out, line)
		}
	}
	return out
}

// WriteFile encodes targets as inventory.yaml to w.
func WriteFile(w io.Writer, f *File) error {
	b, err := yaml.MarshalWithOptions(f, yaml.IndentSequence(true))
	if err != nil {
		return fmt.Errorf("inventory: encode: %w", err)
	}
	header := "# Fathomgate static inventory. Generated by `fathomgate inventory import`; edit freely.\n"
	if _, err := io.WriteString(w, header); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// SplitTags parses a tag list given as "a,b c" or "a;b".
func SplitTags(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '|' })
	out := make([]string, 0, len(f))
	for _, t := range f {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}
