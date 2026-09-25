// SPDX-License-Identifier: FSL-1.1-ALv2

package inventory

import (
	"slices"
	"strconv"
	"strings"
)

// Provider names for Target.Source and Sources (inventory-schema section 1).
const (
	SourceStatic   = "static"
	SourcePattern  = "pattern"
	SourceSnapshot = "snapshot"
)

// Target is what the inventory knows about one device.
//
// Source, Sources and Stale are set by the resolver chain, never read from
// a file: a device record in inventory.yaml that carries any of them is an
// unknown key and fails to load.
type Target struct {
	Name   string   `yaml:"name" json:"name"`
	Role   string   `yaml:"role,omitempty" json:"role,omitempty"`
	Site   string   `yaml:"site,omitempty" json:"site,omitempty"`
	Tags   []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Status string   `yaml:"status,omitempty" json:"status,omitempty"`

	// Source is the name authority that listed the name (static, and from
	// M2 upstream:<id>, netbox, nautobot or snapshot). It is never
	// "pattern": a hostname pattern never makes a name known (ADR 0031).
	Source string `yaml:"-" json:"source,omitempty"`
	// Stale is true when a record that contributed came from a snapshot
	// served because the live source of truth was unreachable.
	Stale bool `yaml:"-" json:"stale,omitempty"`
	// Sources says which provider supplied each field (ADR 0031 decision
	// 3). Chain.Resolve always sets it on a hit.
	Sources *Sources `yaml:"-" json:"sources,omitempty"`
}

// Sources is the per-field provenance of a resolved Target.
type Sources struct {
	Name   string `json:"name,omitempty"`
	Role   string `json:"role,omitempty"`
	Site   string `json:"site,omitempty"`
	Status string `json:"status,omitempty"`
	// Tags maps each tag to the first provider that added it.
	Tags map[string]string `json:"tags,omitempty"`
}

// Resolver is a name authority: it maps a target name to a Target, and the
// bool is false when the provider does not list the name. Only a name
// authority can make a name known.
type Resolver interface {
	Resolve(name string) (Target, bool)
}

// Enricher adds attributes to a device a name authority has listed. It never
// makes a name known on its own. listed is the name as the authority stores
// it; ok is false when the enricher has nothing for it. Hostname patterns
// are the only enricher (ADR 0031 decision 1).
type Enricher interface {
	Attributes(listed string) (attrs Target, ok bool)
}

// Chain is the resolver chain of inventory-schema section 2. Authorities
// decide whether a name is known; enrichers only add attributes to a name an
// authority listed.
type Chain struct {
	// Authorities are tried in order. The first to list the name supplies
	// every field it sets; a later authority that also lists it fills a
	// field still empty and adds its tags.
	Authorities []Resolver
	// Enrichers run after an authority has hit, in order, and fill a field
	// still empty and add their tags. They never run for an unlisted name.
	Enrichers []Enricher
}

// Resolve implements Resolver. A name no authority lists is unknown,
// whatever an enricher would say about it.
func (c Chain) Resolve(name string) (Target, bool) {
	var (
		out Target
		src Sources
		hit bool
	)
	for i, r := range c.Authorities {
		if r == nil {
			continue
		}
		t, ok := r.Resolve(name)
		if !ok {
			continue
		}
		label := t.Source
		if label == "" || label == SourcePattern {
			// An authority never reports itself as a pattern; name it
			// by position so provenance never claims one.
			label = "resolver[" + strconv.Itoa(i) + "]"
		}
		if !hit {
			hit = true
			out.Name, out.Source = t.Name, label
			src.Name = label
		}
		out.Stale = out.Stale || t.Stale
		merge(&out, &src, t, label)
	}
	if !hit {
		return Target{}, false
	}
	for _, e := range c.Enrichers {
		if e == nil {
			continue
		}
		if t, ok := e.Attributes(out.Name); ok {
			t.Status = "" // an enricher never sets device status
			merge(&out, &src, t, SourcePattern)
		}
	}
	out.Sources = &src
	return out, true
}

// merge fills the fields of out that are still empty from t and adds t's
// tags that out lacks, recording label as their source.
func merge(out *Target, src *Sources, t Target, label string) {
	if out.Role == "" && t.Role != "" {
		out.Role, src.Role = t.Role, label
	}
	if out.Site == "" && t.Site != "" {
		out.Site, src.Site = t.Site, label
	}
	if out.Status == "" && t.Status != "" {
		out.Status, src.Status = t.Status, label
	}
	for _, tag := range t.Tags {
		if slices.Contains(out.Tags, tag) {
			continue
		}
		out.Tags = append(out.Tags, tag)
		if src.Tags == nil {
			src.Tags = make(map[string]string)
		}
		src.Tags[tag] = label
	}
}

// Func adapts a function to the Resolver interface.
type Func func(name string) (Target, bool)

// Resolve implements Resolver.
func (f Func) Resolve(name string) (Target, bool) { return f(name) }

// normalize lowercases and trims a hostname for comparison.
func normalize(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
