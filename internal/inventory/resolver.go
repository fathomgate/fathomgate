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
// it; ok is false when the enricher has nothing for it.
//
// Hostname patterns (*Patterns) are the only enricher (ADR 0031 decision 1),
// and Chain.Resolve records every field or tag any enricher supplies with the
// source "pattern". A second kind of enricher needs its own source label, and
// an ADR, before it is added.
type Enricher interface {
	Attributes(listed string) (attrs Target, ok bool)
}

// Chain is the resolver chain of inventory-schema section 2. Authorities
// decide whether a name is known; enrichers only add attributes to a name an
// authority listed.
type Chain struct {
	// Authorities are tried in order. The first to list the name supplies
	// its name, its role, its tags and every field it sets. A later
	// authority that lists the same device (same name, case-insensitively)
	// runs after the enrichers and only fills a site or status still empty:
	// it never sets role or adds tags, because from M2 the later
	// authorities include an upstream's own device list, which is untrusted
	// data (invariant 7), and a role (device_roles) or a tag (device_tags)
	// can unlock writes. A record whose name is not the name looked up is
	// ignored.
	Authorities []Resolver
	// Enrichers run after the first authority has hit and before any later
	// one, in order, and fill a role or site still empty and add their tags.
	// They never run for an unlisted name.
	Enrichers []Enricher
}

// Resolve implements Resolver. A name no authority lists is unknown,
// whatever an enricher would say about it. Resolve matches as its
// authorities do (case-insensitively for the static file); use Known for the
// exact-name rule the gate applies.
//
// Order: the first authority's record; then each enricher (role, site,
// tags); then each later authority (site and status only).
func (c Chain) Resolve(name string) (Target, bool) {
	type hit struct {
		t     Target
		label string
	}
	var hits []hit
	for i, r := range c.Authorities {
		if r == nil {
			continue
		}
		t, ok := r.Resolve(name)
		// A record for another device is not an answer for this name
		// (an authority that returns one is buggy or hostile).
		if !ok || normalize(t.Name) != normalize(name) {
			continue
		}
		label := t.Source
		if label == "" || label == SourcePattern {
			// An authority never reports itself as a pattern; name it
			// by position so provenance never claims one.
			label = "resolver[" + strconv.Itoa(i) + "]"
		}
		hits = append(hits, hit{t, label})
	}
	if len(hits) == 0 {
		return Target{}, false
	}
	var (
		out Target
		src Sources
	)
	first := hits[0]
	out.Name, out.Source, out.Stale = first.t.Name, first.label, first.t.Stale
	src.Name = first.label
	merge(&out, &src, first.t, first.label, fieldsAll)
	for _, e := range c.Enrichers {
		if e == nil {
			continue
		}
		if t, ok := e.Attributes(out.Name); ok {
			merge(&out, &src, t, SourcePattern, fieldsEnricher)
		}
	}
	for _, h := range hits[1:] {
		out.Stale = out.Stale || h.t.Stale
		merge(&out, &src, h.t, h.label, fieldsLaterAuthority)
	}
	out.Sources = &src
	return out, true
}

// Known resolves name through r and reports it known only when the record
// carries exactly the string looked up, case included: the rule internal/gate
// applies to every target, and policy eval and inventory resolve with it
// (inventory-schema section 7). A case variant or a record for another name
// is unknown and yields a zero Target.
func Known(r Resolver, name string) (Target, bool) {
	if r == nil {
		return Target{}, false
	}
	t, ok := r.Resolve(name)
	if !ok || t.Name != name {
		return Target{}, false
	}
	return t, true
}

// fields says which fields a provider may contribute in merge.
type fields struct{ role, site, status, tags bool }

var (
	// fieldsAll: the first name authority.
	fieldsAll = fields{role: true, site: true, status: true, tags: true}
	// fieldsEnricher: a hostname pattern never sets device status.
	fieldsEnricher = fields{role: true, site: true, tags: true}
	// fieldsLaterAuthority: never role or tags, which unlock writes
	// (security review of PR #184, L1 and R2-L1).
	fieldsLaterAuthority = fields{site: true, status: true}
)

// merge fills the fields of out that are still empty from t, for the fields
// f allows, recording label as their source; tags t has that out lacks are
// added when f allows tags.
func merge(out *Target, src *Sources, t Target, label string, f fields) {
	if f.role && out.Role == "" && t.Role != "" {
		out.Role, src.Role = t.Role, label
	}
	if f.site && out.Site == "" && t.Site != "" {
		out.Site, src.Site = t.Site, label
	}
	if f.status && out.Status == "" && t.Status != "" {
		out.Status, src.Status = t.Status, label
	}
	if !f.tags {
		return
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
