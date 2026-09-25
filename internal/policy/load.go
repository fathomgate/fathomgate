// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
)

// Parse decodes a policy from YAML and validates it. Unknown keys are
// errors so a misspelt matcher cannot silently match everything.
func Parse(b []byte) (*Policy, error) {
	var p Policy
	if err := yaml.UnmarshalWithOptions(b, &p, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	// An unset unknown_target is deny for every class (ADR 0032). Filling
	// it in here makes the loaded policy say what Evaluate enforces.
	if p.Defaults.UnknownTarget == "" {
		p.Defaults.UnknownTarget = Deny
	}
	return &p, nil
}

// Load reads and parses a policy file.
func Load(filePath string) (*Policy, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("policy: read: %w", err)
	}
	p, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filePath, err)
	}
	return p, nil
}

// Validate checks structural rules that the YAML decoder cannot: version,
// unique non-empty rule ids, valid effects and classes, known obligations,
// approval only on hold rules, and well-formed ranges and globs.
func (p *Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("policy: unsupported version %d (want 1)", p.Version)
	}
	if p.Defaults.UnknownTarget != "" && !p.Defaults.UnknownTarget.Valid() {
		return fmt.Errorf("policy: defaults.unknown_target: bad effect %q", p.Defaults.UnknownTarget)
	}
	if p.Defaults.UnknownTarget == Hold {
		return fmt.Errorf("policy: defaults.unknown_target: hold is not allowed; use allow or deny")
	}
	if p.Defaults.Session.MaxDevices < 0 || p.Defaults.Session.MaxPending < 0 {
		return fmt.Errorf("policy: defaults.session: limits must not be negative")
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("policy: rules is empty")
	}
	seen := make(map[string]bool, len(p.Rules))
	for i := range p.Rules {
		r := &p.Rules[i]
		if err := r.validate(); err != nil {
			return err
		}
		if seen[r.ID] {
			return fmt.Errorf("policy: duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
	}
	return nil
}

func (r *Rule) validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("policy: rule without id")
	}
	if strings.HasPrefix(r.ID, "default:") {
		return fmt.Errorf("policy: rule %q: the default: prefix is reserved", r.ID)
	}
	if !r.Effect.Valid() {
		return fmt.Errorf("policy: rule %q: bad effect %q", r.ID, r.Effect)
	}
	for _, c := range r.Match.Class {
		if !c.Valid() {
			return fmt.Errorf("policy: rule %q: bad class %q", r.ID, c)
		}
	}
	for _, g := range append(slices.Clone(r.Match.Tools), r.Match.Servers...) {
		if _, err := path.Match(g, ""); err != nil {
			return fmt.Errorf("policy: rule %q: bad glob %q: %w", r.ID, g, err)
		}
	}
	for _, o := range r.Obligations {
		if !slices.Contains(KnownObligations, o) {
			return fmt.Errorf("policy: rule %q: unknown obligation %q (known: %s)", r.ID, o, strings.Join(KnownObligations, ", "))
		}
	}
	if r.Approval != nil && r.Effect != Hold {
		return fmt.Errorf("policy: rule %q: approval is only valid with effect hold", r.ID)
	}
	if r.Approval != nil && r.Approval.TTL < 0 {
		return fmt.Errorf("policy: rule %q: approval.ttl must not be negative", r.ID)
	}
	if r.When != nil && r.When.TargetsCount != nil {
		tc := r.When.TargetsCount
		if tc.Empty() {
			return fmt.Errorf("policy: rule %q: when.targets_count has no bound", r.ID)
		}
		if tc.GT != nil && tc.LT != nil && *tc.GT >= *tc.LT {
			return fmt.Errorf("policy: rule %q: when.targets_count gt %d >= lt %d can never match", r.ID, *tc.GT, *tc.LT)
		}
	}
	return nil
}

// Rule returns the rule with the given id, or nil.
func (p *Policy) Rule(id string) *Rule {
	for i := range p.Rules {
		if p.Rules[i].ID == id {
			return &p.Rules[i]
		}
	}
	return nil
}
