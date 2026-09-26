// SPDX-License-Identifier: FSL-1.1-ALv2

package inventory

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"slices"

	"github.com/fathomgate/fathomgate/internal/termsafe"
)

// Pattern assigns a role, site or tags to every listed device whose name
// matches a regex. It lives under `roles:` in inventory.yaml.
type Pattern struct {
	// Match is a Go regular expression tested case-insensitively against
	// the listed device's name, for example "^core-|^border-".
	Match string   `yaml:"match" json:"match"`
	Role  string   `yaml:"role,omitempty" json:"role,omitempty"`
	Site  string   `yaml:"site,omitempty" json:"site,omitempty"`
	Tags  []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// Patterns is the hostname-pattern enricher. It is deliberately not a
// Resolver: a pattern never makes a name known (ADR 0031). For a device a
// name authority has listed, every matching pattern contributes: the first
// pattern in file order to set role (or site) wins that field, and tags
// accumulate. Chain.Resolve then lets the authority's own record win every
// field it sets.
type Patterns struct {
	compiled []compiledPattern
}

type compiledPattern struct {
	re *regexp.Regexp
	p  Pattern
}

// NewPatterns compiles the patterns.
func NewPatterns(ps []Pattern) (*Patterns, error) {
	out := &Patterns{}
	for i, p := range ps {
		if p.Match == "" {
			return nil, fmt.Errorf("inventory: roles[%d]: match is required", i)
		}
		if p.Role == "" && p.Site == "" && len(p.Tags) == 0 {
			return nil, fmt.Errorf("inventory: roles[%d] %q: sets no role, site or tags", i, p.Match)
		}
		re, err := compilePattern(p.Match)
		if err != nil {
			// The regexp error repeats the expression raw, line breaks and
			// all; name it quoted and keep only the error's fixed code
			// (security re-review of PR #199, R1).
			code := "invalid syntax"
			var se *syntax.Error
			if errors.As(err, &se) {
				code = string(se.Code)
			}
			return nil, fmt.Errorf("inventory: roles[%d] %s: not a valid regular expression (%s)", i, termsafe.Quote(p.Match), code)
		}
		out.compiled = append(out.compiled, compiledPattern{re: re, p: p})
	}
	return out, nil
}

// compilePattern compiles a roles: match the one way Attributes, Matching
// and PatternWarnings test it: case-insensitively.
func compilePattern(match string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + match)
}

// Attributes implements Enricher. listed is a name a name authority listed,
// as it stores it. The result carries the combined role, site and tags of
// every pattern that matches it, and never a status. ok is false when no
// pattern matches.
func (ps *Patterns) Attributes(listed string) (Target, bool) {
	if ps == nil {
		return Target{}, false
	}
	var t Target
	hit := false
	for _, c := range ps.compiled {
		if !c.re.MatchString(listed) {
			continue
		}
		hit = true
		if t.Role == "" {
			t.Role = c.p.Role
		}
		if t.Site == "" {
			t.Site = c.p.Site
		}
		for _, tag := range c.p.Tags {
			if !slices.Contains(t.Tags, tag) {
				t.Tags = append(t.Tags, tag)
			}
		}
	}
	if !hit {
		return Target{}, false
	}
	t.Name = listed
	return t, true
}

// Matching returns the index under roles: of every pattern that matches
// name, in file order. It explains a lookup (fathomgate inventory resolve)
// and decides nothing.
func (ps *Patterns) Matching(name string) []int {
	if ps == nil {
		return nil
	}
	var out []int
	for i, c := range ps.compiled {
		if c.re.MatchString(name) {
			out = append(out, i)
		}
	}
	return out
}

// Len returns the number of patterns.
func (ps *Patterns) Len() int { return len(ps.compiled) }
