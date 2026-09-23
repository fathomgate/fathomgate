package inventory

import (
	"fmt"
	"regexp"
	"slices"
)

// Pattern assigns a role, site or tags to every hostname matching a regex.
// It lives under `roles:` in inventory.yaml or beside the policy.
type Pattern struct {
	// Match is a Go regular expression tested case-insensitively against
	// the hostname, for example "^core-|^border-".
	Match string   `yaml:"match" json:"match"`
	Role  string   `yaml:"role,omitempty" json:"role,omitempty"`
	Site  string   `yaml:"site,omitempty" json:"site,omitempty"`
	Tags  []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// Patterns resolves names by regex. Every matching pattern contributes: the
// first pattern to set role (or site) wins, tags accumulate. A name that
// matches nothing is unknown.
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
		re, err := regexp.Compile("(?i)" + p.Match)
		if err != nil {
			return nil, fmt.Errorf("inventory: roles[%d]: %w", i, err)
		}
		out.compiled = append(out.compiled, compiledPattern{re: re, p: p})
	}
	return out, nil
}

// Resolve implements Resolver.
func (ps *Patterns) Resolve(name string) (Target, bool) {
	if ps == nil {
		return Target{}, false
	}
	t := Target{Name: name}
	hit := false
	for _, c := range ps.compiled {
		if !c.re.MatchString(name) {
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
	t.Status = "pattern"
	return t, true
}

// Len returns the number of patterns.
func (ps *Patterns) Len() int { return len(ps.compiled) }
