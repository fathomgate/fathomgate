// SPDX-License-Identifier: Apache-2.0

package inventory

import "strings"

// Target is what the inventory knows about one device.
type Target struct {
	Name   string   `yaml:"name" json:"name"`
	Role   string   `yaml:"role,omitempty" json:"role,omitempty"`
	Site   string   `yaml:"site,omitempty" json:"site,omitempty"`
	Tags   []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Status string   `yaml:"status,omitempty" json:"status,omitempty"`
}

// Resolver maps a target name to a Target. The bool is false when the
// provider does not know the name.
type Resolver interface {
	Resolve(name string) (Target, bool)
}

// Chain tries each resolver in order and returns the first hit.
type Chain []Resolver

// Resolve implements Resolver.
func (c Chain) Resolve(name string) (Target, bool) {
	for _, r := range c {
		if r == nil {
			continue
		}
		if t, ok := r.Resolve(name); ok {
			return t, true
		}
	}
	return Target{}, false
}

// Func adapts a function to the Resolver interface.
type Func func(name string) (Target, bool)

// Resolve implements Resolver.
func (f Func) Resolve(name string) (Target, bool) { return f(name) }

// normalize lowercases and trims a hostname for comparison.
func normalize(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
