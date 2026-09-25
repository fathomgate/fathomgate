// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

// Profile describes one upstream MCP server: which class each tool belongs
// to and which argument names carry targets, commands and config payloads.
// Profiles are data (profiles/<server>.yaml) so contributors can add a server
// without touching Go.
type Profile struct {
	// Server is the short name used as the tool prefix and in policy
	// match.servers, for example "netdev-ssh-mcp".
	Server string `yaml:"server"`
	// Source is the upstream repository URL, for humans.
	Source string `yaml:"source,omitempty"`
	// Description is a one-line summary of the server.
	Description string `yaml:"description,omitempty"`
	// Tools maps tool name to its specification.
	Tools map[string]ToolSpec `yaml:"tools"`
}

// ToolSpec is the classification and parameter mapping for a single tool.
type ToolSpec struct {
	// Class is the class assigned before any argument inspection.
	Class Class `yaml:"class"`
	// TargetParams are argument names holding a single target
	// (host, hostname, name, device, router_name, target, firewall).
	TargetParams []string `yaml:"target_params,omitempty"`
	// TargetsParams are argument names holding a list of targets, as an
	// array or a comma-separated string (devices, hostnames, router_names).
	TargetsParams []string `yaml:"targets_params,omitempty"`
	// GroupParams are argument names holding group or tag selectors. Each
	// value is emitted as an "@name" token for the inventory to expand.
	GroupParams []string `yaml:"group_params,omitempty"`
	// CommandParams are argument names holding operational commands, as a
	// string or an array (command, commands).
	CommandParams []string `yaml:"command_params,omitempty"`
	// ConfigParams are argument names holding configuration payloads
	// (config_commands, config_lines, config_text, template_content).
	ConfigParams []string `yaml:"config_params,omitempty"`
	// Args names every other argument the tool accepts (ADR 0033). The
	// argument list is closed: an argument that is not in Args and not in
	// one of the five *_params lists above is refused (default:bad_arguments
	// at the gate). Required on every tool; `args: []` when the tool takes
	// no other argument. Values of these arguments are not inspected.
	Args []string `yaml:"args"`
	// RefusedArgs records arguments the upstream accepts that the profile
	// deliberately leaves unnamed (eos-mcp config_path). It changes nothing
	// at run time, since an unnamed argument is refused anyway; it lets the
	// coverage test tell a reviewed refusal from a parameter the upstream
	// added after the profile was written.
	RefusedArgs []string `yaml:"refused_args,omitempty"`
	// Notes is free text for humans: server-side safety, caveats.
	Notes string `yaml:"notes,omitempty"`
}

// ParseProfile decodes a profile from YAML and validates it.
func ParseProfile(b []byte) (*Profile, error) {
	var p Profile
	if err := yaml.UnmarshalWithOptions(b, &p, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("classify: parse profile: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadProfile reads and parses a profile file.
func LoadProfile(path string) (*Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("classify: read profile: %w", err)
	}
	p, err := ParseProfile(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// LoadProfileDir loads every *.yaml file in dir, keyed by Profile.Server.
func LoadProfileDir(dir string) (map[string]*Profile, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	out := make(map[string]*Profile, len(matches))
	for _, m := range matches {
		p, err := LoadProfile(m)
		if err != nil {
			return nil, err
		}
		if _, dup := out[p.Server]; dup {
			return nil, fmt.Errorf("classify: duplicate profile for server %q", p.Server)
		}
		out[p.Server] = p
	}
	return out, nil
}

// Validate checks that the profile names a server, that every tool has a
// known class, and that every tool names its arguments: `args` is present,
// no argument name is empty or appears twice across the *_params lists and
// `args`, and no refused argument is also named.
func (p *Profile) Validate() error {
	if strings.TrimSpace(p.Server) == "" {
		return fmt.Errorf("classify: profile: server is required")
	}
	if len(p.Tools) == 0 {
		return fmt.Errorf("classify: profile %s: tools is empty", p.Server)
	}
	for name, spec := range p.Tools {
		if !spec.Class.Valid() {
			return fmt.Errorf("classify: profile %s: tool %s: invalid class %q", p.Server, name, spec.Class)
		}
		if err := spec.validateArgs(); err != nil {
			return fmt.Errorf("classify: profile %s: tool %s: %w", p.Server, name, err)
		}
	}
	return nil
}

// validateArgs checks the closed argument list of one tool (ADR 0033).
func (s ToolSpec) validateArgs() error {
	if s.Args == nil {
		return fmt.Errorf("args is required: name every argument the tool accepts besides the *_params ones (args: [] for none)")
	}
	seen := map[string]string{}
	lists := []struct {
		field string
		names []string
	}{
		{"target_params", s.TargetParams},
		{"targets_params", s.TargetsParams},
		{"group_params", s.GroupParams},
		{"command_params", s.CommandParams},
		{"config_params", s.ConfigParams},
		{"args", s.Args},
	}
	for _, l := range lists {
		for _, n := range l.names {
			if strings.TrimSpace(n) == "" || n != strings.TrimSpace(n) {
				return fmt.Errorf("%s: argument name %q is empty or has surrounding space", l.field, n)
			}
			if prev, dup := seen[n]; dup {
				return fmt.Errorf("argument %q named twice (%s and %s)", n, prev, l.field)
			}
			seen[n] = l.field
		}
	}
	refused := map[string]bool{}
	for _, n := range s.RefusedArgs {
		if strings.TrimSpace(n) == "" || n != strings.TrimSpace(n) {
			return fmt.Errorf("refused_args: argument name %q is empty or has surrounding space", n)
		}
		if field, named := seen[n]; named {
			return fmt.Errorf("argument %q is both named (%s) and in refused_args", n, field)
		}
		if refused[n] {
			return fmt.Errorf("refused_args: argument %q listed twice", n)
		}
		refused[n] = true
	}
	return nil
}

// Named reports whether the tool's profile entry names the argument, in one
// of the *_params lists or in args. The match is exact and case-sensitive:
// the upstream receives the key byte for byte.
func (s ToolSpec) Named(arg string) bool {
	for _, l := range [][]string{s.TargetParams, s.TargetsParams, s.GroupParams, s.CommandParams, s.ConfigParams, s.Args} {
		for _, n := range l {
			if n == arg {
				return true
			}
		}
	}
	return false
}

// Lookup returns the spec for a tool. The tool may be given bare or prefixed
// with the server name and a dot ("netdev-ssh-mcp.get_config").
func (p *Profile) Lookup(tool string) (ToolSpec, bool) {
	if spec, ok := p.Tools[tool]; ok {
		return spec, true
	}
	prefix := p.Server + "."
	if strings.HasPrefix(tool, prefix) {
		spec, ok := p.Tools[strings.TrimPrefix(tool, prefix)]
		return spec, ok
	}
	return ToolSpec{}, false
}

// ToolNames returns the profile's tool names sorted.
func (p *Profile) ToolNames() []string {
	names := make([]string, 0, len(p.Tools))
	for n := range p.Tools {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
