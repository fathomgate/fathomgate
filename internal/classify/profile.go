// SPDX-License-Identifier: Apache-2.0

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

// Validate checks that the profile names a server and that every tool has a
// known class.
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
	}
	return nil
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
