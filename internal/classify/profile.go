// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fathomgate/fathomgate/internal/termsafe"
	"github.com/fathomgate/fathomgate/internal/yamlstrict"
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
	// Capabilities holds the capability tables of the server's meta-tools,
	// by table name. A table maps a capability id, exactly as the upstream
	// receives it, to the class of a call that selects it (ADR 0010,
	// profile-schema section 3). A tool reads one table through its
	// capability_param and capability_table fields.
	Capabilities map[string]map[string]Class `yaml:"capabilities,omitempty"`
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
	// CapabilityParam names the argument that selects a meta-tool's
	// operation (Meraki execute_api capability_id). When it is set, the
	// class of a call comes from the capability table CapabilityTable names,
	// looked up with the argument's value byte for byte; a value the table
	// does not list, or a missing one, leaves the call at Class, which must
	// be EXEC_ARBITRARY. The argument is named: it counts in the closed
	// argument list like the *_params arguments.
	CapabilityParam string `yaml:"capability_param,omitempty"`
	// CapabilityTable names the table in the profile's top-level
	// capabilities that CapabilityParam is looked up in. Set both or
	// neither.
	CapabilityTable string `yaml:"capability_table,omitempty"`
	// Notes is free text for humans: server-side safety, caveats.
	Notes string `yaml:"notes,omitempty"`
}

// ParseProfile decodes a profile from YAML and validates it.
func ParseProfile(b []byte) (*Profile, error) {
	var p Profile
	if err := yamlstrict.Unmarshal(b, &p); err != nil {
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
		return fmt.Errorf("classify: profile %s: tools is empty", termsafe.Quote(p.Server))
	}
	used := map[string]bool{}
	for _, name := range p.ToolNames() {
		spec := p.Tools[name]
		if !spec.Class.Valid() {
			return fmt.Errorf("classify: profile %s: tool %s: invalid class %q", termsafe.Quote(p.Server), termsafe.Quote(name), spec.Class)
		}
		if err := spec.validateArgs(); err != nil {
			return fmt.Errorf("classify: profile %s: tool %s: %w", termsafe.Quote(p.Server), termsafe.Quote(name), err)
		}
		if err := spec.validateCapability(p.Capabilities); err != nil {
			return fmt.Errorf("classify: profile %s: tool %s: %w", termsafe.Quote(p.Server), termsafe.Quote(name), err)
		}
		if spec.CapabilityTable != "" {
			used[spec.CapabilityTable] = true
		}
	}
	for _, name := range sortedKeys(p.Capabilities) {
		if err := validateTable(name, p.Capabilities[name]); err != nil {
			return fmt.Errorf("classify: profile %s: capabilities: %w", termsafe.Quote(p.Server), err)
		}
		if !used[name] {
			return fmt.Errorf("classify: profile %s: capabilities: table %q is not the capability_table of any tool", termsafe.Quote(p.Server), name)
		}
	}
	return nil
}

// validateCapability checks a meta-tool's capability fields: both set or
// neither, the table exists, the tool's class is EXEC_ARBITRARY (the class
// of a call whose capability the table does not list), and the tool has no
// command or config arguments, so its class comes from the table alone.
func (s ToolSpec) validateCapability(tables map[string]map[string]Class) error {
	if s.CapabilityParam == "" && s.CapabilityTable == "" {
		return nil
	}
	if s.CapabilityParam == "" || s.CapabilityTable == "" {
		return fmt.Errorf("capability_param and capability_table go together: set both or neither")
	}
	if _, ok := tables[s.CapabilityTable]; !ok {
		return fmt.Errorf("capability_table %q is not a table in capabilities", s.CapabilityTable)
	}
	if s.Class != ExecArbitrary {
		return fmt.Errorf("a tool with capability_param must have class EXEC_ARBITRARY, the class of a call whose capability is not in the table (has %s)", s.Class)
	}
	if len(s.CommandParams) > 0 || len(s.ConfigParams) > 0 {
		return fmt.Errorf("a tool with capability_param takes its class from the capability table alone, so it cannot have command_params or config_params")
	}
	return nil
}

// validateTable checks one capability table: a name with no surrounding
// space, at least one entry, every class known, and every capability id a
// validCapabilityID. Two ids that differ only in letter case are refused:
// the upstream looks ids up byte for byte, so they would be two operations,
// and a reader of the profile could take one for the other.
func validateTable(name string, table map[string]Class) error {
	if strings.TrimSpace(name) == "" || name != strings.TrimSpace(name) {
		return fmt.Errorf("table name %q is empty or has surrounding space", name)
	}
	if len(table) == 0 {
		return fmt.Errorf("table %q is empty", name)
	}
	folded := make(map[string]string, len(table))
	for _, id := range sortedKeys(table) {
		if !validCapabilityID(id) {
			return fmt.Errorf("table %q: capability id %q must be 1 to %d printable ASCII bytes with no space, and must not read as JSON", name, id, maxCapabilityID)
		}
		if !table[id].Valid() {
			return fmt.Errorf("table %q: capability %s: invalid class %q", name, id, table[id])
		}
		key := strings.ToLower(id)
		if prev, dup := folded[key]; dup {
			return fmt.Errorf("table %q: capability ids %q and %q differ only in letter case", name, prev, id)
		}
		folded[key] = id
	}
	return nil
}

// maxCapabilityID bounds a capability id in a table. The longest Meraki
// operationId in the pinned spec is 83 bytes.
const maxCapabilityID = 128

// validCapabilityID reports whether a table key is a capability id the
// lookup can match: 1 to maxCapabilityID bytes, each printable ASCII other
// than space (0x21 to 0x7e), and nothing the upstream could parse as JSON
// instead of taking as a string (upstreamMayParseJSON). The lookup is byte
// for byte with no folding, so an agent-sent id with a space, a control
// character, another letter case or any non-ASCII character (a look-alike,
// a zero-width space, a fullwidth form) never matches a key, and the call
// stays EXEC_ARBITRARY.
func validCapabilityID(id string) bool {
	if id == "" || len(id) > maxCapabilityID {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x21 || id[i] > 0x7e {
			return false
		}
	}
	return !upstreamMayParseJSON(id, false)
}

// sortedKeys returns a map's keys sorted, so validation reports the same
// error whatever the map order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
		{"capability_param", s.capabilityParams()},
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
// of the *_params lists, as its capability_param or in args. The match is
// exact and case-sensitive: the upstream receives the key byte for byte.
func (s ToolSpec) Named(arg string) bool {
	for _, n := range s.NamedArgs() {
		if n == arg {
			return true
		}
	}
	return false
}

// NamedArgs returns the tool's named set (ADR 0033): target_params,
// targets_params, group_params, command_params, config_params,
// capability_param and args, in that order, unsorted.
func (s ToolSpec) NamedArgs() []string {
	lists := [][]string{s.TargetParams, s.TargetsParams, s.GroupParams, s.CommandParams, s.ConfigParams, s.capabilityParams(), s.Args}
	n := 0
	for _, l := range lists {
		n += len(l)
	}
	out := make([]string, 0, n)
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// capabilityParams is CapabilityParam as a list, empty when it is unset.
func (s ToolSpec) capabilityParams() []string {
	if s.CapabilityParam == "" {
		return nil
	}
	return []string{s.CapabilityParam}
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
