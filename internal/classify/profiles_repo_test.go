// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// TestRepoProfiles loads every shipped profile and checks the tool names the
// research catalog (docs/research/02-network-mcp-servers.md) says each server
// exposes, so a profile cannot silently drift from the upstream survey.
func TestRepoProfiles(t *testing.T) {
	profiles, err := LoadProfileDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]Class{
		"netdev-ssh-mcp": {
			"get_config": ReadConfig, "run_show_command": ReadOperational,
			"run_ping": ReadOperational, "run_traceroute": ReadOperational, "trust_host_key": LocalAdmin,
		},
		"junos-mcp-server": {
			"execute_junos_command": ExecArbitrary, "execute_junos_pfe_command": ExecArbitrary,
			"execute_junos_command_batch": ExecArbitrary, "get_junos_config": ReadConfig,
			"junos_config_diff": ReadConfig, "gather_device_facts": ReadOperational,
			"get_router_list": InventoryRead, "load_and_commit_config": WriteConfig,
			"render_and_apply_j2_template": ExecArbitrary,
		},
		"ntunes-netmiko-mcp-server": {
			"send_command": ExecArbitrary, "send_command_parallel": ExecArbitrary,
			"send_commands_sequence": ExecArbitrary, "send_config": WriteConfig,
			"send_config_parallel": WriteConfig, "list_devices": InventoryRead,
			"get_device_info": InventoryRead, "list_groups": InventoryRead,
			"get_device_types": InventoryRead, "get_tags": InventoryRead,
			"get_pool_status": InventoryRead, "test_connection": ReadOperational,
		},
		"eos-mcp": {
			"health_check": LocalAdmin, "get_router_list": InventoryRead,
			"get_device_facts": ReadOperational, "get_version": ReadOperational,
			"get_device_facts_batch": ReadOperational, "run_command": ExecArbitrary,
			"run_commands": ExecArbitrary, "run_command_batch": ExecArbitrary,
			"run_commands_batch": ExecArbitrary, "get_config": ReadConfig,
			"get_config_diff": ReadConfig, "list_config_sessions": ReadConfig,
			"push_config": WriteConfig, "confirm_config_session": WriteConfig,
			"abort_config_session": WriteConfig, "collect_tech_support": ReadConfig,
			"daily_brief": ReadOperational,
		},
		"upa": {
			"send_command_and_get_output":            ExecArbitrary,
			"set_config_commands_and_commit_or_save": WriteConfig,
			"get_network_device_list":                InventoryRead,
		},
	}
	for server, tools := range want {
		p, ok := profiles[server]
		if !ok {
			t.Errorf("profile %s missing", server)
			continue
		}
		for tool, class := range tools {
			spec, ok := p.Lookup(tool)
			if !ok {
				t.Errorf("%s: tool %s missing", server, tool)
				continue
			}
			if spec.Class != class {
				t.Errorf("%s.%s: class %s, want %s", server, tool, spec.Class, class)
			}
		}
		if len(p.Tools) != len(tools) {
			t.Errorf("%s: profile has %d tools, catalog has %d", server, len(p.Tools), len(tools))
		}
	}

	// End-to-end through real profiles: the plan's test-matrix rows.
	ntunes := profiles["ntunes-netmiko-mcp-server"]
	if r := Classify(ntunes, "send_command", map[string]any{"device": "acc-sw-01", "command": "show running-config"}); r.Class != ReadConfig {
		t.Errorf("ntunes send_command show running-config: %s", r.Class)
	}
	eos := profiles["eos-mcp"]
	if r := Classify(eos, "run_command", map[string]any{"hostname": "lab-leaf-01", "command": "reload"}); r.Class != ExecArbitrary {
		t.Errorf("eos run_command reload: %s", r.Class)
	}
	junos := profiles["junos-mcp-server"]
	r := Classify(junos, "execute_junos_command_batch", map[string]any{"router_names": []any{"core-rtr-01", "core-rtr-02"}, "command": "show bgp summary"})
	if r.Class != ReadOperational || len(r.Targets) != 2 {
		t.Errorf("junos batch: %+v", r)
	}
	r = Classify(eos, "run_command_batch", map[string]any{"tags": []any{"lab"}, "command": "show version"})
	if len(r.Targets) != 1 || r.Targets[0] != "@lab" {
		t.Errorf("eos tags should become @lab: %+v", r.Targets)
	}
}

// upstreamParams is every parameter each shipped profile's upstream accepts,
// per tool, read from its source (ADR 0033; the commit is in each profile's
// header): netdev-ssh-mcp v1.7.1 struct tags, upa 96e8ff3 main.py, eos-mcp
// v1.3.0 server.py signatures, junos-mcp-server 75fe90a jmcp.py inputSchema
// plus every arguments.get() in its handlers, ntunes 4cc59d6 tools/*.py
// signatures. Each must be named in the profile or listed in refused_args,
// and nothing else may be. When an upstream version adds a parameter,
// update this table from its source first: the test then fails until the
// profile names or refuses it. Read the handler code, not only the declared
// schema: a server whose handlers read the arguments dict directly (junos
// load_and_commit_config reads an undocumented config key) accepts keys its
// schema never lists, and a tools/list comparison (tier 2) cannot see them.
var upstreamParams = map[string]map[string][]string{
	"netdev-ssh-mcp": {
		"get_config":       {"host", "username", "port", "config_type", "device_type"},
		"run_show_command": {"host", "command", "username", "port", "device_type"},
		"run_ping":         {"host", "destination", "username", "port", "count", "timeout", "source", "vrf", "size", "outgoing_interface", "device_type"},
		"run_traceroute":   {"host", "destination", "username", "port", "max_hops", "timeout", "probe", "source", "vrf", "outgoing_interface", "device_type"},
		"trust_host_key":   {"host", "port", "confirm", "replace_existing"},
	},
	"upa": {
		"get_network_device_list":                {},
		"send_command_and_get_output":            {"name", "command"},
		"set_config_commands_and_commit_or_save": {"name", "commands"},
	},
	"eos-mcp": {
		"health_check":           {"config_path"},
		"get_router_list":        {"tags", "config_path"},
		"get_device_facts":       {"hostname", "config_path"},
		"get_device_facts_batch": {"hostnames", "tags", "max_workers", "config_path"},
		"get_version":            {"hostname", "config_path"},
		"get_config_diff":        {"hostname", "rollback_id", "config_path"},
		"list_config_sessions":   {"hostname", "config_path"},
		"run_command":            {"hostname", "command", "config_path"},
		"run_commands":           {"hostname", "commands", "config_path"},
		"run_command_batch":      {"command", "hostnames", "tags", "max_workers", "config_path"},
		"run_commands_batch":     {"commands", "hostnames", "tags", "max_workers", "config_path"},
		"get_config":             {"hostname", "config_path"},
		"push_config":            {"hostname", "config_lines", "session_name", "dry_run", "commit_timer", "config_path"},
		"confirm_config_session": {"hostname", "session_name", "config_path"},
		"abort_config_session":   {"hostname", "session_name", "config_path"},
		"collect_tech_support":   {"hostname", "config_path"},
		"daily_brief":            {"hostnames", "tags", "max_workers", "since_hours", "config_path"},
	},
	"junos-mcp-server": {
		"execute_junos_command":        {"router_name", "command", "timeout"},
		"execute_junos_pfe_command":    {"router_name", "target", "command", "timeout"},
		"execute_junos_command_batch":  {"router_names", "command", "timeout"},
		"get_junos_config":             {"router_name"},
		"junos_config_diff":            {"router_name", "version"},
		"render_and_apply_j2_template": {"router_name", "router_names", "template_content", "vars_content", "apply_config", "dry_run", "commit_comment", "config_format", "timeout"},
		"gather_device_facts":          {"router_name", "timeout"},
		"get_router_list":              {},
		"load_and_commit_config":       {"router_name", "config_text", "config_format", "commit_comment", "timeout", "config"},
	},
	"ntunes-netmiko-mcp-server": {
		"send_command":           {"device", "command", "use_textfsm", "read_timeout"},
		"send_command_parallel":  {"devices", "command", "max_concurrent", "use_textfsm"},
		"send_commands_sequence": {"device", "commands", "stop_on_error"},
		"send_config":            {"device", "config_commands", "save_config", "dry_run", "enter_config_mode"},
		"send_config_parallel":   {"devices", "config_commands", "save_config", "max_concurrent", "rollback_on_error"},
		"list_devices":           {"tag", "device_type"},
		"get_device_info":        {"device", "include_connection_status"},
		"list_groups":            {},
		"get_device_types":       {},
		"get_tags":               {},
		"get_pool_status":        {},
		"test_connection":        {"device"},
	},
}

// wantRefused is every argument a shipped profile deliberately refuses. A
// change here is a security decision and needs the security reviewer.
var wantRefused = map[string]map[string][]string{
	"netdev-ssh-mcp": {
		"get_config": {"username"}, "run_show_command": {"username"},
		"run_ping": {"username"}, "run_traceroute": {"username"},
	},
	"eos-mcp": {
		"health_check": {"config_path"}, "get_router_list": {"config_path"},
		"get_device_facts": {"config_path"}, "get_device_facts_batch": {"config_path"},
		"get_version": {"config_path"}, "get_config_diff": {"config_path"},
		"list_config_sessions": {"config_path"}, "run_command": {"config_path"},
		"run_commands": {"config_path"}, "run_command_batch": {"config_path"},
		"run_commands_batch": {"config_path"}, "get_config": {"config_path"},
		"push_config":            {"config_path", "session_name"},
		"confirm_config_session": {"config_path", "session_name"},
		"abort_config_session":   {"config_path", "session_name"},
		"collect_tech_support":   {"config_path"}, "daily_brief": {"config_path"},
	},
	"ntunes-netmiko-mcp-server": {
		"send_config": {"enter_config_mode"},
	},
	"junos-mcp-server": {
		"load_and_commit_config": {"config"},
	},
}

// TestRepoProfileArguments pins the closed argument list of every shipped
// profile (ADR 0033, M1-35).
func TestRepoProfileArguments(t *testing.T) {
	profiles, err := LoadProfileDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	for server, p := range profiles {
		params, ok := upstreamParams[server]
		if !ok {
			t.Errorf("profile %s has no upstreamParams row; read its parameters from source and add them", server)
			continue
		}
		for _, tool := range p.ToolNames() {
			spec := p.Tools[tool]
			// The loader already refuses a tool without args; check here
			// too, so this test fails on its own if that check moves.
			if spec.Args == nil {
				t.Errorf("%s.%s: no args list", server, tool)
			}
			upstream, ok := params[tool]
			if !ok {
				t.Errorf("%s.%s: no upstreamParams row", server, tool)
				continue
			}
			covered := make([]string, 0, len(upstream))
			for _, l := range [][]string{spec.TargetParams, spec.TargetsParams, spec.GroupParams, spec.CommandParams, spec.ConfigParams, spec.Args, spec.RefusedArgs} {
				covered = append(covered, l...)
			}
			if got, want := sorted(covered), sorted(upstream); !reflect.DeepEqual(got, want) {
				t.Errorf("%s.%s: named plus refused %q, upstream accepts %q", server, tool, got, want)
			}
			if got, want := sorted(spec.RefusedArgs), sorted(wantRefused[server][tool]); !reflect.DeepEqual(got, want) {
				t.Errorf("%s.%s: refused_args %q, want %q", server, tool, got, want)
			}

			// Every named argument passes, with a value of the right shape.
			named := map[string]any{}
			for _, l := range [][]string{spec.TargetParams, spec.TargetsParams, spec.GroupParams, spec.CommandParams, spec.ConfigParams, spec.Args} {
				for _, n := range l {
					named[n] = "x"
				}
			}
			if r := Classify(p, tool, named); !r.ArgumentsOK() {
				t.Errorf("%s.%s: named arguments refused: unnamed %q malformed %q", server, tool, r.UnnamedArgs, r.MalformedArgs)
			}

			// An argument the profile does not name is reported, for every
			// tool of every profile, bare and prefixed.
			probe := map[string]any{"fathomgate_unnamed_probe": ""}
			for k, v := range named {
				probe[k] = v
			}
			for _, name := range []string{tool, server + "." + tool} {
				if r := Classify(p, name, probe); !reflect.DeepEqual(r.UnnamedArgs, []string{"fathomgate_unnamed_probe"}) {
					t.Errorf("%s: unnamed probe reported as %q", name, r.UnnamedArgs)
				}
			}

			// Every refused argument is reported, whatever its value.
			for _, refused := range spec.RefusedArgs {
				for _, v := range []any{"/proc/1/environ", "", nil} {
					args := map[string]any{refused: v}
					for k, nv := range named {
						args[k] = nv
					}
					if r := Classify(p, tool, args); !reflect.DeepEqual(r.UnnamedArgs, []string{refused}) {
						t.Errorf("%s.%s: %s=%v reported as %q", server, tool, refused, v, r.UnnamedArgs)
					}
				}
			}
		}
	}
	for server := range upstreamParams {
		if _, ok := profiles[server]; !ok {
			t.Errorf("upstreamParams names %s, which has no profile", server)
		}
	}
}

// TestEOSConfigPathRefused is the M1-35 regression: every eos-mcp tool
// refuses config_path (the security review of PR #158 reproduced
// get_version and get_router_list reading an agent-chosen file).
func TestEOSConfigPathRefused(t *testing.T) {
	profiles, err := LoadProfileDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	eos := profiles["eos-mcp"]
	if len(eos.Tools) != 17 {
		t.Fatalf("eos-mcp has %d tools, want 17", len(eos.Tools))
	}
	for _, tool := range eos.ToolNames() {
		if eos.Tools[tool].Named("config_path") {
			t.Errorf("eos-mcp.%s names config_path", tool)
		}
	}
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"get_version", map[string]any{"hostname": "lab-leaf-01", "config_path": "/proc/self/stat"}},
		{"get_router_list", map[string]any{"config_path": "/home/op/.git-credentials"}},
		{"health_check", map[string]any{"config_path": ""}},
		{"eos-mcp.run_command", map[string]any{"hostname": "lab-leaf-01", "command": "show version", "config_path": "/tmp/evil.ini"}},
	} {
		if r := Classify(eos, tc.tool, tc.args); r.ArgumentsOK() || !reflect.DeepEqual(r.UnnamedArgs, []string{"config_path"}) {
			t.Errorf("%s: unnamed %q, want [config_path]", tc.tool, r.UnnamedArgs)
		}
	}
	if r := Classify(eos, "get_version", map[string]any{"hostname": "lab-leaf-01"}); !r.ArgumentsOK() {
		t.Errorf("get_version without config_path refused: %q", r.UnnamedArgs)
	}
}

func sorted(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}
