// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"path/filepath"
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
			"render_and_apply_j2_template": WriteConfig,
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
			"abort_config_session": WriteConfig, "collect_tech_support": ReadOperational,
			"daily_brief": ReadOperational,
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
