// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"reflect"
	"testing"
)

const testProfile = `
server: fake
tools:
  get_config:
    class: READ_CONFIG
    target_params: [host]
    args: []
  run_show_command:
    class: READ_OPERATIONAL
    target_params: [host]
    command_params: [command]
    args: []
  send_command_parallel:
    class: EXEC_ARBITRARY
    targets_params: [devices]
    command_params: [command]
    args: []
  run_commands_batch:
    class: EXEC_ARBITRARY
    targets_params: [hostnames]
    group_params: [tags]
    command_params: [commands]
    args: []
  send_config:
    class: WRITE_CONFIG
    target_params: [device]
    config_params: [config_commands]
    args: []
  load_and_commit_config:
    class: WRITE_CONFIG
    target_params: [router_name]
    config_params: [config_text]
    args: []
  list_devices:
    class: INVENTORY_READ
    args: []
`

func mustProfile(t *testing.T) *Profile {
	t.Helper()
	p, err := ParseProfile([]byte(testProfile))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNormalize(t *testing.T) {
	p := mustProfile(t)
	cases := []struct {
		name        string
		tool        string
		args        map[string]any
		wantTargets []string
		wantCmds    []string
		wantPayload string
	}{
		{
			name:        "single target",
			tool:        "get_config",
			args:        map[string]any{"host": "core-rtr-01", "config_type": "running"},
			wantTargets: []string{"core-rtr-01"},
		},
		{
			name:        "prefixed tool name",
			tool:        "fake.get_config",
			args:        map[string]any{"host": "core-rtr-01"},
			wantTargets: []string{"core-rtr-01"},
		},
		{
			name:        "array targets and group token pass-through",
			tool:        "send_command_parallel",
			args:        map[string]any{"devices": []any{"leaf-01", "@edge", "leaf-01"}, "command": "show version"},
			wantTargets: []string{"leaf-01", "@edge"},
			wantCmds:    []string{"show version"},
		},
		{
			name:        "comma separated targets",
			tool:        "send_command_parallel",
			args:        map[string]any{"devices": "leaf-01, leaf-02 ,leaf-03", "command": "show ip route"},
			wantTargets: []string{"leaf-01", "leaf-02", "leaf-03"},
			wantCmds:    []string{"show ip route"},
		},
		{
			name:        "tags become group tokens, commands array",
			tool:        "run_commands_batch",
			args:        map[string]any{"hostnames": []string{"spine-01"}, "tags": []any{"lab"}, "commands": []any{"show version", "show ip route 10.0.0.0, 24"}},
			wantTargets: []string{"spine-01", "@lab"},
			wantCmds:    []string{"show version", "show ip route 10.0.0.0, 24"},
		},
		{
			name:        "config payload from array",
			tool:        "send_config",
			args:        map[string]any{"device": "leaf-01", "config_commands": []any{"interface Gi1", " description x"}},
			wantTargets: []string{"leaf-01"},
			wantPayload: "interface Gi1\n description x",
		},
		{
			name:        "config payload from text",
			tool:        "load_and_commit_config",
			args:        map[string]any{"router_name": "core-rtr-01", "config_text": "set system host-name x\n"},
			wantTargets: []string{"core-rtr-01"},
			wantPayload: "set system host-name x",
		},
		{
			name: "unknown tool",
			tool: "nope",
			args: map[string]any{"host": "x"},
		},
		{
			name: "no target params",
			tool: "list_devices",
			args: map[string]any{"tag": "lab"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			targets, cmds, payload := Normalize(p, tc.tool, tc.args)
			if !reflect.DeepEqual(targets, tc.wantTargets) {
				t.Errorf("targets = %v, want %v", targets, tc.wantTargets)
			}
			if !reflect.DeepEqual(cmds, tc.wantCmds) {
				t.Errorf("commands = %v, want %v", cmds, tc.wantCmds)
			}
			if payload != tc.wantPayload {
				t.Errorf("payload = %q, want %q", payload, tc.wantPayload)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	p := mustProfile(t)
	cases := []struct {
		name  string
		tool  string
		args  map[string]any
		want  Class
		known bool
	}{
		{"profile class kept for config read", "get_config", map[string]any{"host": "a"}, ReadConfig, true},
		{"exec downgraded on show", "send_command_parallel", map[string]any{"devices": "a", "command": "show ip bgp summary"}, ReadOperational, true},
		{"exec downgraded to config read", "send_command_parallel", map[string]any{"devices": "a", "command": "show running-config"}, ReadConfig, true},
		{"exec stays on reload", "send_command_parallel", map[string]any{"devices": "a", "command": "reload"}, ExecArbitrary, true},
		{"exec stays on mixed batch", "run_commands_batch", map[string]any{"hostnames": []any{"a"}, "commands": []any{"show version", "write erase"}}, ExecArbitrary, true},
		{"exec stays with no command", "send_command_parallel", map[string]any{"devices": "a"}, ExecArbitrary, true},
		{"read tool escalated to config read", "run_show_command", map[string]any{"host": "a", "command": "show running-config"}, ReadConfig, true},
		{"read tool escalated to exec", "run_show_command", map[string]any{"host": "a", "command": "reload"}, ExecArbitrary, true},
		{"read tool stays read", "run_show_command", map[string]any{"host": "a", "command": "show version"}, ReadOperational, true},
		{"write stays write", "send_config", map[string]any{"device": "a", "config_commands": []any{"show version"}}, WriteConfig, true},
		{"unknown tool is exec", "mystery", nil, ExecArbitrary, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Classify(p, tc.tool, tc.args)
			if res.Class != tc.want {
				t.Errorf("class = %s, want %s (reason %q)", res.Class, tc.want, res.Reason)
			}
			if res.Known != tc.known {
				t.Errorf("known = %v, want %v", res.Known, tc.known)
			}
		})
	}
	if res := Classify(nil, "x", nil); res.Class != ExecArbitrary {
		t.Fatalf("nil profile should be EXEC_ARBITRARY, got %s", res.Class)
	}
}

func TestParseProfileErrors(t *testing.T) {
	bad := []string{
		"tools: {a: {class: READ_CONFIG}}",                      // missing server
		"server: x\ntools: {}",                                  // no tools
		"server: x\ntools: {a: {class: NOPE}}",                  // bad class
		"server: x\nbogus: 1\ntools: {a: {class: READ_CONFIG}}", // unknown key
	}
	for _, b := range bad {
		if _, err := ParseProfile([]byte(b)); err == nil {
			t.Errorf("expected error for %q", b)
		}
	}
}

func TestProfileToolNames(t *testing.T) {
	p := mustProfile(t)
	names := p.ToolNames()
	if len(names) != len(p.Tools) || names[0] != "get_config" {
		t.Fatalf("unexpected names %v", names)
	}
}
