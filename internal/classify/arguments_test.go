// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"reflect"
	"strings"
	"testing"
)

// TestParseProfileArgs pins the loader's checks on the closed argument list
// (ADR 0033): args is required on every tool, names are unique across the
// *_params lists and args, and a refused argument is never also named.
func TestParseProfileArgs(t *testing.T) {
	cases := []struct {
		name    string
		tool    string // the YAML under "tools:\n  t:\n"
		wantErr string // "" means the profile loads
	}{
		{"empty args list", "    class: READ_OPERATIONAL\n    args: []\n", ""},
		{"args and refused", "    class: READ_OPERATIONAL\n    target_params: [hostname]\n    args: [max_workers]\n    refused_args: [config_path]\n", ""},
		{"args missing", "    class: READ_OPERATIONAL\n    target_params: [hostname]\n", "args is required"},
		{"args null", "    class: READ_OPERATIONAL\n    args:\n", "args is required"},
		{"duplicate inside args", "    class: READ_OPERATIONAL\n    args: [a, a]\n", `"a" named twice`},
		{"duplicate across lists", "    class: READ_OPERATIONAL\n    target_params: [host]\n    args: [host]\n", `"host" named twice (target_params and args)`},
		{"duplicate target and command", "    class: EXEC_ARBITRARY\n    target_params: [x]\n    command_params: [x]\n    args: []\n", `"x" named twice`},
		{"refused and named", "    class: READ_OPERATIONAL\n    args: [config_path]\n    refused_args: [config_path]\n", "both named (args) and in refused_args"},
		{"refused twice", "    class: READ_OPERATIONAL\n    args: []\n    refused_args: [p, p]\n", `"p" listed twice`},
		{"empty name", "    class: READ_OPERATIONAL\n    args: [\"\"]\n", "empty or has surrounding space"},
		{"space in name", "    class: READ_OPERATIONAL\n    args: [\" port\"]\n", "empty or has surrounding space"},
		{"empty refused name", "    class: READ_OPERATIONAL\n    args: []\n    refused_args: [\"\"]\n", "empty or has surrounding space"},
		{"unknown key still strict", "    class: READ_OPERATIONAL\n    args: []\n    forbidden_params: [x]\n", "forbidden_params"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseProfile([]byte("server: s\ntools:\n  t:\n" + tc.tool))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("loaded; want error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// spacedHostname is a key one space away from a named argument.
const spacedHostname = "hostname" + " "

const argsProfile = `
server: fake
tools:
  run_command:
    class: EXEC_ARBITRARY
    target_params: [hostname]
    command_params: [command]
    args: []
    refused_args: [config_path]
  run_commands_batch:
    class: EXEC_ARBITRARY
    targets_params: [hostnames]
    group_params: [tags]
    command_params: [commands]
    args: [max_workers, options]
  push_config:
    class: WRITE_CONFIG
    target_params: [hostname]
    config_params: [config_lines]
    args: [dry_run]
  list:
    class: INVENTORY_READ
    args: []
`

// TestCheckArguments covers the closed argument list at the classifier: what
// is unnamed, what is malformed, and that Classify reports both without
// changing the class.
func TestCheckArguments(t *testing.T) {
	p, err := ParseProfile([]byte(argsProfile))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name          string
		tool          string
		args          map[string]any
		wantUnnamed   []string
		wantMalformed []string
	}{
		{"named only", "run_command", map[string]any{"hostname": "lab-leaf-01", "command": "show version"}, nil, nil},
		{"no arguments", "list", nil, nil, nil},
		{"refused argument", "run_command", map[string]any{"hostname": "h", "command": "show version", "config_path": "/proc/1/environ"}, []string{"config_path"}, nil},
		{"refused argument empty string", "run_command", map[string]any{"hostname": "h", "command": "show version", "config_path": ""}, []string{"config_path"}, nil},
		{"refused argument null", "run_command", map[string]any{"hostname": "h", "command": "show version", "config_path": nil}, []string{"config_path"}, nil},
		{"never seen argument", "run_command", map[string]any{"hostname": "h", "command": "show version", "new_upstream_param": 1}, []string{"new_upstream_param"}, nil},
		{"case differs", "run_command", map[string]any{"Hostname": "h", "command": "show version"}, []string{"Hostname"}, nil},
		{"space in key", "run_command", map[string]any{spacedHostname: "h", "command": "show version"}, []string{spacedHostname}, nil},
		{"empty key", "run_command", map[string]any{"": "x", "hostname": "h"}, []string{""}, nil},
		{"several sorted", "list", map[string]any{"z": 1, "a": 2, "m": nil}, []string{"a", "m", "z"}, nil},
		{"named in args, any value", "run_commands_batch", map[string]any{"hostnames": []any{"a", "b"}, "tags": []any{"lab"}, "commands": []any{"show version"}, "max_workers": 5, "options": map[string]any{"config_path": "/etc/shadow"}}, nil, nil},
		{"named arg, bool", "push_config", map[string]any{"hostname": "h", "config_lines": []any{"hostname x"}, "dry_run": true}, nil, nil},
		{"named target empty string", "run_command", map[string]any{"hostname": "", "command": "show version"}, nil, nil},
		{"named target null", "run_command", map[string]any{"hostname": nil, "command": "show version"}, nil, nil},
		{"target is a number", "run_command", map[string]any{"hostname": 10.0, "command": "show version"}, nil, []string{"hostname"}},
		{"target is an object", "run_command", map[string]any{"hostname": map[string]any{"name": "h"}, "command": "show version"}, nil, []string{"hostname"}},
		{"command is a bool", "run_command", map[string]any{"hostname": "h", "command": true}, nil, []string{"command"}},
		{"targets hold a number", "run_commands_batch", map[string]any{"hostnames": []any{"a", 1.0}, "commands": []any{"show version"}}, nil, []string{"hostnames"}},
		{"nested array in commands", "run_commands_batch", map[string]any{"hostnames": []any{"a"}, "commands": []any{[]any{"show version"}}}, nil, []string{"commands"}},
		{"object in group", "run_commands_batch", map[string]any{"tags": []any{map[string]any{"x": "y"}}, "commands": []any{"show version"}}, nil, []string{"tags"}},
		{"config payload number", "push_config", map[string]any{"hostname": "h", "config_lines": 7.0}, nil, []string{"config_lines"}},
		{"unnamed and malformed", "run_command", map[string]any{"hostname": 1.0, "command": "show version", "config_path": "x"}, []string{"config_path"}, []string{"hostname"}},
		{"unknown tool, every key unnamed", "nope", map[string]any{"hostname": "h", "command": "reload"}, []string{"command", "hostname"}, nil},
		{"unknown tool, prefixed", "fake.nope", map[string]any{"a": 1}, []string{"a"}, nil},
		{"unknown tool, no arguments", "nope", map[string]any{}, nil, nil},
		{"prefixed known tool", "fake.run_command", map[string]any{"hostname": "h", "command": "show version", "config_path": "x"}, []string{"config_path"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unnamed, malformed := CheckArguments(p, tc.tool, tc.args)
			if !reflect.DeepEqual(unnamed, tc.wantUnnamed) {
				t.Errorf("unnamed %q, want %q", unnamed, tc.wantUnnamed)
			}
			if !reflect.DeepEqual(malformed, tc.wantMalformed) {
				t.Errorf("malformed %q, want %q", malformed, tc.wantMalformed)
			}
			r := Classify(p, tc.tool, tc.args)
			if !reflect.DeepEqual(r.UnnamedArgs, tc.wantUnnamed) || !reflect.DeepEqual(r.MalformedArgs, tc.wantMalformed) {
				t.Errorf("Classify reported unnamed %q malformed %q", r.UnnamedArgs, r.MalformedArgs)
			}
			if want := tc.wantUnnamed == nil && tc.wantMalformed == nil; r.ArgumentsOK() != want {
				t.Errorf("ArgumentsOK %v, want %v", r.ArgumentsOK(), want)
			}
		})
	}
}

// TestCheckArgumentsKeepsClass: the argument check reports, it does not
// reclassify. The gate refuses the call; the class stays what the profile
// and payload say, so the decision log line still shows it.
func TestCheckArgumentsKeepsClass(t *testing.T) {
	p, err := ParseProfile([]byte(argsProfile))
	if err != nil {
		t.Fatal(err)
	}
	r := Classify(p, "run_command", map[string]any{"hostname": "h", "command": "show version", "config_path": "/x"})
	if r.Class != ReadOperational || r.ArgumentsOK() {
		t.Fatalf("got class %s, ArgumentsOK %v; want READ_OPERATIONAL and false", r.Class, r.ArgumentsOK())
	}
}

// TestCheckArgumentsNoProfile: with no profile the fallback classifier runs
// (ADR 0027) and there is no list to check against.
func TestCheckArgumentsNoProfile(t *testing.T) {
	unnamed, malformed := CheckArguments(nil, "run_command", map[string]any{"config_path": "/x"})
	if unnamed != nil || malformed != nil {
		t.Fatalf("nil profile: unnamed %q malformed %q, want none", unnamed, malformed)
	}
	if r := Classify(nil, "run_command", map[string]any{"config_path": "/x"}); !r.ArgumentsOK() || r.Class != ExecArbitrary {
		t.Fatalf("nil profile: %+v", r)
	}
}
