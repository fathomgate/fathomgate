package main

import (
	"io"
	"slices"
	"strings"
	"testing"
)

func TestParseServe(t *testing.T) {
	t.Parallel()
	base := []string{"--server", "netdev-ssh-mcp", "--upstream", "/opt/bin/netdev-ssh-mcp"}
	with := func(extra ...string) []string { return append(slices.Clone(base), extra...) }
	cases := []struct {
		name     string
		args     []string
		wantErr  string // substring; empty means success
		wantArgs []string
		wantEnv  []string
	}{
		{name: "minimal", args: base},
		{name: "upstream args after --", args: with("--", "-insecure-skip-host-key-check", "x"), wantArgs: []string{"-insecure-skip-host-key-check", "x"}},
		{name: "empty --", args: with("--"), wantArgs: []string{}},
		{name: "repeated upstream-env", args: with("--upstream-env", "A=1", "--upstream-env", "B=x=y"), wantEnv: []string{"A=1", "B=x=y"}},
		{name: "upstream-env empty value", args: with("--upstream-env", "A="), wantEnv: []string{"A="}},
		{name: "upstream-env no equals", args: with("--upstream-env", "NOEQUALS"), wantErr: "--upstream-env argument 1 is not KEY=VALUE"},
		{name: "upstream-env empty key", args: with("--upstream-env", "=v"), wantErr: `--upstream-env "": key must match`},
		{name: "upstream-env underscore key", args: with("--upstream-env", "_A1=v"), wantEnv: []string{"_A1=v"}},
		{name: "upstream-env digit first", args: with("--upstream-env", "1A=v"), wantErr: "[A-Za-z_]"},
		{name: "upstream-env dash in key", args: with("--upstream-env", "A-B=v"), wantErr: "[A-Za-z_]"},
		{name: "upstream-env dot in key", args: with("--upstream-env", "A.B=v"), wantErr: "[A-Za-z_]"},
		{name: "upstream-env space in key", args: with("--upstream-env", "A B=v"), wantErr: "[A-Za-z_]"},
		{name: "upstream-env non-ASCII key", args: with("--upstream-env", "\u017fystemRoot=v"), wantErr: "[A-Za-z_]"},
		{name: "empty upstream", args: []string{"--server", "s", "--upstream", ""}, wantErr: "required"},
		{name: "blank upstream", args: []string{"--server", "s", "--upstream", "  "}, wantErr: "not an executable path"},
		{name: "upstream is --", args: []string{"--server", "s", "--upstream", "--"}, wantErr: "not an executable path"},
		{name: "positional without --", args: with("extra"), wantErr: `unexpected argument "extra"`},
		{name: "reserved --policy", args: with("--policy", "p.yaml"), wantErr: "--policy"},
		{name: "reserved -audit=x", args: with("-audit=a.jsonl"), wantErr: "--audit"},
		{name: "reserved flags listed together", args: with("--inventory", "i", "--profiles", "p"), wantErr: "--inventory, --profiles"},
		// S1: the flag parser stops at "extra", so --policy is not parsed as a flag.
		{name: "reserved after a positional", args: with("extra", "--policy", "p.yaml"), wantErr: "--policy"},
		{name: "reserved after --", args: with("--", "--policy=p.yaml"), wantErr: "--policy=p.yaml"},
		{name: "missing upstream", args: []string{"--server", "s"}, wantErr: "required"},
		{name: "missing server", args: []string{"--upstream", "x"}, wantErr: "required"},
		{name: "dotted server", args: []string{"--server", "net.dev", "--upstream", "x"}, wantErr: "--server"},
		{name: "server with space", args: []string{"--server", "net dev", "--upstream", "x"}, wantErr: "--server"},
		{name: "reserved server name", args: []string{"--server", "NetGuard", "--upstream", "x"}, wantErr: "reserved"},
		{name: "unknown flag", args: with("--bogus"), wantErr: "bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := parseServe(tc.args, io.Discard, noEnv, "linux")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.server != "netdev-ssh-mcp" || cfg.upstream != "/opt/bin/netdev-ssh-mcp" {
				t.Fatalf("cfg = %+v", cfg)
			}
			if tc.wantArgs == nil {
				tc.wantArgs = []string{}
			}
			if !slices.Equal(cfg.upstreamArgs, tc.wantArgs) {
				t.Errorf("upstream args %q, want %q", cfg.upstreamArgs, tc.wantArgs)
			}
			if !slices.Equal(cfg.upstreamEnv, tc.wantEnv) {
				t.Errorf("upstream env %q, want %q", cfg.upstreamEnv, tc.wantEnv)
			}
		})
	}
}
