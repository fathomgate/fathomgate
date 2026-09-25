// SPDX-License-Identifier: Apache-2.0

package classify

import "testing"

func TestClassifyCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		want Class
	}{
		{"show ip bgp summary", ReadOperational},
		{"  SHOW   version ", ReadOperational},
		{"show interfaces terse", ReadOperational},
		{"get system status", ReadOperational},
		{"display version", ReadOperational},
		{"monitor traffic interface ge-0/0/0 count 5", ReadOperational},
		{"ping 10.0.0.1 count 3", ReadOperational},
		{"traceroute 10.0.0.1", ReadOperational},
		{"tracepath 10.0.0.1", ReadOperational},
		{"show system reset-reason", ReadOperational},
		{"show interfaces status", ReadOperational},

		{"show running-config", ReadConfig},
		{"show running-config interface Gi1", ReadConfig},
		{"show startup-config", ReadConfig},
		{"show configuration", ReadConfig},
		{"show configuration interfaces", ReadConfig},
		{"show full-configuration", ReadConfig},
		{"display current-configuration", ReadConfig},
		{"show config", ReadConfig},

		{"", ExecArbitrary},
		{"monitor interface traffic", ExecArbitrary},
		{"reload", ExecArbitrary},
		{"reload in 5", ExecArbitrary},
		{"write erase", ExecArbitrary},
		{"write memory", ExecArbitrary},
		{"write", ExecArbitrary},
		{"configure terminal", ExecArbitrary},
		{"config t", ExecArbitrary},
		{"conf t", ExecArbitrary},
		{"copy running-config startup-config", ExecArbitrary},
		{"clear ip bgp *", ExecArbitrary},
		{"request system reboot", ExecArbitrary},
		{"request system zeroize", ExecArbitrary},
		{"commit", ExecArbitrary},
		{"rollback 0", ExecArbitrary},
		{"set interfaces ge-0/0/0 disable", ExecArbitrary},
		{"delete interfaces ge-0/0/0", ExecArbitrary},
		{"debug ip packet", ExecArbitrary},
		{"shutdown", ExecArbitrary},
		{"format flash:", ExecArbitrary},
		{"terminal length 0", ExecArbitrary},
		{"enable", ExecArbitrary},
		{"show version; reload", ExecArbitrary},
		{"show run | include password", ExecArbitrary},
		{"show version > flash:out.txt", ExecArbitrary},
		{"show version && reload", ExecArbitrary},
		{"show $(reload)", ExecArbitrary},
		{"ping 10.0.0.1 ; reload", ExecArbitrary},
		{"show version reload", ExecArbitrary},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			if got := ClassifyCommand(tc.cmd); got != tc.want {
				t.Fatalf("ClassifyCommand(%q) = %s, want %s", tc.cmd, got, tc.want)
			}
		})
	}
}

func TestClassifyCommands(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want Class
	}{
		{"empty", nil, ExecArbitrary},
		{"all reads", []string{"show version", "show ip route"}, ReadOperational},
		{"one config read", []string{"show version", "show running-config"}, ReadConfig},
		{"one failure", []string{"show version", "reload"}, ExecArbitrary},
		{"config read then failure", []string{"show running-config", "write erase"}, ExecArbitrary},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyCommands(tc.cmds); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestParseClass(t *testing.T) {
	for _, c := range All() {
		got, err := Parse(string(c))
		if err != nil || got != c {
			t.Fatalf("Parse(%s) = %s, %v", c, got, err)
		}
	}
	if got, err := Parse("read-config"); err != nil || got != ReadConfig {
		t.Fatalf("Parse(read-config) = %s, %v", got, err)
	}
	if _, err := Parse("DELETE_EVERYTHING"); err == nil {
		t.Fatal("expected error for unknown class")
	}
	if !WriteConfig.IsWrite() || ReadConfig.IsWrite() || !ReadConfig.IsRead() {
		t.Fatal("IsWrite/IsRead mismatch")
	}
}
