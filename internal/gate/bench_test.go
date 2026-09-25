// SPDX-License-Identifier: FSL-1.1-ALv2

package gate

import (
	"context"
	"testing"

	"github.com/fathomgate/fathomgate/internal/gate/seam"
)

// benchCorpus is a fixed mix of calls through the three M1 profiles: typed
// reads, downgraded exec, config dumps, refused exec, writes that hold,
// unknown targets, bad names, fan-out and group selectors.
func benchCorpus() []seam.CallInfo {
	return []seam.CallInfo{
		call(netdev, "run_show_command", map[string]any{"host": "core-rtr-01", "command": "show ip bgp summary"}),
		call(netdev, "get_config", map[string]any{"host": "lab-sw-01"}),
		call(upa, "send_command_and_get_output", map[string]any{"name": "core-rtr-01", "command": "show interfaces status"}),
		call(upa, "send_command_and_get_output", map[string]any{"name": "core-rtr-01", "command": "reload"}),
		call(upa, "set_config_commands_and_commit_or_save", map[string]any{"name": "core-rtr-01", "commands": []any{"interface Ethernet1", "description uplink"}}),
		call(eos, "run_command", map[string]any{"hostname": "lab-sw-01", "command": "show running-config"}),
		call(eos, "run_commands", map[string]any{"hostname": "lab-sw-01", "commands": []any{"show version", "show clock", "show ip route"}}),
		call(eos, "push_config", map[string]any{"hostname": "core-rtr-01", "config_lines": []any{"hostname x"}}),
		call(eos, "get_version", map[string]any{"hostname": "core-x.attacker.example"}),
		call(eos, "get_version", map[string]any{"hostname": "lab-x@core-rtr-01"}),
		call(eos, "daily_brief", map[string]any{"hostnames": []any{"lab-sw-01", "lab-sw-02", "core-rtr-01", "core-rtr-02"}}),
		call(eos, "daily_brief", map[string]any{"tags": []any{"core"}}),
	}
}

// BenchmarkDecide is one pass over the corpus per iteration, with the
// shipped profiles, inventory.example.yaml and prod-approval. M1-23 turns
// it into the p99 budget test (PRD: under 5 ms).
func BenchmarkDecide(b *testing.B) {
	g := newGate(b, examplePolicy(b, "prod-approval"), false)
	corpus := benchCorpus()
	ctx := context.Background()
	b.ReportAllocs()
	n := 0
	for b.Loop() {
		for _, in := range corpus {
			_ = g.Decide(ctx, in)
		}
		n++
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(n*len(corpus)), "ns/call")
}
