// SPDX-License-Identifier: FSL-1.1-ALv2

package gate

import (
	"context"
	"testing"

	"github.com/fathomgate/fathomgate/internal/gate/gatetest"
	"github.com/fathomgate/fathomgate/internal/gate/seam"
)

// benchCorpus is the typical overhead corpus (gatetest.Typical): a fixed mix
// of calls through the three M1 profiles, typed reads, downgraded exec,
// config dumps, refused exec, writes that hold, unknown targets, bad names,
// fan-out and group selectors.
func benchCorpus() []seam.CallInfo {
	cs := gatetest.Typical()
	out := make([]seam.CallInfo, len(cs))
	for i, c := range cs {
		out[i] = callInfo(c)
	}
	return out
}

// callInfo is call() for a corpus case.
func callInfo(c gatetest.Case) seam.CallInfo {
	in := call(c.Server, c.Tool, nil)
	in.Arguments = c.Args
	return in
}

// BenchmarkDecide is one pass over the corpus per iteration, with the
// shipped profiles, inventory.example.yaml and prod-approval.
// TestDecideOverhead holds the p99 budget (PRD: under 5 ms).
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
