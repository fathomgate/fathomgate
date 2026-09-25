// SPDX-License-Identifier: FSL-1.1-ALv2

package gate

import (
	"context"
	"testing"

	"github.com/fathomgate/fathomgate/internal/gate/gatetest"
	"github.com/fathomgate/fathomgate/internal/gate/seam"
	"github.com/fathomgate/fathomgate/internal/inventory"
)

// exampleDeviceNames are the device names of inventory.example.yaml, in
// file order.
func exampleDeviceNames(t testing.TB) []string {
	t.Helper()
	f, err := inventory.LoadFile(repoPath("inventory.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(f.Devices))
	for i, d := range f.Devices {
		names[i] = d.Name
	}
	return names
}

// overheadCases is the typical corpus and the worst cases, each checked
// once for the verdict it must get under prod-approval.
func overheadCases(t testing.TB, g *Gate) (typical, worst []gatetest.Case) {
	t.Helper()
	worst, err := gatetest.Worst(exampleDeviceNames(t))
	if err != nil {
		t.Fatal(err)
	}
	typical = gatetest.Typical()
	for _, c := range append(append([]gatetest.Case(nil), typical...), worst...) {
		v := g.Decide(context.Background(), callInfo(c))
		if v.Effect != c.Effect || v.RuleID != c.Rule {
			t.Fatalf("%s: got %s %s (%s), want %s %s", c.Name, v.Effect, v.RuleID, v.Error, c.Effect, c.Rule)
		}
	}
	return typical, worst
}

// TestDecideOverhead pins the PRD's M1 overhead budget (M1-23): Decide, the
// parse, classify, resolve and Evaluate steps with the repo profiles,
// prod-approval and inventory.example.yaml, adds under 5 ms at p99 per call
// over the typical corpus, in every run. Each worst case at the 64 KiB
// argument cap is timed on its own; its p50 is enforced only with
// FATHOMGATE_OVERHEAD_STRICT=1 (gatetest.CheckWorst), and in every other
// run, and under -race, it is checked for its verdict only. Every call is timed on its own after a
// warm-up; run go test -v -run Overhead for the numbers.
func TestDecideOverhead(t *testing.T) {
	g := newGate(t, examplePolicy(t, "prod-approval"), false)
	typical, worst := overheadCases(t, g)
	ctx := context.Background()
	typicalRounds, worstRounds, warm := gatetest.Rounds()
	gatetest.Header(t, gatetest.WhatGate)

	// The typical corpus in turn, so its p99 is over the mix.
	ins := make([]seam.CallInfo, len(typical))
	for i, c := range typical {
		ins[i] = callInfo(c)
	}
	k := 0
	all := gatetest.Time(typicalRounds*len(ins), warm*len(ins), func() {
		_ = g.Decide(ctx, ins[k%len(ins)])
		k++
	})
	gatetest.CheckTypical(t, gatetest.WhatGate, "typical corpus", all)

	if !gatetest.TimeWorst() {
		t.Logf("%s: worst cases checked for their verdict only (not strict, or -race)", gatetest.WhatGate)
		return
	}
	for _, c := range worst {
		in := callInfo(c)
		gatetest.CheckWorst(t, gatetest.WhatGate, c.Name, gatetest.Time(worstRounds, warm, func() { _ = g.Decide(ctx, in) }))
	}
}

// BenchmarkDecideOverhead is one sub-benchmark per corpus case, for the
// mean cost and allocations of each (TestDecideOverhead has the p99).
func BenchmarkDecideOverhead(b *testing.B) {
	g := newGate(b, examplePolicy(b, "prod-approval"), false)
	typical, worst := overheadCases(b, g)
	ctx := context.Background()
	for _, c := range append(typical, worst...) {
		in := callInfo(c)
		b.Run(c.Name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = g.Decide(ctx, in)
			}
		})
	}
}
