// SPDX-License-Identifier: FSL-1.1-ALv2

package gate

import (
	"context"
	"testing"

	"github.com/fathomgate/fathomgate/internal/gate/gatetest"
	"github.com/fathomgate/fathomgate/internal/gate/seam"
)

// overheadCases is the typical corpus and the worst cases, each with the
// verdict it must get under prod-approval.
func overheadCases(t testing.TB, g *Gate) (typical, worst []gatetest.Case) {
	t.Helper()
	worst, err := gatetest.Worst()
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
// over the typical corpus; each worst case at the 64 KiB argument cap is
// timed on its own and its p50 must stay under the budget
// (gatetest.KnownOverBudget lists the ones that do not yet; a worst case's
// p99 over the budget is logged, see the gatetest package doc). Every call
// is timed on its own after a warm-up; run go test -v -run Overhead for the
// numbers.
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
