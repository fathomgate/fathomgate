// SPDX-License-Identifier: FSL-1.1-ALv2

package gate

import (
	"context"
	"testing"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/classify/classifytest"
	"github.com/fathomgate/fathomgate/internal/policy"
)

// TestFallbackBrief02Gate is M1-15 (M1 exit criterion 1) on the path
// fathomgate serve takes. Under --policy, a --server with no profile gets
// an empty profile (cmd/fathomgate/serve_policy.go, ADR 0027 note of
// 2026-09-25), so Decide never calls classify.Classify for these tools: it
// builds the fallback result itself. Every tool brief 02 names on a server
// with no shipped profile (classifytest.Brief02) goes through Decide under
// each example policy and must be EXEC_ARBITRARY, class_source fallback,
// and not forwarded. A call with arguments is denied default:bad_arguments
// before the rules (every argument is unnamed, ADR 0033); a call with none
// reaches the rules as EXEC_ARBITRARY with zero targets and is denied by
// no-exec in all three policies. The fallback never downgrades.
func TestFallbackBrief02Gate(t *testing.T) {
	rows := classifytest.Brief02()
	profiles := repoProfiles(t)
	for _, s := range classifytest.Brief02Servers {
		if profiles[s] != nil {
			t.Fatalf("server %s has a shipped profile", s)
		}
		// Exactly what serve builds for a --server with no profile.
		profiles[s] = &classify.Profile{Server: s, Tools: map[string]classify.ToolSpec{}}
	}
	for _, name := range []string{"read-only", "lab-open", "prod-approval"} {
		g, err := New(Config{Policy: examplePolicy(t, name), Profiles: profiles, Inventory: repoInventory(t, false)})
		if err != nil {
			t.Fatal(err)
		}
		withArgs, noArgs := 0, 0
		for _, row := range rows {
			v := g.Decide(context.Background(), call(row.Server, row.Tool, row.Args))
			wantRule := "no-exec"
			if len(row.Args) > 0 {
				wantRule = policy.RuleBadArguments
				withArgs++
			} else {
				noArgs++
			}
			if v.Class != string(classify.ExecArbitrary) || v.ClassSource != string(classify.SourceFallback) {
				t.Errorf("%s %s: class %s source %s, want %s source %s (brief 02 class %q)",
					name, row.Key(), v.Class, v.ClassSource, classify.ExecArbitrary, classify.SourceFallback, row.Brief)
			}
			if v.Forward || v.Effect != string(policy.Deny) || v.RuleID != wantRule {
				t.Errorf("%s %s: forward %v effect %s rule %s, want deny by %s", name, row.Key(), v.Forward, v.Effect, v.RuleID, wantRule)
			}
			if len(v.Targets) != 0 {
				t.Errorf("%s %s: targets %q, want none", name, row.Key(), v.Targets)
			}
			if v.Error == "" {
				t.Errorf("%s %s: no tool error text", name, row.Key())
			}
		}
		t.Logf("%s: %d rows denied %s, %d rows denied no-exec", name, withArgs, policy.RuleBadArguments, noArgs)
	}
}
