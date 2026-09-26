// SPDX-License-Identifier: FSL-1.1-ALv2

package classify_test

import (
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/classify/classifytest"
)

// M1-15, M1 exit criterion 1 (second half of the PRD metric): every tool
// that brief 02 names on a server with no shipped profile is
// fallback-classified, with a test. The table is classifytest.Brief02; the
// gate-level test over the same rows, the path serve takes, is
// internal/gate TestFallbackBrief02Gate.
//
// The fallback never downgrades: a tool with no profile entry is
// EXEC_ARBITRARY with class_source fallback whatever its arguments
// (maintainer decision of 2026-09-25 not to build the classification.md
// section 3 fallback classifier). So every row must be EXEC_ARBITRARY; the
// brief's class is kept in the table as documentation only. A row that
// comes out any other class fails; there is no skip list.

// TestFallbackBrief02 classifies every row the ways a call reaches the
// fallback in Classify: with no profile at all, and with the empty profile
// fathomgate serve gives a --server that has none (ADR 0027 note of
// 2026-09-25), by bare and by prefixed tool name.
func TestFallbackBrief02(t *testing.T) {
	for _, row := range classifytest.Brief02() {
		key := row.Key()
		t.Run(key, func(t *testing.T) {
			empty := &classify.Profile{Server: row.Server, Tools: map[string]classify.ToolSpec{}}
			wantUnnamed := sortedArgNames(row.Args)
			for _, c := range []struct {
				name    string
				profile *classify.Profile
				tool    string
				unnamed []string
			}{
				{"no profile", nil, row.Tool, nil},
				{"empty profile", empty, row.Tool, wantUnnamed},
				{"empty profile, prefixed", empty, key, wantUnnamed},
			} {
				r := classify.Classify(c.profile, c.tool, row.Args)
				if r.Class != classify.ExecArbitrary || r.ClassSource != classify.SourceFallback {
					t.Errorf("%s: class %s source %s, want %s source %s (brief 02 class %q; the fallback never downgrades)",
						c.name, r.Class, r.ClassSource, classify.ExecArbitrary, classify.SourceFallback, row.Brief)
				}
				if r.Known || r.ProfileClass != "" {
					t.Errorf("%s: Known %v ProfileClass %q, want an unknown tool", c.name, r.Known, r.ProfileClass)
				}
				// Every argument of an unlisted tool is unnamed under a
				// profile (ADR 0033); with no profile nothing is checked.
				if !slices.Equal(r.UnnamedArgs, c.unnamed) {
					t.Errorf("%s: UnnamedArgs %q, want %q", c.name, r.UnnamedArgs, c.unnamed)
				}
				if r.MalformedArgs != nil {
					t.Errorf("%s: MalformedArgs %q, want none", c.name, r.MalformedArgs)
				}
			}
		})
	}
}

// TestFallbackBrief02Table checks the table itself: every row is on a
// declared server, no row repeats, every brief class is a class or
// Unclassed, the never-downgrade names are rows the brief calls
// EXEC_ARBITRARY, Meraki execute_api is not here,
// and no declared server has a shipped profile (its rows would belong in
// TestRepoProfiles).
func TestFallbackBrief02Table(t *testing.T) {
	rows := classifytest.Brief02()
	declared := map[string]bool{}
	for _, s := range classifytest.Brief02Servers {
		declared[s] = true
	}
	byKey := map[string]classifytest.Brief02Tool{}
	perServer := map[string]int{}
	noArgs := 0
	for _, row := range rows {
		key := row.Key()
		if !declared[row.Server] {
			t.Errorf("%s: server not in Brief02Servers", key)
		}
		if _, dup := byKey[key]; dup {
			t.Errorf("%s: row repeated", key)
		}
		byKey[key] = row
		perServer[row.Server]++
		if len(row.Args) == 0 {
			noArgs++
		}
		if row.Brief != classifytest.Unclassed && !row.Brief.Valid() {
			t.Errorf("%s: brief class %q is not a class", key, row.Brief)
		}
		if row.Server == "cisco-meraki-mcp" && row.Tool == "execute_api" {
			t.Errorf("%s: belongs to M1-17 (capability tables)", key)
		}
	}
	for key := range classifytest.NeverDowngrade {
		row, ok := byKey[key]
		if !ok {
			t.Errorf("NeverDowngrade %s has no row", key)
			continue
		}
		if row.Brief != classify.ExecArbitrary {
			t.Errorf("%s: never-downgrade row with brief class %s", key, row.Brief)
		}
	}
	for _, s := range classifytest.Brief02Servers {
		if perServer[s] == 0 {
			t.Errorf("server %s has no rows", s)
		}
	}
	shipped, err := classify.LoadProfileDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	for server := range shipped {
		if declared[server] {
			t.Errorf("server %s now has a shipped profile: move its rows to TestRepoProfiles", server)
		}
	}
	t.Logf("%d tools on %d servers fallback-classified, %d of them with no arguments",
		len(rows), len(classifytest.Brief02Servers), noArgs)
}

func sortedArgNames(m map[string]any) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
