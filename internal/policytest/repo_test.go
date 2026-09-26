// SPDX-License-Identifier: FSL-1.1-ALv2

package policytest

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestRepoExamplePolicies runs every shipped *.test.yaml, class-given and
// gate cases, with the embedded profiles, so the examples cannot drift from
// the engine, the classifier or the profiles (moved here from
// internal/policy by ADR 0035). Each example policy has both kinds of file,
// and each gate file has gate cases for rows 3, 4 and 6.
func TestRepoExamplePolicies(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "policies", "examples", "*.test.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no example test files found")
	}
	r := embedded(t)
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			results, err := r.RunFile(f)
			if err != nil {
				t.Fatal(err)
			}
			gateFile := strings.HasSuffix(f, ".gate.test.yaml")
			rows := map[string]bool{}
			for _, res := range results {
				if !res.Pass {
					t.Errorf("%s: %s", res.Name, res.Message)
				}
				if res.Gate != gateFile {
					t.Errorf("%s: gate %v in %s", res.Name, res.Gate, filepath.Base(f))
				}
				for _, row := range []string{"row 3", "row 4", "row 6"} {
					if strings.HasPrefix(res.Name, row+":") {
						rows[row] = true
					}
				}
			}
			if gateFile && len(rows) != 3 {
				t.Errorf("gate cases for rows %v only; each gate file covers rows 3, 4 and 6", rows)
			}
		})
	}
	for _, p := range []string{"read-only", "lab-open", "prod-approval"} {
		for _, kind := range []string{".test.yaml", ".gate.test.yaml"} {
			if matches, _ := filepath.Glob(filepath.Join("..", "..", "policies", "examples", p+kind)); len(matches) != 1 {
				t.Errorf("policies/examples/%s%s is missing", p, kind)
			}
		}
	}
}
