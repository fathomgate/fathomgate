// SPDX-License-Identifier: FSL-1.1-ALv2

package proxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestGateSurface pins the guard the maintainer accepted with gate.Explain
// (ADR 0035, notes after acceptance): the proxy decides through Decide
// alone. Explain returns Evaluate's own reasons, which name targets and
// counters, and uncapped argument names; none of it may reach the agent.
//
//   - The proxy's Gate interface has exactly Decide and Arguments, so no
//     implementation's Explain is reachable through it.
//   - No non-test file of internal/proxy, in the package or any directory
//     below it, has an identifier containing Explain (Explain, Explanation,
//     an alias such as gateExplain), or calls MethodByName, which could
//     reach a method the interface does not list (security re-review of PR
//     #199, item 4).
func TestGateSurface(t *testing.T) {
	gt := reflect.TypeFor[Gate]()
	methods := make([]string, 0, gt.NumMethod())
	for i := range gt.NumMethod() {
		methods = append(methods, gt.Method(i).Name)
	}
	slices.Sort(methods)
	if !slices.Equal(methods, []string{"Arguments", "Decide"}) {
		t.Errorf("proxy.Gate methods %v, want [Arguments Decide]; a new method needs a record (ADR 0035 notes after acceptance)", methods)
	}

	fset := token.NewFileSet()
	checked := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != "." && (name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		checked++
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			switch {
			case !ok:
			case strings.Contains(id.Name, "Explain"):
				t.Errorf("%s: internal/proxy names %s; the proxy decides through Decide only (ADR 0035)", fset.Position(id.Pos()), id.Name)
			case id.Name == "MethodByName":
				t.Errorf("%s: internal/proxy calls MethodByName, which can reach a gate method proxy.Gate does not list (ADR 0035)", fset.Position(id.Pos()))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no non-test file of internal/proxy was checked")
	}
}
