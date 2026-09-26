// SPDX-License-Identifier: FSL-1.1-ALv2

package proxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
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
//   - No non-test file of internal/proxy names Explain or Explanation, as a
//     selector, a type or anything else.
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

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && (id.Name == "Explain" || id.Name == "Explanation") {
				t.Errorf("%s: internal/proxy names %s; the proxy decides through Decide only (ADR 0035)", fset.Position(id.Pos()), id.Name)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no non-test file of internal/proxy was checked")
	}
}
