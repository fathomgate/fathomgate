// SPDX-License-Identifier: FSL-1.1-ALv2

package classifytest

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNotInBinary: the table is for tests only.
func TestNotInBinary(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command on PATH")
	}
	out, err := exec.Command(gobin, "list", "-deps", "github.com/fathomgate/fathomgate/cmd/fathomgate").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep == "github.com/fathomgate/fathomgate/internal/classify/classifytest" {
			t.Fatal("cmd/fathomgate depends on internal/classify/classifytest, which is for tests only")
		}
	}
}
