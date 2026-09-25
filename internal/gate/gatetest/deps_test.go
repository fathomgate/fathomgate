// SPDX-License-Identifier: FSL-1.1-ALv2

package gatetest

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNotInBinary: gatetest is for tests only, so the fathomgate binary's
// dependencies must not include it.
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
		if dep == "github.com/fathomgate/fathomgate/internal/gate/gatetest" {
			t.Fatal("cmd/fathomgate depends on internal/gate/gatetest, which is for tests only")
		}
	}
}
