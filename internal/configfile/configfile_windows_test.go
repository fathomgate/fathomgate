// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package configfile

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func icacls(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
		t.Fatalf("icacls %v: %v\n%s", args, err, out)
	}
}

// TestWindowsWriteACE: a file or directory that grants Everyone (S-1-1-0)
// write access is refused; read access for Everyone is fine.
func TestWindowsWriteACE(t *testing.T) {
	dir := ownerOnlyDir(t, t.TempDir())
	p := write(t, dir, "read.yaml", "version: 1\n")
	icacls(t, p, "/grant", "*S-1-1-0:(R)")
	if _, err := Read(p, "the policy file", 1<<10); err != nil {
		t.Fatalf("Everyone read: %v", err)
	}
	for _, right := range []string{"(W)", "(M)", "(F)", "(D)", "(WDAC)"} {
		q := write(t, dir, "w"+strings.Trim(right, "()")+".yaml", "version: 1\n")
		icacls(t, q, "/grant", "*S-1-1-0:"+right)
		if _, err := Read(q, "the policy file", 1<<10); !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), "S-1-1-0") {
			t.Errorf("Everyone %s: %v", right, err)
		}
	}
	sub := ownerOnlyDir(t, t.TempDir())
	icacls(t, sub, "/grant", "*S-1-1-0:(OI)(CI)(M)")
	if err := CheckDir(sub, "the profiles directory"); !errors.Is(err, ErrUnsafe) {
		t.Errorf("writable directory: %v", err)
	}
}
