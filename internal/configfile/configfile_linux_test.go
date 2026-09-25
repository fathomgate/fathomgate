// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package configfile

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestLinuxPOSIXACLWrite: a POSIX ACL entry granting a named user write
// raises the ACL mask, which stat reports as the group write bit, so the
// file is refused although its owner never ran chmod g+w. Outside CI a
// machine without setfacl or ACL support skips; under CI (CI set) that is
// a failure, and ci.yaml checks the test printed --- PASS.
func TestLinuxPOSIXACLWrite(t *testing.T) {
	skip := t.Skipf
	if os.Getenv("CI") != "" {
		skip = t.Fatalf
	}
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		skip("setfacl is not installed")
	}
	p := write(t, ownerOnlyDir(t, t.TempDir()), "p.yaml", "version: 1\n")
	if _, err := Read(p, "the policy file", 1<<10); err != nil {
		t.Fatalf("before the ACL: %v", err)
	}
	// uid 65534 (nobody); the entry needs no account to name.
	if out, err := exec.Command(setfacl, "-m", "u:65534:rw", p).CombinedOutput(); err != nil {
		skip("setfacl failed (file system without ACLs?): %v %s", err, out)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o020 == 0 {
		t.Fatalf("mode %04o after a named-user write entry; expected the mask to show g+w", fi.Mode().Perm())
	}
	_, err = Read(p, "the policy file", 1<<10)
	if !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), "chmod go-w") {
		t.Fatalf("named-user write ACL: %v", err)
	}
}
