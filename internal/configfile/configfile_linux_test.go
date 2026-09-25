// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package configfile

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// TestLinuxPOSIXACLWrite: a POSIX ACL entry granting a named user write
// raises the ACL mask, which stat reports as the group write bit, so the
// file is refused although its owner never ran chmod g+w.
func TestLinuxPOSIXACLWrite(t *testing.T) {
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("setfacl is not installed")
	}
	p := write(t, ownerOnlyDir(t, t.TempDir()), "p.yaml", "version: 1\n")
	if _, err := Read(p, "the policy file", 1<<10); err != nil {
		t.Fatalf("before the ACL: %v", err)
	}
	// uid 65534 (nobody) exists on every Linux the CI uses; the entry
	// needs no account to name.
	if out, err := exec.Command(setfacl, "-m", "u:"+strconv.Itoa(65534)+":rw", p).CombinedOutput(); err != nil {
		t.Skipf("setfacl failed (file system without ACLs?): %v %s", err, out)
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
