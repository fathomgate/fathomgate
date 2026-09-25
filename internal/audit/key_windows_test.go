// SPDX-License-Identifier: Apache-2.0

//go:build windows

package audit

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

type aceInfo struct {
	sid       *windows.SID
	typ       uint8
	inherited bool
}

type fileSecurity struct {
	protected bool
	owner     *windows.SID
	aces      []aceInfo
}

// readSecurity reads back the owner and DACL of path from the file system.
func readSecurity(t *testing.T, path string) fileSecurity {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo %s: %v", path, err)
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil {
		t.Fatalf("%s: NULL DACL grants everyone full access", path)
	}
	fs := fileSecurity{protected: ctrl&windows.SE_DACL_PROTECTED != 0, owner: owner}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		fs.aces = append(fs.aces, aceInfo{
			sid:       (*windows.SID)(unsafe.Pointer(&ace.SidStart)),
			typ:       ace.Header.AceType,
			inherited: ace.Header.AceFlags&windows.INHERITED_ACE != 0,
		})
	}
	return fs
}

func wellKnown(t *testing.T, k windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	s, err := windows.CreateWellKnownSid(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func currentUser(t *testing.T) *windows.SID {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid
}

// assertOwnerOnly checks the T0.12 guarantee: a protected DACL, no inherited
// ACEs, no Everyone / Users / Authenticated Users entries, only allow ACEs
// for the current user and SYSTEM, and the current user as owner.
func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()
	me := currentUser(t)
	system := wellKnown(t, windows.WinLocalSystemSid)
	forbidden := map[string]*windows.SID{
		"Everyone":            wellKnown(t, windows.WinWorldSid),
		"BUILTIN\\Users":      wellKnown(t, windows.WinBuiltinUsersSid),
		"Authenticated Users": wellKnown(t, windows.WinAuthenticatedUserSid),
	}
	sec := readSecurity(t, path)
	if !sec.protected {
		t.Errorf("%s: DACL is not protected (SE_DACL_PROTECTED unset)", filepath.Base(path))
	}
	if sec.owner == nil || !sec.owner.Equals(me) {
		t.Errorf("%s: owner %v, want current user %v", filepath.Base(path), sec.owner, me)
	}
	if len(sec.aces) == 0 {
		t.Errorf("%s: empty DACL; the owner could not read its own file", filepath.Base(path))
	}
	for _, a := range sec.aces {
		if a.inherited {
			t.Errorf("%s: inherited ACE for %v", filepath.Base(path), a.sid)
		}
		for name, s := range forbidden {
			if a.sid.Equals(s) {
				t.Errorf("%s: ACE for %s (%v)", filepath.Base(path), name, a.sid)
			}
		}
		if a.typ != windows.ACCESS_ALLOWED_ACE_TYPE || (!a.sid.Equals(me) && !a.sid.Equals(system)) {
			t.Errorf("%s: unexpected ACE type %d for %v", filepath.Base(path), a.typ, a.sid)
		}
	}
}

// looseDir returns a temp directory whose inheritable DACL also grants read
// to Everyone, BUILTIN\Users and Authenticated Users, like C:\ProgramData
// does, so an unprotected file created in it would inherit those entries.
func looseDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	me := currentUser(t).String()
	sd, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;" + me + ")(A;OICI;FA;;;SY)(A;OICI;FR;;;WD)(A;OICI;FR;;;BU)(A;OICI;FR;;;AU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	// Sanity: a file created the ordinary way inherits the loose entries,
	// so assertOwnerOnly has something to catch.
	plain := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	users := wellKnown(t, windows.WinBuiltinUsersSid)
	found := false
	for _, a := range readSecurity(t, plain).aces {
		if a.inherited && a.sid.Equals(users) {
			found = true
		}
	}
	if !found {
		t.Fatal("setup: a plain file in the loose directory did not inherit BUILTIN\\Users")
	}
	return dir
}

func TestSaveKeyWindowsDACL(t *testing.T) {
	_, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	kp := filepath.Join(looseDir(t), "audit.key")
	if err := SaveKey(kp, priv); err != nil {
		t.Fatal(err)
	}
	assertOwnerOnly(t, kp)
	loaded, err := LoadKey(kp)
	if err != nil {
		t.Fatalf("owner cannot read its own key: %v", err)
	}
	if !loaded.Equal(priv) {
		t.Fatal("loaded key differs")
	}
}

func TestWriterWindowsDACL(t *testing.T) {
	dir := looseDir(t)

	// A log NewWriter creates is owner-only from the start.
	fresh := filepath.Join(dir, "new.jsonl")
	writeChain(t, fresh, 2, Options{})
	assertOwnerOnly(t, fresh)

	// An existing log that inherited the loose folder ACL is corrected on
	// resume, and its chain continues.
	old := filepath.Join(dir, "old.jsonl")
	b, err := os.ReadFile(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if sec := readSecurity(t, old); sec.protected {
		t.Fatal("setup: the copied log should start with an inherited DACL")
	}
	w, err := NewWriter(old, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(sampleEvent(3)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	assertOwnerOnly(t, old)
	if rep, err := Verify(old); err != nil || !rep.OK || rep.Events != 3 {
		t.Fatalf("resumed chain %+v, %v", rep, err)
	}
}

// looseLog writes a valid two-event chain into dir, where it inherits the
// loose folder ACL, and returns its path.
func looseLog(t *testing.T, dir, name string) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src.jsonl")
	writeChain(t, src, 2, Options{})
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if readSecurity(t, p).protected {
		t.Fatal("setup: the loose log should start with an inherited DACL")
	}
	return p
}

// assertUntouched fails if the file's DACL was made protected, which is
// what restrictOpenFile would have done.
func assertUntouched(t *testing.T, path string) {
	t.Helper()
	if readSecurity(t, path).protected {
		t.Fatalf("%s: DACL was changed", filepath.Base(path))
	}
}

// requirePrivilegedEnv makes privilege-dependent tests fail instead of skip.
// The windows-latest CI job sets it, so those tests cannot pass silently.
const requirePrivilegedEnv = "FATHOMGATE_REQUIRE_PRIVILEGED_TESTS"

// needPrivilege skips the test, or fails it when requirePrivilegedEnv=1.
func needPrivilege(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv(requirePrivilegedEnv) == "1" {
		t.Fatalf(requirePrivilegedEnv+"=1 but the test cannot run: "+format, args...)
	}
	t.Skipf(format, args...)
}

// symlinkOrSkip creates a file symlink, or skips / fails via needPrivilege.
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		needPrivilege(t, "creating a symlink needs SeCreateSymbolicLinkPrivilege (Developer Mode or admin): %v", err)
	}
}

// H1: a symlink at the log path is opened as itself and refused; its
// target's DACL is not changed.
func TestNewWriterWindowsRefusesSymlink(t *testing.T) {
	dir := looseDir(t)
	target := looseLog(t, dir, "target.jsonl")
	link := filepath.Join(dir, "audit.jsonl")
	symlinkOrSkip(t, target, link)
	if _, err := NewWriter(link, Options{}); !errors.Is(err, errUnsafeLog) {
		t.Fatalf("err = %v, want errUnsafeLog", err)
	}
	assertUntouched(t, target)
}

// H1: a junction (mount point) at the log path is refused and its target
// directory's DACL is not changed. Junctions need no privilege.
func TestNewWriterWindowsRefusesJunction(t *testing.T) {
	dir := looseDir(t)
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "audit.jsonl")
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		needPrivilege(t, "mklink /J: %v: %s", err, out)
	}
	_, err = NewWriter(link, Options{})
	if !errors.Is(err, errUnsafeLog) {
		t.Fatalf("err = %v, want errUnsafeLog", err)
	}
	t.Logf("junction refused: %v", err)
	assertUntouched(t, target)
}

// M1 (round 2): a dangling symlink at the key, public key or log path must
// not be followed. CREATE_NEW without FILE_FLAG_OPEN_REPARSE_POINT would
// create the file at the link's target, a place the attacker chose.
func TestWindowsDanglingSymlinkNotFollowed(t *testing.T) {
	pub, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		create func(path string) error
		want   error
	}{
		{"key", func(p string) error { return SaveKey(p, priv) }, fs.ErrExist},
		{"pub", func(p string) error { return SavePublicKey(p, pub) }, fs.ErrExist},
		{"log", func(p string) error {
			w, err := NewWriter(p, Options{})
			if err == nil {
				_ = w.Close()
			}
			return err
		}, errUnsafeLog},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "attacker-chosen")
			link := filepath.Join(dir, "audit."+tc.name)
			symlinkOrSkip(t, target, link)
			if err := tc.create(link); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("file created at the symlink target: %v", err)
			}
		})
	}
}

// H1: a hard link is refused and the shared file's DACL is not changed.
func TestNewWriterWindowsHardLinkKeepsDACL(t *testing.T) {
	dir := looseDir(t)
	orig := looseLog(t, dir, "orig.jsonl")
	link := filepath.Join(dir, "audit.jsonl")
	if err := os.Link(orig, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWriter(link, Options{}); !errors.Is(err, errUnsafeLog) {
		t.Fatalf("err = %v, want errUnsafeLog", err)
	}
	assertUntouched(t, orig)
}

// Q2: the DACL changes only after the chain verifies.
func TestNewWriterWindowsBrokenChainKeepsDACL(t *testing.T) {
	p := filepath.Join(looseDir(t), "audit.jsonl")
	if err := os.WriteFile(p, []byte("not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWriter(p, Options{}); err == nil {
		t.Fatal("NewWriter should refuse a broken chain")
	}
	assertUntouched(t, p)
}

// H2: a log owned by another SID is refused. Giving a file another owner
// needs elevation (SeRestorePrivilege, or membership of an owner-capable
// group such as Administrators), so this skips when run unelevated unless
// requirePrivilegedEnv=1.
func TestNewWriterWindowsRefusesOtherOwner(t *testing.T) {
	p := looseLog(t, looseDir(t), "audit.jsonl")
	admins := wellKnown(t, windows.WinBuiltinAdministratorsSid)
	if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
		needPrivilege(t, "cannot give the file another owner without elevation: %v", err)
	}
	if _, err := NewWriter(p, Options{}); !errors.Is(err, errUnsafeLog) {
		t.Fatalf("err = %v, want errUnsafeLog", err)
	}
	assertUntouched(t, p)
}
