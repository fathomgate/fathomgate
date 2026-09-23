//go:build windows

package audit

import (
	"os"
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
// for the current user and SYSTEM, and (for files NetGuard created) the
// current user as owner. Resuming a log never changes its owner.
func assertOwnerOnly(t *testing.T, path string, checkOwner bool) {
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
	if checkOwner && (sec.owner == nil || !sec.owner.Equals(me)) {
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
	assertOwnerOnly(t, kp, true)
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
	assertOwnerOnly(t, fresh, true)

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
	assertOwnerOnly(t, old, false)
	if rep, err := Verify(old); err != nil || !rep.OK || rep.Events != 3 {
		t.Fatalf("resumed chain %+v, %v", rep, err)
	}
}
