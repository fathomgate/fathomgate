// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package audit

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func chmodACL(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("/bin/chmod", args...).CombinedOutput(); err != nil {
		t.Fatalf("chmod %v: %v: %s", args, err, out)
	}
}

// TestDarwinInheritedACLRefused (L2 in the security review of PR #109): in
// a folder whose ACL gives everyone read access to new files, the private
// key and a new log would get mode 0600 and still be readable by others.
// SaveKey and NewWriter refuse and leave no file behind; the public key,
// which is meant to be readable, is written.
func TestDarwinInheritedACLRefused(t *testing.T) {
	dir := t.TempDir()
	chmodACL(t, "+a", "everyone allow read,file_inherit", dir)
	pubKey, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, create := range map[string]func(string) error{
		"key": func(p string) error { return SaveKey(p, priv) },
		"log": func(p string) error {
			w, err := NewWriter(p, Options{})
			if err == nil {
				_ = w.Close()
			}
			return err
		},
	} {
		p := filepath.Join(dir, name)
		err := create(p)
		if err == nil || !strings.Contains(err.Error(), "extended ACL") {
			t.Fatalf("%s: error %v, want an extended ACL refusal", name, err)
		}
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s: left behind after the refusal: %v", name, err)
		}
	}
	pub := filepath.Join(dir, "audit.pub")
	if err := SavePublicKey(pub, pubKey); err != nil {
		t.Fatalf("public key: %v", err)
	}
}

// TestDarwinExistingLogWithACLRefused: an existing log that has an
// extended ACL is refused before anything is changed; restrictOpenFile
// would reset the mode but not the ACL.
func TestDarwinExistingLogWithACLRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	writeChain(t, p, 2, Options{})
	chmodACL(t, "+a", "everyone allow read", p)
	w, err := NewWriter(p, Options{})
	if err == nil {
		_ = w.Close()
		t.Fatal("a log with an extended ACL was reopened")
	}
	if !errors.Is(err, errUnsafeLog) || !strings.Contains(err.Error(), "extended ACL") {
		t.Fatalf("error %v, want errUnsafeLog naming the extended ACL", err)
	}
}
