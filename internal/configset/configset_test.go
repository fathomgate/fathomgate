// SPDX-License-Identifier: FSL-1.1-ALv2

package configset

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoProfile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "profiles", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestEmbeddedProfiles: the embedded set parses, every file is named after
// its server key, and Profiles("") is that set under the name "embedded".
func TestEmbeddedProfiles(t *testing.T) {
	set, source, err := Profiles("")
	if err != nil || source != Embedded || len(set) == 0 {
		t.Fatalf("Profiles(\"\") = %d profiles, %q, %v", len(set), source, err)
	}
	by := ByServer(set)
	for _, p := range set {
		if p.Name != p.Profile.Server+".yaml" || by[p.Profile.Server] != p.Profile {
			t.Errorf("%s holds server %q", p.Name, p.Profile.Server)
		}
	}
}

// TestProfileDir: a directory replaces the embedded set, and what serve
// --profiles refuses is refused: a misnamed file, a *.yml file, a
// subdirectory, a directory with no profile, a file others can change.
func TestProfileDir(t *testing.T) {
	upa := repoProfile(t, "upa.yaml")
	dir := configDir(t)
	write(t, filepath.Join(dir, "upa.yaml"), upa)
	write(t, filepath.Join(dir, "README"), []byte("not a profile"))
	set, source, err := Profiles(dir)
	if err != nil || source != dir || len(set) != 1 || set[0].Profile.Server != "upa" {
		t.Fatalf("Profiles(dir) = %+v, %q, %v", set, source, err)
	}

	refused := map[string]func(d string){
		"misnamed":     func(d string) { write(t, filepath.Join(d, "other.yaml"), upa) },
		"yml":          func(d string) { write(t, filepath.Join(d, "upa.yml"), upa) },
		"subdirectory": func(d string) { _ = os.Mkdir(filepath.Join(d, "sub"), 0o700) },
		"empty":        func(d string) { _ = os.Remove(filepath.Join(d, "upa.yaml")) },
	}
	for name, spoil := range refused {
		d := configDir(t)
		write(t, filepath.Join(d, "upa.yaml"), upa)
		spoil(d)
		if _, err := ProfileDir(d); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}

	letOthersWrite(t, filepath.Join(dir, "upa.yaml"))
	if _, err := ProfileDir(dir); err == nil {
		t.Error("a profile others can change: loaded")
	}
}

// TestProfileFileAt: one profile file is read as ProfileDir reads each of
// its files, including the name check.
func TestProfileFileAt(t *testing.T) {
	dir := configDir(t)
	good := filepath.Join(dir, "upa.yaml")
	write(t, good, repoProfile(t, "upa.yaml"))
	pf, err := ProfileFileAt(good)
	if err != nil || pf.Profile.Server != "upa" || pf.Name != "upa.yaml" {
		t.Fatalf("ProfileFileAt = %+v, %v", pf, err)
	}
	bad := filepath.Join(dir, "eos-mcp.yaml")
	write(t, bad, repoProfile(t, "upa.yaml"))
	if _, err := ProfileFileAt(bad); err == nil || !strings.Contains(err.Error(), "named after its server key, upa.yaml") {
		t.Errorf("misnamed: %v", err)
	}
	if _, err := ProfileFileAt(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("missing file: loaded")
	}
}

// TestReadInventory: a CSV is refused with ErrCSV, a file is read with the
// configfile checks, and a path that is not printable ASCII is quoted in
// the error, never repeated raw (security review of PR #197, L1).
func TestReadInventory(t *testing.T) {
	dir := configDir(t)
	if _, err := ReadInventory(filepath.Join(dir, "devices.CSV")); !errors.Is(err, ErrCSV) {
		t.Errorf("CSV: %v", err)
	}
	inv := filepath.Join(dir, "inv.yaml")
	write(t, inv, []byte("devices:\n  - {name: lab-sw-01, tags: [lab]}\nroles:\n  - match: \"^lab-\"\n    site: lab\n"))
	b, err := ReadInventory(inv)
	if err != nil {
		t.Fatal(err)
	}
	f, chain, err := ParseInventory(b)
	if err != nil || len(f.Devices) != 1 {
		t.Fatalf("ParseInventory: %+v %v", f, err)
	}
	if tg, ok := chain.Resolve("lab-sw-01"); !ok || tg.Site != "lab" {
		t.Errorf("chain: %+v %v", tg, ok)
	}
	if _, _, err := ParseInventory([]byte("version: 1\ndevices: []\n")); err == nil {
		t.Error("a version key: parsed (the decoder has no version field)")
	}

	_, err = ReadInventory(filepath.Join(dir, "no\x1b[31mthere.yaml"))
	if err == nil || strings.ContainsRune(err.Error(), 0x1b) || !strings.Contains(err.Error(), "\\x1b[31m") {
		t.Errorf("path in error: %q", err)
	}
	letOthersWrite(t, inv)
	if _, err := ReadInventory(inv); err == nil {
		t.Error("an inventory others can change: read")
	}
}
