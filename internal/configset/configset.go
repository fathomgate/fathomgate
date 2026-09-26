// SPDX-License-Identifier: FSL-1.1-ALv2

// Package configset loads the profile set and the inventory the gate
// decides with, the one way fathomgate serve loads them (ADR 0027), so that
// fathomgate policy test proves what serve enforces (ADR 0035). A file serve
// would refuse is refused here with the same checks: internal/configfile's
// owner and write-permission rules on a --profiles directory, every profile
// file in it and an inventory file; strict decoding; each profile file named
// after its server key.
package configset

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/configfile"
	"github.com/fathomgate/fathomgate/internal/inventory"
	"github.com/fathomgate/fathomgate/internal/termsafe"
	"github.com/fathomgate/fathomgate/profiles"
)

// MaxFile is the size cap, in bytes, on each file configset reads (a
// profile, an inventory). serve applies the same cap to the policy file, and
// policy test to a test file and its policy.
const MaxFile = 16 << 20

// Embedded is the source name of the profiles built into the binary.
const Embedded = "embedded"

// ProfileFile is one parsed profile and where it came from.
type ProfileFile struct {
	// Name is the file name without a directory: <server>.yaml.
	Name string
	// Sum is the SHA-256 of the file's bytes.
	Sum [sha256.Size]byte
	// Profile is the parsed, validated profile.
	Profile *classify.Profile
}

// EmbeddedProfiles parses the profiles built into the binary.
func EmbeddedProfiles() ([]ProfileFile, error) {
	fsys := profiles.FS()
	return loadProfiles(fsys, "", func(name string) ([]byte, error) { return fs.ReadFile(fsys, name) })
}

// ProfileDir parses the set in dir, as serve --profiles does: every *.yaml
// file at the top of dir. The directory and every profile file pass the
// configfile integrity checks. A subdirectory or a *.yml file is refused
// rather than skipped (it would look loaded), and a directory with no
// profile is an error: an empty set would deny every call that carries
// arguments.
func ProfileDir(dir string) ([]ProfileFile, error) {
	if err := configfile.CheckDir(dir, "the profiles directory "+termsafe.Quote(dir)); err != nil {
		return nil, err
	}
	set, err := loadProfiles(os.DirFS(dir), dir, func(name string) ([]byte, error) {
		p := filepath.Join(dir, name)
		return configfile.Read(p, "the profile "+termsafe.Quote(p), MaxFile)
	})
	if err != nil {
		return nil, err
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("%s holds no *.yaml profile", termsafe.Quote(dir))
	}
	return set, nil
}

// ProfileFileAt reads one profile file as ProfileDir reads each of its
// files: the configfile checks, the size cap, strict decoding and Validate,
// and the file named after its server key. fathomgate policy eval --profile
// uses it, so the profile it decides with is one serve would load.
func ProfileFileAt(path string) (ProfileFile, error) {
	shown := termsafe.Quote(path)
	b, err := configfile.Read(path, "the profile "+shown, MaxFile)
	if err != nil {
		return ProfileFile{}, err
	}
	p, err := classify.ParseProfile(b)
	if err != nil {
		return ProfileFile{}, fmt.Errorf("%s: %w", shown, err)
	}
	name := filepath.Base(path)
	if want := p.Server + ".yaml"; name != want {
		return ProfileFile{}, fmt.Errorf("%s defines server %q; a profile file is named after its server key, %s", shown, p.Server, want)
	}
	return ProfileFile{Name: name, Sum: sha256.Sum256(b), Profile: p}, nil
}

// Profiles returns the embedded set when dir is empty and the set in dir
// otherwise (it replaces the embedded set, never merges with it), with the
// source name serve logs: Embedded or dir.
func Profiles(dir string) (set []ProfileFile, source string, err error) {
	if dir == "" {
		set, err = EmbeddedProfiles()
		if err != nil {
			return nil, Embedded, fmt.Errorf("embedded profiles: %w", err)
		}
		return set, Embedded, nil
	}
	set, err = ProfileDir(dir)
	return set, dir, err
}

// ByServer maps each profile's server key to the profile.
func ByServer(set []ProfileFile) map[string]*classify.Profile {
	out := make(map[string]*classify.Profile, len(set)+1)
	for _, p := range set {
		out[p.Profile.Server] = p.Profile
	}
	return out
}

// loadProfiles parses every *.yaml file at the top of fsys, in name order:
// strict decoding and Validate (classify.ParseProfile). Each file must be
// named after its server key (<server>.yaml), so the file that classified
// a tool is never in doubt. dir prefixes file names in errors; read reads
// one file by name.
func loadProfiles(fsys fs.FS, dir string, read func(name string) ([]byte, error)) ([]ProfileFile, error) {
	shown := func(name string) string {
		if dir == "" {
			return termsafe.Quote(name)
		}
		return termsafe.Quote(filepath.Join(dir, name))
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", shown("."), err)
	}
	out := make([]ProfileFile, 0, len(entries))
	seen := map[string]string{}
	for _, e := range entries { // ReadDir sorts by name
		name := e.Name()
		switch {
		case e.IsDir():
			return nil, fmt.Errorf("%s is a directory; profiles are read from the top level only, so move it out", shown(name))
		case strings.HasSuffix(name, ".yml"):
			return nil, fmt.Errorf("%s: profiles are named <server>.yaml; rename it", shown(name))
		case !strings.HasSuffix(name, ".yaml"):
			continue // LICENSE, README and the like
		}
		b, err := read(name)
		if err != nil {
			return nil, err
		}
		p, err := classify.ParseProfile(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", shown(name), err)
		}
		if want := p.Server + ".yaml"; name != want {
			return nil, fmt.Errorf("%s defines server %q; a profile file is named after its server key, %s", shown(name), p.Server, want)
		}
		if first, dup := seen[p.Server]; dup {
			return nil, fmt.Errorf("%s and %s both define server %q", shown(first), shown(name), p.Server)
		}
		seen[p.Server] = name
		out = append(out, ProfileFile{Name: name, Sum: sha256.Sum256(b), Profile: p})
	}
	return out, nil
}

// ErrCSV is returned by ReadInventory for a *.csv path: serve reads no CSV.
var ErrCSV = errors.New("takes an inventory.yaml; convert a CSV first with fathomgate inventory import --csv <file> --out inventory.yaml")

// ReadInventory reads an inventory file as serve --inventory does: a *.csv
// path is refused (ErrCSV), and the file passes the configfile checks and
// the size cap. It returns the bytes; ParseInventory decodes them.
func ReadInventory(path string) ([]byte, error) {
	if strings.EqualFold(filepath.Ext(path), ".csv") {
		return nil, ErrCSV
	}
	return configfile.Read(path, "the inventory file "+termsafe.Quote(path), MaxFile)
}

// ParseInventory decodes an inventory document and builds its chain: the
// static devices as the name authority, the hostname patterns as the
// enricher (ADR 0031).
func ParseInventory(b []byte) (*inventory.File, inventory.Chain, error) {
	f, err := inventory.ParseFile(b)
	if err != nil {
		return nil, inventory.Chain{}, err
	}
	chain, err := f.Chain()
	if err != nil {
		return nil, inventory.Chain{}, err
	}
	return f, chain, nil
}
