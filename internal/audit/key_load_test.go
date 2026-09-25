// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fathomgate/fathomgate/internal/secretfile"
)

// ADR 0028: keygen writes a pair that LoadKey accepts as it is, with no
// change to the private key file.
func TestKeygenOutputPassesLoadKey(t *testing.T) {
	pub, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	kp, pp := filepath.Join(dir, "audit.key"), filepath.Join(dir, "audit.key.pub")
	if err := WriteKeyPair(kp, pp, pub, priv); err != nil {
		t.Fatal(err)
	}
	got, err := LoadKey(kp)
	if err != nil {
		t.Fatalf("LoadKey of a key keygen wrote: %v", err)
	}
	if !got.Equal(priv) {
		t.Fatal("loaded key differs")
	}
	if p, err := LoadPublicKey(pp); err != nil || !p.Equal(pub) {
		t.Fatalf("LoadPublicKey of the .pub keygen wrote: %v", err)
	}
}

// ADR 0028: LoadPublicKey accepts one PUBLIC KEY block and nothing else;
// any private key block is ErrPrivateKey.
func TestLoadPublicKeyRefusesPrivateKey(t *testing.T) {
	pub, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block := func(typ string, b []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}))
	}
	dir := t.TempDir()
	for _, tc := range []struct {
		name, content string
		want          error  // matched with errors.Is
		wantText      string // or a substring; "" with want nil accepts
	}{
		{"public key", block("PUBLIC KEY", pkix), nil, ""},
		{"pkcs8 private key", block("PRIVATE KEY", pkcs8), ErrPrivateKey, ""},
		{"encrypted private key", block("ENCRYPTED PRIVATE KEY", pkcs8), ErrPrivateKey, ""},
		{"openssh private key", block("OPENSSH PRIVATE KEY", pkcs8), ErrPrivateKey, ""},
		{"private key after the public key", block("PUBLIC KEY", pkix) + block("PRIVATE KEY", pkcs8), nil, "more than the one PEM block"},
		{"certificate", block("CERTIFICATE", pkix), nil, "not a PUBLIC KEY PEM block"},
		{"no PEM", "not a key\n", nil, "no PEM block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
			if err := os.WriteFile(p, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := LoadPublicKey(p)
			switch {
			case tc.want == nil && tc.wantText == "":
				if err != nil || !got.Equal(pub) {
					t.Fatalf("err = %v", err)
				}
			case tc.want != nil:
				if !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
			default:
				if err == nil || !strings.Contains(err.Error(), tc.wantText) {
					t.Fatalf("err = %v, want %q", err, tc.wantText)
				}
			}
			if err != nil && strings.Contains(err.Error(), "MC4CAQ") {
				t.Fatalf("the error quotes the key: %v", err)
			}
		})
	}
}

// assertKeyRefused checks a LoadKey refusal: it matches
// secretfile.ErrUnsafe, names the path and the check, and quotes nothing
// of the key.
func assertKeyRefused(t *testing.T, path, want string) {
	t.Helper()
	_, err := LoadKey(path)
	if err == nil {
		t.Fatalf("LoadKey(%s) accepted the key; want a refusal naming %q", filepath.Base(path), want)
	}
	if !errors.Is(err, secretfile.ErrUnsafe) {
		t.Errorf("err = %v, want secretfile.ErrUnsafe", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, want) {
		t.Errorf("err = %v, want %q", err, want)
	}
	if !strings.Contains(msg, path) {
		t.Errorf("err = %v does not name the path %s", err, path)
	}
	if strings.Contains(msg, "BEGIN") || strings.Contains(msg, "MC4CAQ") {
		t.Errorf("the error quotes the key: %v", err)
	}
}

// saveTestKey writes an owner-only key with SaveKey and returns its path.
func saveTestKey(t *testing.T, dir, name string) string {
	t.Helper()
	_, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := SaveKey(p, priv); err != nil {
		t.Fatal(err)
	}
	return p
}

// A second hard link to the key is refused through either name: another
// user who can link the file into a directory they control keeps it.
func TestLoadKeyRefusesHardLink(t *testing.T) {
	dir := t.TempDir()
	kp := saveTestKey(t, dir, "audit.key")
	link := filepath.Join(dir, "linked.key")
	if err := os.Link(kp, link); err != nil {
		t.Fatal(err)
	}
	assertKeyRefused(t, kp, "2 hard links")
	assertKeyRefused(t, link, "2 hard links")
}

// A missing key is an error, but not a refusal of an unsafe file.
func TestLoadKeyMissing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "absent.key")
	_, err := LoadKey(p)
	if err == nil || errors.Is(err, secretfile.ErrUnsafe) {
		t.Fatalf("err = %v, want an open error that is not secretfile.ErrUnsafe", err)
	}
	if !strings.Contains(err.Error(), "cannot open the signing key "+p) {
		t.Fatalf("err = %v, want it to name the key", err)
	}
}
