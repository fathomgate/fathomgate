package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Files Fathomgate creates for the audit trail, and how each is protected.
// The OS-specific halves are in key_unix.go and key_windows.go:
//
//	createExclusive(path, flag, ownerOnly) creates path, never following or
//	    replacing an existing entry (fs.ErrExist). ownerOnly: mode 0600 on
//	    Unix, a protected owner-only DACL applied by CreateFile on Windows;
//	    otherwise mode 0644 / the folder's inherited ACL.
//	removeCreated(f, path) deletes the file f was created as, without
//	    deleting whatever else might now be at path.
//	openExistingLog(path) opens an existing log for read and append without
//	    following links, and refuses anything that is not a regular file
//	    with one link owned by the current user (errUnsafeLog).
//	restrictOpenFile(f) resets f to owner-only through the open handle.

// errUnsafeLog is wrapped by every refusal of an existing log path.
var errUnsafeLog = errors.New("audit: refusing existing log")

// NewKey generates an Ed25519 checkpoint signing key.
func NewKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// SaveKey writes the private key as a PKCS#8 PEM file readable by its owner
// only. It never overwrites: an existing path (file, symlink or anything
// else) fails with an error wrapping fs.ErrExist and is left untouched. On
// Unix the file is created with O_EXCL and set to mode 0600 whatever the
// umask; on Windows it is created with a protected DACL that grants the
// current user and SYSTEM only, so it inherits nothing from its folder. A
// failed write deletes the new file through its handle.
func SaveKey(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("audit: marshal key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	f, err := createExclusive(path, os.O_WRONLY, true)
	if err != nil {
		return fmt.Errorf("audit: create key: %w", err)
	}
	if err := fill(f, path, data); err != nil {
		return fmt.Errorf("audit: write key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("audit: write key: %w", err)
	}
	return nil
}

// SavePublicKey writes the public key as a PEM file for verifiers. Like
// SaveKey it never overwrites an existing path, so a verifier's key cannot
// be swapped silently. The file is readable by everyone by design (mode 0644
// on Unix, the folder's inherited ACL on Windows).
func SavePublicKey(path string, pub ed25519.PublicKey) error {
	f, err := createPublicKey(path, pub)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("audit: write public key: %w", err)
	}
	return nil
}

// WriteKeyPair writes the public key to pubPath and then the private key to
// privPath, both exclusively. The public half is written first so a failure
// never leaves a private key without it; if the private key cannot be
// written, the public key file just created is deleted again.
func WriteKeyPair(privPath, pubPath string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	pf, err := createPublicKey(pubPath, pub)
	if err != nil {
		return err
	}
	if err := SaveKey(privPath, priv); err != nil {
		discard(pf, pubPath)
		return err
	}
	if err := pf.Close(); err != nil {
		return fmt.Errorf("audit: write public key: %w", err)
	}
	return nil
}

// createPublicKey creates and fills the public key file and returns it
// still open, so a caller can delete it through the handle.
func createPublicKey(path string, pub ed25519.PublicKey) (*os.File, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("audit: marshal public key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	f, err := createExclusive(path, os.O_WRONLY, false)
	if err != nil {
		return nil, fmt.Errorf("audit: create public key: %w", err)
	}
	if err := fill(f, path, data); err != nil {
		return nil, fmt.Errorf("audit: write public key: %w", err)
	}
	return f, nil
}

// fill writes and syncs data to a file created by createExclusive. On
// failure it deletes the file through f and closes it.
func fill(f *os.File, path string, data []byte) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		discard(f, path)
		return err
	}
	return nil
}

// discard deletes a file created by createExclusive and closes it.
func discard(f *os.File, path string) {
	_ = removeCreated(f, path)
	_ = f.Close()
}

// LoadKey reads a PKCS#8 PEM Ed25519 private key written by SaveKey.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit: read key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("audit: %s: no PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("audit: %s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("audit: %s: not an Ed25519 key", path)
	}
	return priv, nil
}

// LoadPublicKey reads a PEM public key written by SavePublicKey. It also
// accepts a private key file and derives the public half.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit: read public key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("audit: %s: no PEM block", path)
	}
	if block.Type == "PRIVATE KEY" {
		priv, err := LoadKey(path)
		if err != nil {
			return nil, err
		}
		return priv.Public().(ed25519.PublicKey), nil
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("audit: %s: %w", path, err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("audit: %s: not an Ed25519 key", path)
	}
	return pub, nil
}
