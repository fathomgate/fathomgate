// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/fathomgate/fathomgate/internal/secretfile"
)

// Files Fathomgate creates for the audit trail, and how each is protected.
// The OS-specific halves are in key_unix.go and key_windows.go:
//
//	createExclusive(path, flag, ownerOnly) creates path, never following or
//	    replacing an existing entry (fs.ErrExist). ownerOnly: mode 0600 on
//	    Unix, and refused (and deleted) if it inherited an extended ACL on
//	    macOS; a protected owner-only DACL applied by CreateFile on Windows;
//	    otherwise mode 0644 / the folder's inherited ACL.
//	removeCreated(f, path) deletes the file f was created as, without
//	    deleting whatever else might now be at path.
//	openExistingLog(path) opens an existing log for read and append without
//	    following links, and refuses anything that is not a regular file
//	    with one link owned by the current user, or (macOS) that has an
//	    extended ACL (errUnsafeLog).
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

// maxKeyFileBytes caps what LoadKey and LoadPublicKey read. A PEM Ed25519
// key is under 200 bytes.
const maxKeyFileBytes = 16 << 10

// ErrPrivateKey is returned by LoadPublicKey for a file that contains a
// private key, or the text "PRIVATE KEY" anywhere: a verifier never needs,
// and is never handed, the signing key.
var ErrPrivateKey = errors.New("audit: a private key where a public key is required")

// LoadKey reads a PKCS#8 PEM Ed25519 private key written by SaveKey,
// refusing a file another user could read or replace (ADR 0028): it is
// opened without following a final symbolic link or reparse point, and must
// be a regular file with one link, owned by the current user, with no group
// or other permission bits (0600 or 0400) and no macOS extended ACL on
// Unix, or a protected DACL granting only the owner and SYSTEM on Windows.
// The checks run on the open file (internal/secretfile); a refusal matches
// secretfile.ErrUnsafe and names the path and the check, never the content.
// There is no way to skip them.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	b, err := secretfile.Read(path, "the signing key "+path, maxKeyFileBytes)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	block, err := onePEMBlock(path, b)
	if err != nil {
		return nil, err
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("audit: %s: not a PKCS#8 PRIVATE KEY PEM block", path)
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

// LoadPublicKey reads a PEM Ed25519 public key written by SavePublicKey.
// The file must be a regular file (checked on the open file, which is
// opened without blocking, so a FIFO cannot hang the verifier) of at most
// 16 KiB. If the text "PRIVATE KEY" appears anywhere in it, before, inside
// or after a PEM block, it is refused with an error matching ErrPrivateKey
// before anything is decoded. Otherwise it must hold exactly one PEM block,
// of type PUBLIC KEY, with nothing but white space around it. The public
// key is not secret, so its owner and mode are not checked; that it is the
// right key is for the operator to establish.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	f, err := openPublicKey(path)
	if err != nil {
		return nil, fmt.Errorf("audit: read public key: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("audit: read public key: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("audit: %s: not a regular file (%v); not a public key", path, fi.Mode().Type())
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("audit: read public key: %w", err)
	}
	if len(b) > maxKeyFileBytes {
		return nil, fmt.Errorf("audit: %s: larger than %d bytes; not a public key", path, maxKeyFileBytes)
	}
	// Before decoding: pem.Decode skips text it cannot parse, so a private
	// key (or a corrupted one) ahead of the public block would otherwise
	// pass unseen.
	if bytes.Contains(b, []byte("PRIVATE KEY")) {
		return nil, fmt.Errorf("%w: %s", ErrPrivateKey, path)
	}
	block, err := onePEMBlock(path, b)
	if err != nil {
		return nil, err
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("audit: %s: not a PUBLIC KEY PEM block", path)
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

// pemBegin starts every PEM block.
var pemBegin = []byte("-----BEGIN ")

// onePEMBlock decodes the single PEM block a key file holds. The file must
// contain "-----BEGIN " exactly once, with only white space before it and
// after the block's END line, and the block must have no headers. pem.Decode alone would skip anything it
// cannot parse, before the block or as a corrupted first block, so a file
// could carry text or a second key the reader never looks at.
func onePEMBlock(path string, b []byte) (*pem.Block, error) {
	switch n := bytes.Count(b, pemBegin); {
	case n == 0:
		return nil, fmt.Errorf("audit: %s: no PEM block", path)
	case n > 1:
		return nil, fmt.Errorf("audit: %s: more than the one PEM block of a key", path)
	}
	i := bytes.Index(b, pemBegin)
	if len(bytes.TrimSpace(b[:i])) != 0 {
		return nil, fmt.Errorf("audit: %s: text before the PEM block", path)
	}
	block, rest := pem.Decode(b[i:])
	if block == nil {
		return nil, fmt.Errorf("audit: %s: the PEM block is malformed", path)
	}
	// A header (for example "Comment: <base64>") could carry another key
	// the reader never looks at; key files have none.
	if len(block.Headers) != 0 {
		return nil, fmt.Errorf("audit: %s: the PEM block has headers; a key file has none", path)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("audit: %s: text after the PEM block", path)
	}
	return block, nil
}
