package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// NewKey generates an Ed25519 checkpoint signing key.
func NewKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// SaveKey writes the private key as a PKCS#8 PEM file readable by its owner
// only. It never overwrites: an existing path fails with an error wrapping
// fs.ErrExist and the file is left untouched. On Unix the file is created
// with O_EXCL and set to mode 0600 whatever the umask; on Windows it is
// created with a protected DACL that grants the current user and SYSTEM
// only, so it inherits nothing from its folder (key_unix.go, key_windows.go).
func SaveKey(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("audit: marshal key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	f, err := createOwnerOnly(path, os.O_WRONLY)
	if err != nil {
		return fmt.Errorf("audit: create key: %w", err)
	}
	_, werr := f.Write(pem.EncodeToMemory(block))
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		// The file is ours (created exclusively above); do not leave a
		// truncated key behind.
		_ = os.Remove(path)
		return fmt.Errorf("audit: write key: %w", werr)
	}
	return nil
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

// SavePublicKey writes the public key as a PEM file for verifiers.
func SavePublicKey(path string, pub ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("audit: marshal public key: %w", err)
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644) //nolint:gosec // public key; world-readable by design
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
