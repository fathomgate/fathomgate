package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// HashEvent computes the chain hash for ev given the previous hash:
// sha256(canonical(event with hash cleared) + prev_hash), hex encoded.
// ev.PrevHash is set to prevHash before hashing so the field and the input
// agree.
func HashEvent(ev *Event, prevHash string) (string, error) {
	ev.PrevHash = prevHash
	ev.Hash = ""
	if ev.Type == "" {
		ev.Type = TypeEvent
	}
	c, err := Canonical(ev)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(c, []byte(prevHash)...))
	return hex.EncodeToString(sum[:]), nil
}

// checkpointMessage is the byte string a checkpoint signature covers.
func checkpointMessage(seq uint64, hash string) ([]byte, error) {
	return Canonical(Checkpoint{Type: TypeCheckpoint, Seq: seq, Hash: hash})
}

// SignCheckpoint builds a signed checkpoint for the chain state (seq, hash).
func SignCheckpoint(priv ed25519.PrivateKey, seq uint64, hash string) (Checkpoint, error) {
	msg, err := checkpointMessage(seq, hash)
	if err != nil {
		return Checkpoint{}, err
	}
	sig := ed25519.Sign(priv, msg)
	return Checkpoint{Type: TypeCheckpoint, Seq: seq, Hash: hash, Sig: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyCheckpoint checks cp's signature with pub.
func VerifyCheckpoint(pub ed25519.PublicKey, cp Checkpoint) error {
	if cp.Sig == "" {
		return fmt.Errorf("audit: checkpoint at seq %d has no signature", cp.Seq)
	}
	sig, err := base64.StdEncoding.DecodeString(cp.Sig)
	if err != nil {
		return fmt.Errorf("audit: checkpoint at seq %d: bad signature encoding: %w", cp.Seq, err)
	}
	msg, err := checkpointMessage(cp.Seq, cp.Hash)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("audit: checkpoint at seq %d: signature does not verify", cp.Seq)
	}
	return nil
}
