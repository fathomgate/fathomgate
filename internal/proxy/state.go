package proxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// A stateless (2026-07-28) agent answers an upstream's input request by
// re-sending the tools/call with inputResponses and the requestState it was
// given. The agent is untrusted, so the requestState the proxy hands out is
// not the upstream's: it is an envelope sealed with AES-256-GCM under a key
// that never leaves the process. The upstream's own state and the binding
// (server, tool, arguments, outstanding input request ids, round, expiry)
// are inside the ciphertext, so the agent can neither read nor change them.
// See docs/specs/profile-schema.md section 8.4.

const (
	// statePrefix starts every requestState netguard issues; it versions
	// the envelope format and is authenticated as additional data.
	statePrefix = "ng2."
	// maxRequestState caps the upstream's requestState (untrusted) before
	// netguard tries to seal it.
	maxRequestState = 64 << 10
	// maxSealedState caps a requestState netguard issues and, from the same
	// constant, one it accepts: seal refuses to issue a longer one, so
	// everything seal issues, open can open. JSON escaping and base64 make
	// the sealed form larger than the upstream's state, by up to about
	// eight times for escape-heavy text, so this is checked after sealing.
	maxSealedState = 96 << 10
	// stateTTL bounds how long an issued requestState is accepted. It covers
	// a human answering a prompt, not a parked approval (that is M3).
	stateTTL = 30 * time.Minute
	// maxInputRounds bounds how many times one call may ask for input, in
	// either era, matching go-sdk's own client limit.
	maxInputRounds = 10
)

// sealedState is the encrypted content of a requestState netguard issues.
type sealedState struct {
	Server  string   `json:"s"`           // upstream server name (prefix)
	Tool    string   `json:"t"`           // unprefixed upstream tool
	Args    string   `json:"a"`           // argsDigest of the call's arguments
	IDs     []string `json:"i"`           // input request ids the upstream asked for
	Up      string   `json:"u,omitempty"` // the upstream's requestState, verbatim
	Round   int      `json:"r"`           // input rounds so far in this call
	Prompts int      `json:"p"`           // prompts put to the human so far in this call
	Exp     int64    `json:"e"`           // expiry, Unix seconds
}

// Reasons a requestState is refused. They are shown to the agent.
var (
	errStateMalformed = errors.New("requestState was not issued by netguard")
	errStateAuth      = errors.New("requestState does not verify")
	errStateExpired   = errors.New("requestState has expired; call the tool again without it")
	errStateTooLarge  = errors.New("the sealed requestState would exceed the size netguard accepts")
)

// sealer issues and opens requestState envelopes. The key is random per
// process, so a restart invalidates every outstanding state; the agent then
// starts the call again, as the spec allows.
type sealer struct {
	aead cipher.AEAD
	now  func() time.Time
}

// newSealer returns a sealer with a fresh random AES-256-GCM key and the
// real clock.
func newSealer() (*sealer, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("proxy: requestState key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("proxy: requestState cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("proxy: requestState cipher: %w", err)
	}
	return &sealer{aead: aead, now: time.Now}, nil
}

// seal returns the requestState for st, with its expiry set from now. It
// fails with errStateTooLarge rather than issue a state open would refuse.
func (s *sealer) seal(st sealedState) (string, error) {
	st.Exp = s.now().Add(stateTTL).Unix()
	plain, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("proxy: marshal requestState: %w", err)
	}
	nonce := make([]byte, s.aead.NonceSize(), s.aead.NonceSize()+len(plain)+s.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("proxy: requestState nonce: %w", err)
	}
	sealed := s.aead.Seal(nonce, nonce, plain, []byte(statePrefix))
	out := statePrefix + base64.RawURLEncoding.EncodeToString(sealed)
	if len(out) > maxSealedState {
		return "", errStateTooLarge
	}
	return out, nil
}

// open decrypts and authenticates a requestState and checks its expiry; the
// caller checks the binding.
func (s *sealer) open(state string) (sealedState, error) {
	var st sealedState
	if len(state) > maxSealedState {
		return st, errStateMalformed
	}
	body, ok := strings.CutPrefix(state, statePrefix)
	if !ok {
		return st, errStateMalformed
	}
	sealed, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || len(sealed) < s.aead.NonceSize()+s.aead.Overhead() {
		return st, errStateMalformed
	}
	n := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, sealed[:n], sealed[n:], []byte(statePrefix))
	if err != nil {
		return st, errStateAuth
	}
	if err := json.Unmarshal(plain, &st); err != nil {
		return st, errStateMalformed
	}
	if s.now().Unix() > st.Exp {
		return st, errStateExpired
	}
	return st, nil
}

// argsDigest identifies a call's arguments across MRTR rounds. It hashes the
// arguments as sent, with insignificant whitespace removed, so key order and
// duplicate keys count: a retry that changes what the upstream would parse
// changes the digest. Absent and null arguments are "{}", which is what
// go-sdk sends for none.
func argsDigest(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		raw = json.RawMessage("{}")
	}
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		b.Reset()
		b.Write(raw)
	}
	sum := sha256.Sum256(b.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
