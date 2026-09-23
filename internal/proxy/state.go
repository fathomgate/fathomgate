package proxy

import (
	"bytes"
	"crypto/hmac"
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
// not the upstream's: it is a sealed envelope that binds the upstream's own
// state to the server, tool, arguments and input request ids it was issued
// for, signed with a key that never leaves the process. See
// docs/specs/profile-schema.md section 8.4.

const (
	// statePrefix starts every requestState netguard issues; it versions
	// the envelope format.
	statePrefix = "ng1."
	// maxRequestState caps a requestState in either direction: the
	// upstream's (untrusted, carried inside the envelope) and the agent's.
	maxRequestState = 64 << 10
	// stateTTL bounds how long an issued requestState is accepted. It covers
	// a human answering a prompt, not a parked approval (that is M3).
	stateTTL = 30 * time.Minute
	// maxInputRounds bounds how many times one call may ask for input,
	// matching go-sdk's own client limit.
	maxInputRounds = 10
)

// sealedState is the signed content of a requestState netguard issues.
type sealedState struct {
	Server string   `json:"s"`           // upstream server name (prefix)
	Tool   string   `json:"t"`           // unprefixed upstream tool
	Args   string   `json:"a"`           // argsDigest of the call's arguments
	IDs    []string `json:"i"`           // input request ids the upstream asked for
	Up     string   `json:"u,omitempty"` // the upstream's requestState, verbatim
	Round  int      `json:"r"`           // input rounds so far in this call
	Exp    int64    `json:"e"`           // expiry, Unix seconds
}

// Reasons a requestState is refused. They are shown to the agent.
var (
	errStateMalformed = errors.New("requestState was not issued by netguard")
	errStateSignature = errors.New("requestState signature does not verify")
	errStateExpired   = errors.New("requestState has expired; call the tool again without it")
)

// sealer issues and verifies requestState envelopes. The key is random per
// process, so a restart invalidates every outstanding state; the agent then
// starts the call again, as the spec allows.
type sealer struct {
	key []byte
	now func() time.Time
}

func newSealer() (*sealer, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("proxy: requestState key: %w", err)
	}
	return &sealer{key: key, now: time.Now}, nil
}

func (s *sealer) mac(payload string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(statePrefix))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// seal returns the requestState for st, with its expiry set from now.
func (s *sealer) seal(st sealedState) string {
	st.Exp = s.now().Add(stateTTL).Unix()
	raw, err := json.Marshal(st)
	if err != nil {
		// sealedState holds only strings and ints.
		panic(fmt.Sprintf("proxy: marshal requestState: %v", err))
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return statePrefix + payload + "." + base64.RawURLEncoding.EncodeToString(s.mac(payload))
}

// open verifies a requestState and returns its content. It checks the
// format, the signature and the expiry; the caller checks the binding.
func (s *sealer) open(state string) (sealedState, error) {
	var st sealedState
	if len(state) > maxRequestState+len(statePrefix)+128 {
		return st, errStateMalformed
	}
	rest, ok := strings.CutPrefix(state, statePrefix)
	if !ok {
		return st, errStateMalformed
	}
	payload, sig, ok := strings.Cut(rest, ".")
	if !ok {
		return st, errStateMalformed
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return st, errStateMalformed
	}
	if !hmac.Equal(got, s.mac(payload)) {
		return st, errStateSignature
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return st, errStateMalformed
	}
	if err := json.Unmarshal(raw, &st); err != nil {
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
