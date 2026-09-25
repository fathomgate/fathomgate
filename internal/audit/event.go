// SPDX-License-Identifier: FSL-1.1-ALv2

package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// GenesisHash is the prev_hash of the first event in a log.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Line types written to the JSONL file. Tool-call records are "call" to
// match docs/specs/audit-event-schema.md; the verifier also accepts the
// older "event" spelling and a missing type.
const (
	TypeEvent      = "call"
	TypeCheckpoint = "checkpoint"
)

// Event is one audit record. Field names are the console's meta labels
// lowercased, so a screenshot and a log line describe one event in one
// vocabulary.
type Event struct {
	// Type is "call" for tool-call records; checkpoints use Checkpoint.
	Type string `json:"type"`
	// EventID is a random identifier, filled by the Writer if empty.
	EventID string `json:"event_id"`
	// Seq is the 1-based position in the chain, assigned by the Writer.
	Seq uint64 `json:"seq"`
	// TS is an RFC 3339 timestamp, filled by the Writer if empty.
	TS string `json:"ts"`

	// Who.
	Principal string `json:"principal"`
	SessionID string `json:"session_id"`

	// What.
	Server     string `json:"server"`
	Tool       string `json:"tool"`
	Class      string `json:"class"`
	ArgsSHA256 string `json:"args_sha256"`

	// Where.
	Targets []string `json:"targets"`
	Roles   []string `json:"roles"`

	// Policy.
	Decision    string   `json:"decision"`
	RuleID      string   `json:"rule_id"`
	Reason      string   `json:"reason,omitempty"`
	Obligations []string `json:"obligations"`

	// Approval, when the call was held.
	Approval *ApprovalRef `json:"approval,omitempty"`

	// Outcome.
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	Redactions int    `json:"redactions"`

	// Integrity.
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash,omitempty"`
}

// ApprovalRef identifies who approved a held call and through which channel
// (cli, webhook, mrtr).
type ApprovalRef struct {
	ID       string `json:"id"`
	Approver string `json:"approver"`
	Channel  string `json:"channel"`
}

// Checkpoint is a signed statement that the chain had hash Hash at seq Seq.
type Checkpoint struct {
	Type string `json:"type"`
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
	// Sig is the base64 Ed25519 signature over canonical({type,seq,hash}).
	Sig string `json:"sig,omitempty"`
}

// Canonical returns compact JSON with object keys sorted recursively and no
// HTML escaping, so the same value always hashes the same. Numbers keep
// their source text.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeScalar(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case json.Number:
		buf.WriteString(t.String())
	default:
		return writeScalar(buf, t)
	}
	return nil
}

func writeScalar(buf *bytes.Buffer, v any) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("audit: canonical: %w", err)
	}
	// Encoder appends a newline; drop it.
	buf.Truncate(buf.Len() - 1)
	return nil
}
