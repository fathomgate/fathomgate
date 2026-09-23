package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// Report is the result of replaying a log.
type Report struct {
	// Events and Checkpoints count the lines seen before any break.
	Events      int    `json:"events"`
	Checkpoints int    `json:"checkpoints"`
	LastSeq     uint64 `json:"last_seq"`
	LastHash    string `json:"last_hash"`
	// OK is true when the whole file verifies.
	OK bool `json:"ok"`
	// BrokenSeq is the sequence number at which verification failed: the
	// seq the bad event claims, or the checkpoint's seq, or the next
	// expected seq for an unparseable line. Zero when OK.
	BrokenSeq uint64 `json:"broken_seq,omitempty"`
	// Problem describes the failure in one line.
	Problem string `json:"problem,omitempty"`
	// SignaturesChecked is true when a public key was supplied.
	SignaturesChecked bool `json:"signatures_checked"`
}

// Verify replays the chain in the file at path. Checkpoint hashes are
// checked against the chain; signatures are not verified because no key is
// given. A missing file is an empty, valid chain. I/O errors are returned;
// chain breaks are reported in the Report.
func Verify(path string) (Report, error) {
	return verifyFile(path, nil, true)
}

// VerifyWithKey is Verify plus Ed25519 signature checks on every checkpoint.
func VerifyWithKey(path string, pub ed25519.PublicKey) (Report, error) {
	return verifyFile(path, pub, true)
}

// VerifyReader replays a chain from r.
func VerifyReader(r io.Reader, pub ed25519.PublicKey) (Report, error) {
	rep := Report{LastHash: GenesisHash, OK: true, SignaturesChecked: pub != nil}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if problem := verifyLine(&rep, line, pub); problem != "" {
			rep.OK = false
			rep.Problem = fmt.Sprintf("line %d: %s", lineNo, problem)
			return rep, nil
		}
	}
	if err := sc.Err(); err != nil {
		return rep, fmt.Errorf("audit: read: %w", err)
	}
	return rep, nil
}

func verifyFile(path string, pub ed25519.PublicKey, missingOK bool) (Report, error) {
	f, err := os.Open(path)
	if err != nil {
		if missingOK && errors.Is(err, os.ErrNotExist) {
			return Report{LastHash: GenesisHash, OK: true, SignaturesChecked: pub != nil}, nil
		}
		return Report{}, fmt.Errorf("audit: open: %w", err)
	}
	defer f.Close()
	return VerifyReader(f, pub)
}

// verifyLine checks one line against the running state in rep and advances
// it. It returns a non-empty problem string on failure and sets BrokenSeq.
func verifyLine(rep *Report, line []byte, pub ed25519.PublicKey) string {
	var head struct {
		Type string `json:"type"`
		Seq  uint64 `json:"seq"`
	}
	if err := json.Unmarshal(line, &head); err != nil {
		rep.BrokenSeq = rep.LastSeq + 1
		return fmt.Sprintf("not JSON: %v", err)
	}
	switch head.Type {
	case TypeCheckpoint:
		var cp Checkpoint
		if err := json.Unmarshal(line, &cp); err != nil {
			rep.BrokenSeq = head.Seq
			return fmt.Sprintf("bad checkpoint: %v", err)
		}
		rep.BrokenSeq = cp.Seq
		if cp.Seq != rep.LastSeq {
			return fmt.Sprintf("checkpoint seq %d but chain is at %d", cp.Seq, rep.LastSeq)
		}
		if cp.Hash != rep.LastHash {
			return fmt.Sprintf("checkpoint hash %s does not match chain hash %s", short(cp.Hash), short(rep.LastHash))
		}
		if pub != nil {
			if err := VerifyCheckpoint(pub, cp); err != nil {
				return err.Error()
			}
		}
		rep.Checkpoints++
		rep.BrokenSeq = 0
		return ""
	case TypeEvent, "event", "":
		var ev Event
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&ev); err != nil {
			rep.BrokenSeq = head.Seq
			return fmt.Sprintf("bad event: %v", err)
		}
		rep.BrokenSeq = ev.Seq
		if ev.Seq != rep.LastSeq+1 {
			return fmt.Sprintf("seq %d, expected %d", ev.Seq, rep.LastSeq+1)
		}
		if ev.PrevHash != rep.LastHash {
			return fmt.Sprintf("prev_hash %s does not match previous hash %s", short(ev.PrevHash), short(rep.LastHash))
		}
		claimed := ev.Hash
		want, err := HashEvent(&ev, rep.LastHash)
		if err != nil {
			return fmt.Sprintf("cannot hash: %v", err)
		}
		if claimed != want {
			return fmt.Sprintf("hash %s does not match computed %s (record altered)", short(claimed), short(want))
		}
		rep.Events++
		rep.LastSeq, rep.LastHash = ev.Seq, claimed
		rep.BrokenSeq = 0
		return ""
	default:
		rep.BrokenSeq = rep.LastSeq + 1
		return fmt.Sprintf("unknown line type %q", head.Type)
	}
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12] + "…"
	}
	if h == "" {
		return "(empty)"
	}
	return h
}
