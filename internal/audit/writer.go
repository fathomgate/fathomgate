package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"
)

// Options configure a Writer.
type Options struct {
	// CheckpointEvery appends a signed checkpoint after every N events.
	// Zero disables checkpoints.
	CheckpointEvery int
	// Key signs checkpoints. Required when CheckpointEvery > 0.
	Key ed25519.PrivateKey
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Writer appends events to a JSONL file, maintaining the hash chain. It is
// safe for concurrent use. Opening an existing file resumes its chain.
type Writer struct {
	mu       sync.Mutex
	f        *os.File
	opts     Options
	lastSeq  uint64
	lastHash string
}

// NewWriter opens (or creates) the log at path and resumes the chain from
// the last valid line. The log is never truncated.
//
// A new log is created exclusively and owner-only (mode 0600 on Unix, a
// protected owner-only DACL on Windows). An existing log is opened without
// following links and must be a regular file with one link, owned by the
// current user; anything else is refused. Its chain is then verified
// through that same handle, and only if it verifies is the file reset to
// owner-only. NewWriter refuses to append to a chain that does not verify,
// because appending to a broken chain would hide the break behind valid new
// records.
func NewWriter(path string, opts Options) (*Writer, error) {
	if opts.CheckpointEvery > 0 && opts.Key == nil {
		return nil, fmt.Errorf("audit: checkpoints require a signing key")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	f, created, err := openLog(path)
	if err != nil {
		return nil, err
	}
	return resumeLog(f, created, path, opts)
}

// openLog creates the log at path, or opens the existing one after the
// link, type and owner checks. The handle is open for read and append.
func openLog(path string) (f *os.File, created bool, err error) {
	f, err = createExclusive(path, os.O_RDWR|os.O_APPEND, true)
	if err == nil {
		return f, true, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		// Windows reports CREATE_NEW over a directory or junction as
		// access denied, not "exists". Name the reason when the path is
		// something other than a regular file; either way nothing is
		// created or changed.
		if fi, lerr := os.Lstat(path); lerr == nil && !fi.Mode().IsRegular() {
			return nil, false, fmt.Errorf("%w: %s is a symbolic link, junction, directory or other non-regular file (%w)", errUnsafeLog, path, err)
		}
		return nil, false, fmt.Errorf("audit: create log: %w", err)
	}
	f, err = openExistingLog(path)
	if err != nil {
		if errors.Is(err, errUnsafeLog) {
			return nil, false, err
		}
		return nil, false, fmt.Errorf("audit: open log: %w", err)
	}
	return f, false, nil
}

// resumeLog verifies the chain by reading the held handle from the start,
// so a file swapped in at path after openLog is never what gets verified,
// then restricts an existing log to owner-only and returns the Writer. It
// closes f on any failure.
func resumeLog(f *os.File, created bool, path string, opts Options) (*Writer, error) {
	rep, err := VerifyReader(f, nil)
	if err == nil && !rep.OK {
		err = fmt.Errorf("audit: %s: existing chain broken at seq %d: %s", path, rep.BrokenSeq, rep.Problem)
	}
	if err == nil && !created {
		if rerr := restrictOpenFile(f); rerr != nil {
			err = fmt.Errorf("audit: %s: restrict to owner: %w", path, rerr)
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Writer{f: f, opts: opts, lastSeq: rep.LastSeq, lastHash: rep.LastHash}, nil
}

// Append assigns seq, ts, event_id, prev_hash and hash, writes the event as
// one JSON line, and writes a checkpoint when due. On success ev holds the
// assigned integrity fields.
func (w *Writer) Append(ev *Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	ev.Type = TypeEvent
	ev.Seq = w.lastSeq + 1
	if ev.TS == "" {
		ev.TS = w.opts.Now().UTC().Format(time.RFC3339Nano)
	}
	if ev.EventID == "" {
		id, err := randomID()
		if err != nil {
			return err
		}
		ev.EventID = id
	}
	// Keep arrays non-null so consumers never see "targets": null.
	if ev.Targets == nil {
		ev.Targets = []string{}
	}
	if ev.Roles == nil {
		ev.Roles = []string{}
	}
	if ev.Obligations == nil {
		ev.Obligations = []string{}
	}
	hash, err := HashEvent(ev, w.lastHash)
	if err != nil {
		return err
	}
	ev.Hash = hash
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	if _, err := w.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	w.lastSeq, w.lastHash = ev.Seq, ev.Hash

	if every := w.opts.CheckpointEvery; every > 0 && ev.Seq%uint64(every) == 0 {
		cp, err := SignCheckpoint(w.opts.Key, w.lastSeq, w.lastHash)
		if err != nil {
			return err
		}
		cl, err := json.Marshal(cp)
		if err != nil {
			return fmt.Errorf("audit: marshal checkpoint: %w", err)
		}
		if _, err := w.f.Write(append(cl, '\n')); err != nil {
			return fmt.Errorf("audit: write checkpoint: %w", err)
		}
	}
	return nil
}

// Seq returns the sequence number of the last event written.
func (w *Writer) Seq() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastSeq
}

// Hash returns the hash of the last event written, or GenesisHash.
func (w *Writer) Hash() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastHash
}

// Close syncs and closes the file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.f.Sync(); err != nil {
		_ = w.f.Close()
		return err
	}
	return w.f.Close()
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("audit: random id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
