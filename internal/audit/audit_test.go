package audit

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sampleEvent(i int) *Event {
	return &Event{
		Principal:   "josh",
		SessionID:   "sess-1",
		Server:      "netdev-ssh-mcp",
		Tool:        "run_show_command",
		Class:       "READ_OPERATIONAL",
		ArgsSHA256:  strings.Repeat("ab", 32),
		Targets:     []string{"core-rtr-01"},
		Roles:       []string{"core"},
		Decision:    "allow",
		RuleID:      "reads-anywhere",
		Obligations: []string{},
		Status:      "ok",
		DurationMS:  int64(10 + i),
		Redactions:  i,
	}
}

func writeChain(t *testing.T, path string, n int, opts Options) []Event {
	t.Helper()
	w, err := NewWriter(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	var out []Event
	for i := 1; i <= n; i++ {
		ev := sampleEvent(i)
		if err := w.Append(ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, *ev)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCanonical(t *testing.T) {
	a, err := Canonical(map[string]any{"b": 1, "a": []any{"x", map[string]any{"z": true, "y": nil}}, "c": "<&>"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":["x",{"y":null,"z":true}],"b":1,"c":"<&>"}`
	if string(a) != want {
		t.Fatalf("canonical = %s, want %s", a, want)
	}
	// Large integers must survive without float rounding.
	b, err := Canonical(map[string]uint64{"seq": 9007199254740993})
	if err != nil || string(b) != `{"seq":9007199254740993}` {
		t.Fatalf("canonical big int = %s, %v", b, err)
	}
}

func TestChainWritesAndVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	fixed := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	events := writeChain(t, path, 5, Options{Now: func() time.Time { return fixed }})

	if events[0].PrevHash != GenesisHash || events[0].Seq != 1 {
		t.Fatalf("first event %+v", events[0])
	}
	for i := 1; i < len(events); i++ {
		if events[i].PrevHash != events[i-1].Hash {
			t.Fatalf("event %d prev_hash mismatch", i+1)
		}
		if events[i].Seq != uint64(i+1) {
			t.Fatalf("event %d seq %d", i+1, events[i].Seq)
		}
	}
	if events[0].TS != "2026-09-23T12:00:00Z" || len(events[0].EventID) != 32 {
		t.Fatalf("ts/id not filled: %+v", events[0])
	}

	rep, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Events != 5 || rep.LastSeq != 5 || rep.LastHash != events[4].Hash {
		t.Fatalf("report %+v", rep)
	}

	// Resume the chain in a second writer.
	w, err := NewWriter(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ev := sampleEvent(6)
	if err := w.Append(ev); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if ev.Seq != 6 || ev.PrevHash != events[4].Hash {
		t.Fatalf("resumed event %+v", ev)
	}
	rep, _ = Verify(path)
	if !rep.OK || rep.Events != 6 {
		t.Fatalf("after resume %+v", rep)
	}
}

func TestVerifyMissingFileIsEmptyChain(t *testing.T) {
	rep, err := Verify(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err != nil || !rep.OK || rep.Events != 0 || rep.LastHash != GenesisHash {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestTamperDetectedAtRightSeq(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeChain(t, path, 6, Options{})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected 6 lines, got %d", len(lines))
	}

	cases := []struct {
		name   string
		mutate func([]string) []string
		seq    uint64
		msg    string
	}{
		{
			name: "edited field",
			mutate: func(l []string) []string {
				l[2] = strings.Replace(l[2], `"decision":"allow"`, `"decision":"deny"`, 1)
				return l
			},
			seq: 3, msg: "record altered",
		},
		{
			name:   "deleted line",
			mutate: func(l []string) []string { return append(l[:3], l[4:]...) },
			seq:    5, msg: "seq 5, expected 4",
		},
		{
			name:   "reordered lines",
			mutate: func(l []string) []string { l[1], l[2] = l[2], l[1]; return l },
			seq:    3, msg: "seq 3, expected 2",
		},
		{
			name:   "duplicated line",
			mutate: func(l []string) []string { return append(l[:3], append([]string{l[2]}, l[3:]...)...) },
			seq:    3, msg: "seq 3, expected 4",
		},
		{
			name:   "garbage line",
			mutate: func(l []string) []string { l[4] = "not json"; return l },
			seq:    5, msg: "not JSON",
		},
		{
			name:   "truncated tail is still valid",
			mutate: func(l []string) []string { return l[:4] },
			seq:    0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mutate(append([]string(nil), lines...))
			p := filepath.Join(t.TempDir(), "t.jsonl")
			if err := os.WriteFile(p, []byte(strings.Join(mutated, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			rep, err := Verify(p)
			if err != nil {
				t.Fatal(err)
			}
			if tc.seq == 0 {
				if !rep.OK {
					t.Fatalf("expected OK, got %+v", rep)
				}
				return
			}
			if rep.OK || rep.BrokenSeq != tc.seq || !strings.Contains(rep.Problem, tc.msg) {
				t.Fatalf("report %+v, want broken at %d with %q", rep, tc.seq, tc.msg)
			}
			// A writer must refuse to extend a broken chain.
			if _, err := NewWriter(p, Options{}); err == nil {
				t.Fatal("NewWriter should refuse a broken chain")
			}
		})
	}
}

func TestCheckpointsSignedAndVerified(t *testing.T) {
	pub, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeChain(t, path, 7, Options{CheckpointEvery: 3, Key: priv})

	raw, _ := os.ReadFile(path)
	var cps int
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		if strings.Contains(sc.Text(), `"type":"checkpoint"`) {
			cps++
		}
	}
	if cps != 2 {
		t.Fatalf("expected 2 checkpoint lines, got %d", cps)
	}

	rep, err := VerifyWithKey(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Checkpoints != 2 || rep.Events != 7 || !rep.SignaturesChecked {
		t.Fatalf("report %+v", rep)
	}

	// Wrong key fails at the first checkpoint.
	otherPub, _, _ := NewKey()
	rep, _ = VerifyWithKey(path, otherPub)
	if rep.OK || rep.BrokenSeq != 3 || !strings.Contains(rep.Problem, "signature") {
		t.Fatalf("wrong key report %+v", rep)
	}

	// Rewriting the chain and re-signing without the key: the attacker can
	// fix hashes but not signatures.
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	lines[0] = strings.Replace(lines[0], `"decision":"allow"`, `"decision":"deny"`, 1)
	p2 := filepath.Join(t.TempDir(), "rewritten.jsonl")
	if err := os.WriteFile(p2, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _ = Verify(p2)
	if rep.OK || rep.BrokenSeq != 1 {
		t.Fatalf("rewritten report %+v", rep)
	}

	// A checkpoint whose hash disagrees with the chain is caught without a key.
	lines = strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	for i, l := range lines {
		if strings.Contains(l, `"type":"checkpoint"`) {
			lines[i] = strings.Replace(l, `"hash":"`, `"hash":"f`, 1)
			break
		}
	}
	p3 := filepath.Join(t.TempDir(), "badcp.jsonl")
	if err := os.WriteFile(p3, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _ = Verify(p3)
	if rep.OK || rep.BrokenSeq != 3 || !strings.Contains(rep.Problem, "checkpoint hash") {
		t.Fatalf("bad checkpoint report %+v", rep)
	}
}

func TestKeyRoundTrip(t *testing.T) {
	pub, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	kp := filepath.Join(dir, "audit.key")
	if err := SaveKey(kp, priv); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(kp)
	if err != nil {
		t.Fatal(err)
	}
	// Windows ignores Unix permission bits (ACLs govern access), so assert 0600 on Unix only.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", info.Mode().Perm())
	}
	loaded, err := LoadKey(kp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, priv) {
		t.Fatal("loaded key differs")
	}
	pp := filepath.Join(dir, "audit.pub")
	if err := SavePublicKey(pp, pub); err != nil {
		t.Fatal(err)
	}
	lp, err := LoadPublicKey(pp)
	if err != nil || !bytes.Equal(lp, pub) {
		t.Fatalf("public key round trip: %v", err)
	}
	fromPriv, err := LoadPublicKey(kp)
	if err != nil || !bytes.Equal(fromPriv, pub) {
		t.Fatalf("public from private: %v", err)
	}
	if _, err := LoadKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing key should error")
	}
	if err := os.WriteFile(filepath.Join(dir, "junk"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(filepath.Join(dir, "junk")); err == nil {
		t.Fatal("junk key should error")
	}
}

func TestWriterRequiresKeyForCheckpoints(t *testing.T) {
	if _, err := NewWriter(filepath.Join(t.TempDir(), "a.jsonl"), Options{CheckpointEvery: 2}); err == nil {
		t.Fatal("expected error")
	}
}
