package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func testSealer(t *testing.T, now time.Time) *sealer {
	t.Helper()
	s, err := newSealer()
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }
	return s
}

func mustSeal(t *testing.T, s *sealer, st sealedState) string {
	t.Helper()
	token, err := s.seal(st)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestSealer(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	s := testSealer(t, now)
	st := sealedState{Server: "s", Tool: "t", Args: argsDigest(json.RawMessage(`{"a":1}`)), IDs: []string{"otp", "pw"}, Up: "FAKE-up-state-secret", Round: 2}
	token := mustSeal(t, s, st)
	if !strings.HasPrefix(token, statePrefix) {
		t.Fatalf("token %q lacks prefix", token)
	}
	got, err := s.open(token)
	if err != nil {
		t.Fatal(err)
	}
	st.Exp = now.Add(stateTTL).Unix()
	if !reflect.DeepEqual(got, st) {
		t.Fatalf("open = %+v, want %+v", got, st)
	}

	// The agent cannot read the upstream's state or the binding.
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, statePrefix))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"FAKE-up-state-secret", `"s":"s"`, "otp"} {
		if bytes.Contains(raw, []byte(secret)) || strings.Contains(token, secret) {
			t.Errorf("sealed state reveals %q", secret)
		}
	}
	// Sealing twice gives two different tokens (random nonce).
	if again := mustSeal(t, s, st); again == token {
		t.Error("two seals of the same state are identical")
	}

	body := strings.TrimPrefix(token, statePrefix)
	edited := bytes.Clone(raw)
	edited[len(edited)/2] ^= 1
	flipped := base64.RawURLEncoding.EncodeToString(edited)
	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"empty", "", errStateMalformed},
		{"not ours", "FAKE-up-state", errStateMalformed},
		{"old format", "ng1." + body, errStateMalformed},
		{"prefix only", statePrefix, errStateMalformed},
		{"not base64", statePrefix + "!!", errStateMalformed},
		{"too short", statePrefix + "AAAA", errStateMalformed},
		{"ciphertext edited", statePrefix + flipped, errStateSignature},
		{"truncated", statePrefix + body[:len(body)-4], errStateSignature},
		{"oversized", statePrefix + strings.Repeat("A", maxSealedState), errStateMalformed},
	}
	for _, tc := range cases {
		if _, err := s.open(tc.token); !errors.Is(err, tc.want) {
			t.Errorf("%s: open error %v, want %v", tc.name, err, tc.want)
		}
	}

	// Another process (another key) cannot open it.
	if _, err := testSealer(t, now).open(token); !errors.Is(err, errStateSignature) {
		t.Errorf("foreign key: %v", err)
	}

	// Valid up to the TTL, expired after it.
	s.now = func() time.Time { return now.Add(stateTTL) }
	if _, err := s.open(token); err != nil {
		t.Errorf("at TTL: %v", err)
	}
	s.now = func() time.Time { return now.Add(stateTTL + time.Second) }
	if _, err := s.open(token); !errors.Is(err, errStateExpired) {
		t.Errorf("after TTL: %v", err)
	}
}

// TestSealLimit: seal never issues a state open refuses. For each kind of
// upstream state, find the longest one that seals; it must open, and one
// byte more must be refused by seal itself.
func TestSealLimit(t *testing.T) {
	s := testSealer(t, time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC))
	base := sealedState{Server: testServer, Tool: "ask", Args: argsDigest(nil), IDs: []string{"pw"}, Round: 1}
	kinds := []struct {
		name string
		unit string
	}{
		{"plain text", "a"},
		{"HTML-escaped", "<"},
		{"control characters", "\x01"},
		{"multibyte", "\xe2\x82\xac"},
	}
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			sealN := func(n int) (string, error) {
				st := base
				st.Up = strings.Repeat(k.unit, n)
				return s.seal(st)
			}
			// Largest n that seals, by binary search over repeat counts.
			n := sort.Search(maxSealedState, func(n int) bool {
				_, err := sealN(n)
				return err != nil
			}) - 1
			if n < 1 {
				t.Fatalf("nothing seals")
			}
			at, err := sealN(n)
			if err != nil {
				t.Fatalf("at limit (%d units): %v", n, err)
			}
			if len(at) > maxSealedState {
				t.Fatalf("issued %d bytes, cap %d", len(at), maxSealedState)
			}
			if _, err := s.open(at); err != nil {
				t.Fatalf("open refuses what seal issued at the limit (%d bytes): %v", len(at), err)
			}
			if _, err := sealN(n + 1); !errors.Is(err, errStateTooLarge) {
				t.Fatalf("limit+1: %v, want errStateTooLarge", err)
			}
		})
	}
	// The cap on the upstream's own state is below what always seals for
	// plain text, so a plain 64 KiB state is carried.
	st := base
	st.Up = strings.Repeat("a", maxRequestState)
	if _, err := s.seal(st); err != nil {
		t.Fatalf("plain state at maxRequestState: %v", err)
	}
}

func TestArgsDigest(t *testing.T) {
	same := [][2]string{
		{``, `{}`},
		{`null`, `{}`},
		{`{ "host" : "lab-sw-01" }`, `{"host":"lab-sw-01"}`},
	}
	for _, p := range same {
		if argsDigest(json.RawMessage(p[0])) != argsDigest(json.RawMessage(p[1])) {
			t.Errorf("%q and %q should share a digest", p[0], p[1])
		}
	}
	// Anything that could change what the upstream parses changes the digest.
	differ := [][2]string{
		{`{"host":"lab-sw-01"}`, `{"host":"core-rtr-01"}`},
		{`{"a":1,"b":2}`, `{"b":2,"a":1}`},
		{`{"host":"lab-sw-01"}`, `{"host":"core-rtr-01","host":"lab-sw-01"}`},
		{`{}`, `{"x":null}`},
	}
	for _, p := range differ {
		if argsDigest(json.RawMessage(p[0])) == argsDigest(json.RawMessage(p[1])) {
			t.Errorf("%q and %q should differ", p[0], p[1])
		}
	}
}
