package proxy

import (
	"encoding/json"
	"errors"
	"reflect"
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

func TestSealer(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	s := testSealer(t, now)
	st := sealedState{Server: "s", Tool: "t", Args: argsDigest(json.RawMessage(`{"a":1}`)), IDs: []string{"otp", "pw"}, Up: "FAKE-up-state", Round: 2}
	token := s.seal(st)
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

	payload, sig, _ := strings.Cut(strings.TrimPrefix(token, statePrefix), ".")
	flipped := []byte(payload)
	flipped[0] ^= 1
	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"empty", "", errStateMalformed},
		{"not ours", "FAKE-up-state", errStateMalformed},
		{"prefix only", statePrefix, errStateMalformed},
		{"no signature", statePrefix + payload, errStateMalformed},
		{"signature not base64", statePrefix + payload + ".!!", errStateMalformed},
		{"payload edited", statePrefix + string(flipped) + "." + sig, errStateSignature},
		{"signature cut", statePrefix + payload + "." + sig[:10], errStateSignature},
		{"oversized", statePrefix + strings.Repeat("A", maxRequestState+200) + "." + sig, errStateMalformed},
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
