package redact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var testKey = []byte("netguard-test-key")

func TestTokenFormat(t *testing.T) {
	r := New(testKey)
	tok := r.Token("secret")
	if !regexp.MustCompile(`^<redacted:hmac:[0-9a-f]{12}>$`).MatchString(tok) {
		t.Fatalf("bad token %q", tok)
	}
	if tok != r.Token("secret") {
		t.Fatal("token must be deterministic for one key")
	}
	if tok == New([]byte("other")).Token("secret") {
		t.Fatal("token must depend on the key")
	}
	if tok == r.Token("secret2") {
		t.Fatal("different secrets must not collide")
	}
}

func TestRedactSingleLines(t *testing.T) {
	r := New(testKey)
	cases := []struct {
		name   string
		in     string
		rule   string
		secret string
		keep   []string
	}{
		{"cisco type 9", "enable secret 9 $9$abc/def.123", "cisco-password-type", "$9$abc/def.123", []string{"enable secret 9 "}},
		{"cisco type 7 username", "username admin privilege 15 password 7 0822455D0A16", "cisco-password-type", "0822455D0A16", []string{"privilege 15 password 7 "}},
		{"cisco type 14", "username x secret 14 $14$abcdefgh", "cisco-password-type", "$14$abcdefgh", nil},
		{"snmp community keeps ACL", "snmp-server community s3cr3t RO SNMP-ACL", "cisco-snmp-community", "s3cr3t", []string{" RO SNMP-ACL"}},
		{"key-string", "  key-string 7 abc123", "cisco-key-string", "abc123", nil},
		{"tacacs", "tacacs-server key 7 abc123", "cisco-aaa-server-key", "abc123", nil},
		{"radius plain", "radius-server key hunter2", "cisco-aaa-server-key", "hunter2", nil},
		{"bgp neighbor", " neighbor 10.0.0.1 password 7 abc", "cisco-bgp-neighbor-password", "abc", []string{"neighbor 10.0.0.1 password 7 "}},
		{"ospf md5", " ip ospf message-digest-key 1 md5 7 abc", "cisco-ospf-md5", "abc", nil},
		{"nxos snmp user two secrets", "snmp-server user admin network-admin auth md5 0xAAA priv 0xBBB localizedkey", "cisco-snmp-user", "0xAAA", []string{"localizedkey"}},
		{"junos encrypted", `encrypted-password "$6$salt$hash"; ## SECRET-DATA`, "junos-encrypted-password", "$6$salt$hash", []string{"## SECRET-DATA"}},
		{"junos 9", `set system tacplus-server 1.1.1.1 secret "$9$abcDEF"`, "junos-9-hash", "$9$abcDEF", nil},
		{"junos secret-data", `authentication-key "abc def"; ## SECRET-DATA`, "junos-secret-data", "abc def", nil},
		{"junos psk", `pre-shared-key ascii-text "$9$psk"; ## SECRET-DATA`, "ike-pre-shared-key", "$9$psk", nil},
		{"eos sha512", "username admin secret sha512 $6$salt$hash", "eos-secret-sha512", "$6$salt$hash", nil},
		{"panos phash", "set mgt-config users admin phash $1$abc$def", "panos-phash", "$1$abc$def", nil},
		{"panos psk", "set network ike gateway GW authentication pre-shared-key key -AQ==abc", "ike-pre-shared-key", "-AQ==abc", nil},
		{"fortios enc", "        set password ENC AAAAAAAAAAAAAAAAAAAAAAAAAAAA==", "fortios-enc", "AAAAAAAAAAAAAAAAAAAAAAAAAAAA==", []string{"set password ENC "}},
		{"generic colon", "password: hunter2", "generic-keyword", "hunter2", nil},
		{"generic equals", "psk=abc123", "generic-keyword", "abc123", nil},
		{"generic quoted", `community "public"`, "generic-keyword", "public", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, hits := r.Redact(tc.in)
			if len(hits) != 1 || hits[0].RuleID != tc.rule {
				t.Fatalf("hits = %+v, want one hit for %s", hits, tc.rule)
			}
			if strings.Contains(out, tc.secret) {
				t.Errorf("secret survived: %q", out)
			}
			if !strings.Contains(out, r.Token(tc.secret)) {
				t.Errorf("token for secret missing in %q", out)
			}
			for _, k := range tc.keep {
				if !strings.Contains(out, k) {
					t.Errorf("expected %q to survive in %q", k, out)
				}
			}
		})
	}
}

func TestRedactNoFalsePositives(t *testing.T) {
	r := New(testKey)
	lines := []string{
		"service password-encryption",
		"hostname core-rtr-01",
		"interface GigabitEthernet0/0/0",
		" ip address 192.0.2.1 255.255.255.252",
		"aaa authentication login default group tacacs+ local",
		"set type password",
		"key chain ISIS-AUTH",
		" key 1",
		"snmp-server location dfw1-row3",
		"router bgp 65000",
		"!",
		"",
	}
	for _, l := range lines {
		out, hits := r.Redact(l)
		if len(hits) != 0 || out != l {
			t.Errorf("false positive on %q: %q %+v", l, out, hits)
		}
	}
}

func TestRedactIdempotentAndCounts(t *testing.T) {
	r := New(testKey)
	in := "snmp-server community a RO\nsnmp-server community b RW\nenable secret 9 $9$zzz\nnothing here\n"
	out, hits := r.Redact(in)
	want := []Hit{{"cisco-snmp-community", 2}, {"cisco-password-type", 1}}
	if !slices.Equal(hits, want) {
		t.Fatalf("hits %+v, want %+v", hits, want)
	}
	if Count(hits) != 3 {
		t.Fatalf("Count = %d", Count(hits))
	}
	if !strings.HasSuffix(out, "nothing here\n") {
		t.Fatalf("line structure changed: %q", out)
	}
	again, hits2 := r.Redact(out)
	if again != out || len(hits2) != 0 {
		t.Fatalf("second pass changed output: %+v %q", hits2, again)
	}
}

type expectFile struct {
	Platform string   `json:"platform"`
	Rules    []string `json:"rules"`
	Secrets  []string `json:"secrets"`
}

// TestFixtureCorpus runs every tests/fixtures/configs/<name>.txt through the
// redactor and checks its <name>.expect.json: every listed rule fires, no
// listed secret survives, and a second pass is a no-op.
func TestFixtureCorpus(t *testing.T) {
	dir := filepath.Join("..", "..", "tests", "fixtures", "configs")
	fixtures, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) < 6 {
		t.Fatalf("expected at least 6 fixtures in %s, found %d", dir, len(fixtures))
	}
	r := New(testKey)
	for _, fx := range fixtures {
		name := strings.TrimSuffix(filepath.Base(fx), ".txt")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(fx)
			if err != nil {
				t.Fatal(err)
			}
			eb, err := os.ReadFile(filepath.Join(dir, name+".expect.json"))
			if err != nil {
				t.Fatal(err)
			}
			var exp expectFile
			if err := json.Unmarshal(eb, &exp); err != nil {
				t.Fatal(err)
			}
			if len(exp.Rules) == 0 || len(exp.Secrets) == 0 {
				t.Fatal("expect file must list rules and secrets")
			}
			for _, s := range exp.Secrets {
				if !strings.Contains(string(raw), s) {
					t.Errorf("expect file lists secret %q that is not in the fixture", s)
				}
			}
			out, hits := r.Redact(string(raw))
			fired := map[string]bool{}
			for _, h := range hits {
				fired[h.RuleID] = true
			}
			for _, id := range exp.Rules {
				if !fired[id] {
					t.Errorf("rule %s did not fire (fired: %v)", id, RuleIDs(rulesFromHits(hits)))
				}
			}
			for id := range fired {
				if !slices.Contains(exp.Rules, id) {
					t.Errorf("rule %s fired but is not listed in %s.expect.json", id, name)
				}
			}
			for _, s := range exp.Secrets {
				if strings.Contains(out, s) {
					t.Errorf("secret %q survived redaction", s)
				}
			}
			if Count(hits) < len(exp.Secrets) {
				t.Errorf("only %d hits for %d secrets", Count(hits), len(exp.Secrets))
			}
			if strings.Count(out, "\n") != strings.Count(string(raw), "\n") {
				t.Error("line count changed")
			}
			if again, h2 := r.Redact(out); again != out || len(h2) != 0 {
				t.Errorf("second pass not idempotent: %+v", h2)
			}
		})
	}
}

func rulesFromHits(hits []Hit) []Rule {
	out := make([]Rule, len(hits))
	for i, h := range hits {
		out[i] = Rule{ID: h.RuleID}
	}
	return out
}
