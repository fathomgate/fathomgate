package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// TokenPrefix starts every replacement so downstream code (and the console)
// can recognise redacted values.
const TokenPrefix = "<redacted:hmac:"

// Hit counts how many secrets one rule replaced in a single Redact call.
type Hit struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

// Redactor replaces secrets with keyed HMAC tokens.
type Redactor struct {
	// Key is the HMAC key. It must be the same across a deployment for
	// tokens to compare equal, and secret, or tokens become brute-forceable.
	Key []byte
	// Rules is the ordered pattern list; nil means DefaultRules.
	Rules []Rule
}

// New returns a Redactor with the default rules.
func New(key []byte) *Redactor {
	return &Redactor{Key: key, Rules: DefaultRules}
}

// Token returns the replacement for one secret:
// "<redacted:hmac:" + first 12 hex of HMAC-SHA256(key, secret) + ">".
func (r *Redactor) Token(secret string) string {
	mac := hmac.New(sha256.New, r.Key)
	mac.Write([]byte(secret))
	return TokenPrefix + hex.EncodeToString(mac.Sum(nil))[:12] + ">"
}

// Redact processes text line by line. For each line the first rule that
// matches claims it and every occurrence on that line is replaced. It
// returns the redacted text and one Hit per rule that fired, in rule order.
// Already-redacted tokens are never matched again, so Redact is idempotent.
func (r *Redactor) Redact(text string) (string, []Hit) {
	rules := r.Rules
	if rules == nil {
		rules = DefaultRules
	}
	counts := make(map[string]int)
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		for _, rule := range rules {
			out, matched, replaced := r.applyRule(rule, line)
			if matched == 0 {
				continue
			}
			// The first rule whose pattern matches claims the line, even
			// when every secret it found was already a token; otherwise a
			// later, looser rule would redact the leftovers ("secret 9
			// <token>" losing its "9") and Redact would not be idempotent.
			lines[i] = out
			counts[rule.ID] += replaced
			break
		}
	}
	var hits []Hit
	for _, rule := range rules {
		if n := counts[rule.ID]; n > 0 {
			hits = append(hits, Hit{RuleID: rule.ID, Count: n})
		}
	}
	return strings.Join(lines, "\n"), hits
}

// applyRule replaces the secret groups of every match of rule in line. It
// returns the new line, the number of matches whose secret groups were
// non-empty (already-redacted tokens count as matches), and the number of
// secret groups actually replaced.
func (r *Redactor) applyRule(rule Rule, line string) (out string, matched, replaced int) {
	idx := rule.Pattern.FindAllStringSubmatchIndex(line, -1)
	if idx == nil {
		return line, 0, 0
	}
	names := rule.Pattern.SubexpNames()
	var b strings.Builder
	last := 0
	for _, m := range idx {
		hit := false
		for g := 1; g < len(names); g++ {
			if !strings.HasPrefix(names[g], "s") {
				continue
			}
			start, end := m[2*g], m[2*g+1]
			if start < 0 || start < last || start == end {
				continue
			}
			hit = true
			secret := line[start:end]
			if strings.HasPrefix(secret, TokenPrefix) {
				continue
			}
			b.WriteString(line[last:start])
			b.WriteString(r.Token(secret))
			last = end
			replaced++
		}
		if hit {
			matched++
		}
	}
	if replaced == 0 {
		return line, matched, 0
	}
	b.WriteString(line[last:])
	return b.String(), matched, replaced
}

// Count sums the hits.
func Count(hits []Hit) int {
	total := 0
	for _, h := range hits {
		total += h.Count
	}
	return total
}
