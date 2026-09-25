// SPDX-License-Identifier: FSL-1.1-ALv2

package policy

import (
	"strings"
	"testing"
)

// TestParseErrorsQuoteNoFileContent: a policy that does not load is never
// echoed to stderr (security review of PR #171, M1), and a second YAML
// document is refused (L3).
func TestParseErrorsQuoteNoFileContent(t *testing.T) {
	const canary = "FAKE-canary-policy-5521"
	for _, in := range []string{
		"version: 1\n# password " + canary + "\nrules:\n  - {id: r, effect: allow, matchh: {}}\n",
		"version: " + canary + "\nrules: []\n",
		"version: 1\ndefaults: {unknown_target: " + canary + "}\nrules:\n  - {id: r, effect: deny}\n",
		"version: 1\nrules:\n  - id: r\n    effect: deny\n    reason: \"" + canary + "\n",
		"version: 1\nrules:\n  - {id: r, effect: deny}\n---\nversion: 1\nrules:\n  - {id: " + canary + ", effect: allow}\n",
	} {
		_, err := Parse([]byte(in))
		if err == nil {
			t.Fatalf("no error for %q", in)
		}
		if strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), "\n") {
			t.Fatalf("error quotes the file: %q", err)
		}
	}
	if _, err := Parse([]byte("version: 1\nrules:\n  - {id: r, effect: deny}\n---\nversion: 1\n")); err == nil || !strings.Contains(err.Error(), "2 YAML documents") {
		t.Fatalf("second document: %v", err)
	}
}
