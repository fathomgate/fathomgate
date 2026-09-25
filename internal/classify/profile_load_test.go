// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"strings"
	"testing"
)

// TestParseProfileErrorsQuoteNoFileContent: a profile that does not load
// is never echoed (security review of PR #171, M1), and a second YAML
// document is refused (L3).
func TestParseProfileErrorsQuoteNoFileContent(t *testing.T) {
	const canary = "FAKE-canary-profile-9043"
	for _, in := range []string{
		"server: s\n# key " + canary + "\ntools:\n  t: {class: READ_CONFIG, args: [], bogus: 1}\n",
		"server: s\ntools:\n  t: {class: " + canary + ", args: []}\n",
		"server: s\ntools:\n  t: {class: READ_CONFIG, args: " + canary + "}\n",
		"server: s\ntools:\n  t: {class: READ_CONFIG, args: []}\n---\nserver: " + canary + "\n",
	} {
		_, err := ParseProfile([]byte(in))
		if err == nil {
			t.Fatalf("no error for %q", in)
		}
		if strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), "\n") {
			t.Fatalf("error quotes the file: %q", err)
		}
	}
}
