// SPDX-License-Identifier: FSL-1.1-ALv2

package inventory

import (
	"strings"
	"testing"
)

// TestParseFileErrorsQuoteNoFileContent: an inventory that does not load
// is never echoed (security review of PR #171, M1: a device password in
// the file reached stderr), and a second YAML document is refused (L3).
func TestParseFileErrorsQuoteNoFileContent(t *testing.T) {
	const canary = "FAKE-canary-inventory-3310"
	for _, in := range []string{
		"devices:\n  - {name: a, role: core, password: " + canary + "}\n",
		"devices:\n  - name: a\n    mgmt_pass: " + canary + "\n",
		"devices:\n  - {name: a, tags: " + canary + "}\n",
		"devices:\n  - {name: \"" + canary + "\n",
		"devices: [{name: a}]\n---\ndevices: [{name: " + canary + "}]\n",
	} {
		_, err := ParseFile([]byte(in))
		if err == nil {
			t.Fatalf("no error for %q", in)
		}
		if strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), "\n") {
			t.Fatalf("error quotes the file: %q", err)
		}
	}
}
