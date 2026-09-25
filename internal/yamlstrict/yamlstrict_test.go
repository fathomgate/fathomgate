// SPDX-License-Identifier: FSL-1.1-ALv2

package yamlstrict

import (
	"strings"
	"testing"
)

type doc struct {
	Version  int               `yaml:"version"`
	Name     string            `yaml:"name"`
	Devices  []map[string]any  `yaml:"devices"`
	Settings map[string]string `yaml:"settings"`
}

// TestNoFileContentInErrors: every decode error keeps the file's values
// out of its text (security review of PR #171, M1). The canary sits beside
// or inside the fault.
func TestNoFileContentInErrors(t *testing.T) {
	const canary = "FAKE-canary-pw-7731"
	for _, tc := range []struct {
		name, in, want string
	}{
		{"unknown key beside a secret", "name: a\nsettings: {password: " + canary + "}\nbogus: 1\n", "unknown field"},
		{"unknown key on the secret's line", "name: a\n" + canary + ": 1\n", ""},
		{"unknown key is the secret", "name: a\nFAKEcanary7731: 1\n", ""},
		{"type error on the secret", "version: " + canary + "\n", ""},
		{"type error, quoted secret", "version: \"" + canary + "\"\n", ""},
		{"syntax error after the secret", "settings:\n  password: " + canary + "\n  - x\n", ""},
		{"unterminated quote", "name: \"" + canary + "\n", ""},
		{"tab indentation", "settings:\n\tpassword: " + canary + "\n", ""},
		{"second document", "name: a\n---\nname: " + canary + "\n", "2 YAML documents"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d doc
			err := Unmarshal([]byte(tc.in), &d)
			if err == nil {
				t.Fatal("no error")
			}
			if strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), "7731") {
				t.Fatalf("error quotes the file: %q", err)
			}
			if strings.Contains(err.Error(), "\n") {
				t.Fatalf("error spans lines: %q", err)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q lacks %q", err, tc.want)
			}
		})
	}
}

func TestUnmarshal(t *testing.T) {
	for _, in := range []string{"name: a\n", "---\nname: a\n", "name: a\n---\n", "# c\n---\nname: a\n"} {
		var d doc
		if err := Unmarshal([]byte(in), &d); err != nil || d.Name != "a" {
			t.Errorf("%q: %v %+v", in, err, d)
		}
	}
	var d doc
	err := Unmarshal([]byte("name: a\nnamex: b\n"), &d)
	if err == nil || !strings.Contains(err.Error(), `unknown field "namex"`) || !strings.HasPrefix(err.Error(), "[2:1]") {
		t.Errorf("unknown key: %v", err)
	}
}
