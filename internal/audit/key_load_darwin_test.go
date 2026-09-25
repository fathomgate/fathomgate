// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package audit

import "testing"

// ADR 0028 on macOS: a key with mode 0600 but an extended ACL entry is
// refused; the mode does not show the access the ACL grants. Removing the
// entry makes it loadable again.
func TestLoadKeyDarwinRefusesExtendedACL(t *testing.T) {
	p := saveTestKey(t, t.TempDir(), "audit.key")
	chmodACL(t, "+a", "everyone allow read", p)
	assertKeyRefused(t, p, "has an extended ACL")
	chmodACL(t, "-N", p)
	if _, err := LoadKey(p); err != nil {
		t.Fatalf("after chmod -N: %v", err)
	}
}
