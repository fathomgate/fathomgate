// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"fmt"
	"strings"
)

// Class is the network-semantic class of a tool call. The string values are
// the exact spellings used in policy files, profiles and audit events.
type Class string

// The closed set of classes. See docs/PLAN.md "Tool classification".
const (
	// ReadOperational returns device state without changing it: typed show
	// tools, ping, traceroute, and free-form commands that pass the
	// allow-list.
	ReadOperational Class = "READ_OPERATIONAL"
	// ReadConfig returns running, startup or candidate configuration, diffs
	// or backups. Highest secret-leak risk; redaction is mandatory.
	ReadConfig Class = "READ_CONFIG"
	// WriteConfig changes device or controller configuration, including
	// commit, confirm, abort and rollback.
	WriteConfig Class = "WRITE_CONFIG"
	// ExecArbitrary is unfiltered command execution, PFE shells, lab-node
	// exec and XML op commands.
	ExecArbitrary Class = "EXEC_ARBITRARY"
	// InventoryRead lists devices, groups, tags or source-of-truth objects.
	InventoryRead Class = "INVENTORY_READ"
	// LabLifecycle deploys or destroys lab topologies.
	LabLifecycle Class = "LAB_LIFECYCLE"
	// LocalAdmin acts on the MCP server host rather than a device: trusting
	// host keys, starting dashboards, health checks.
	LocalAdmin Class = "LOCAL_ADMIN"
)

// All returns every class in a stable order.
func All() []Class {
	return []Class{
		ReadOperational, ReadConfig, WriteConfig, ExecArbitrary,
		InventoryRead, LabLifecycle, LocalAdmin,
	}
}

// Parse converts a string to a Class. Matching is case-insensitive and
// accepts '-' in place of '_'. It returns an error for unknown names.
func Parse(s string) (Class, error) {
	norm := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", "_"))
	for _, c := range All() {
		if string(c) == norm {
			return c, nil
		}
	}
	return "", fmt.Errorf("classify: unknown class %q", s)
}

// Valid reports whether c is one of the known classes.
func (c Class) Valid() bool {
	_, err := Parse(string(c))
	return err == nil
}

// String returns the policy-file spelling of the class.
func (c Class) String() string { return string(c) }

// IsWrite reports whether the class can change device state. Destroying a
// lab counts as a write; the plan treats LAB_LIFECYCLE case by case, so the
// policy file decides for it and this returns false.
func (c Class) IsWrite() bool {
	return c == WriteConfig || c == ExecArbitrary
}

// IsRead reports whether the class only observes state.
func (c Class) IsRead() bool {
	return c == ReadOperational || c == ReadConfig || c == InventoryRead
}

// UnmarshalYAML implements yaml unmarshalling with validation so a typo in a
// profile or policy fails at load time rather than silently never matching.
func (c *Class) UnmarshalYAML(b []byte) error {
	parsed, err := Parse(strings.Trim(string(b), "\"' \n"))
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}
