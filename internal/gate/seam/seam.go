// SPDX-License-Identifier: FSL-1.1-ALv2

// Package seam holds the two plain-data types that cross between
// internal/proxy and internal/gate at Proxy.dispatch (ADR 0026): what the
// proxy knows about a call, and what the gate answers. It imports nothing
// from fathomgate, so the proxy can depend on it without importing classify,
// inventory or policy.
package seam

import (
	"encoding/json"
	"log/slog"
)

// CallInfo is one tools/call as the proxy sees it at dispatch.
type CallInfo struct {
	// Server is the upstream's prefix (the profile's server name) and Tool
	// the upstream's own tool name, without the prefix. The proxy has
	// already checked both against [A-Za-z0-9_.-]. Tool is looked up in the
	// profile exactly as given.
	Server, Tool string
	// Arguments is the call's arguments object as the agent sent it.
	Arguments json.RawMessage
	// ReadOnlyHint and DestructiveHint are the tool's annotations from the
	// upstream's tools/list, nil when the upstream did not send them. They
	// can only raise a read class to EXEC_ARBITRARY (an explicit false and an
	// explicit true respectively); nothing lowers a class. go-sdk v1.8
	// decodes an absent readOnlyHint as false, so the proxy must not map
	// that false to a non-nil pointer for every tool.
	ReadOnlyHint, DestructiveHint *bool
	// AgentProtocol and UpstreamProtocol are the negotiated protocol
	// versions; AgentEra and UpstreamEra their era labels (stateful or
	// stateless). The era is a label for the record, never a capability.
	AgentProtocol, AgentEra, UpstreamProtocol, UpstreamEra string
	// Transport is the agent transport (stdio or http), Principal the
	// server-side identity of the agent, and SessionID fathomgate's short
	// session hash. They are recorded, never used to decide.
	Transport, Principal, SessionID string
	// DevicesTouched and PendingHolds are the counters of this call's
	// counter key (ADR 0026, Session counters), read before the call.
	DevicesTouched, PendingHolds int
	// Counted reports whether the counter key has already counted a target
	// name, exactly as the upstream receives it. The gate takes each of the
	// call's targets it reports true for off DevicesTouched, so a device is
	// counted once toward max_devices (policy-schema 2: distinct devices)
	// and one Decide is enough (M1-39). nil counts none. The proxy holds
	// the counter key's lock across Decide; Counted is valid only during
	// that call, must not be kept, and only reads.
	Counted func(target string) bool
}

// Verdict is the gate's answer for one call. The proxy acts on Forward
// alone: it forwards the call when Forward is true and otherwise returns
// Error as a tool result with isError true. Effect, RuleID, Class and
// ClassSource are for display and logging only.
type Verdict struct {
	// Forward is true only for an allow whose obligations fathomgate can
	// meet or carry in M1 (redact, notify, require_ticket, canary_first).
	Forward bool
	// Effect is what Evaluate returned (allow, hold or deny), or deny for a
	// call refused before Evaluate. A hold stays hold here even though it
	// is not forwarded.
	Effect string
	// RuleID names the rule that decided, or a default: id.
	RuleID string
	// Class and ClassSource are the final class and the step that set it.
	Class, ClassSource string
	// Targets are the call's target names after validation, exactly as the
	// upstream receives them; the proxy counts them when it forwards.
	Targets []string
	// Error is the one-line tool error text for a call that is not
	// forwarded, empty when Forward is true.
	Error string
	// Record is the decision log line's attributes (msg=decision, level
	// Info). It holds no argument value, command or upstream text.
	Record []slog.Attr
	// Trace is the rule trace as one attribute for the same line when the
	// logger is at Debug. Its value is a slog.LogValuer, so it costs
	// nothing unless a handler resolves it.
	Trace slog.Attr
}
