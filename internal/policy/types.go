package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/joshscott13/netguard/internal/classify"
)

// Effect is the outcome of a rule or decision.
type Effect string

// The three effects a rule can produce. Evaluate applies rules in file order
// and stops at the first match; there is no effect precedence between rules.
const (
	Allow Effect = "allow"
	Hold  Effect = "hold"
	Deny  Effect = "deny"
)

// ParseEffect converts a string to an Effect.
func ParseEffect(s string) (Effect, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow":
		return Allow, nil
	case "hold":
		return Hold, nil
	case "deny":
		return Deny, nil
	}
	return "", fmt.Errorf("policy: unknown effect %q", s)
}

// Valid reports whether e is allow, hold or deny.
func (e Effect) Valid() bool { _, err := ParseEffect(string(e)); return err == nil }

// UnmarshalYAML validates the effect at load time.
func (e *Effect) UnmarshalYAML(b []byte) error {
	parsed, err := ParseEffect(strings.Trim(string(b), "\"' \n"))
	if err != nil {
		return err
	}
	*e = parsed
	return nil
}

// Duration is a time.Duration that reads "15m" from YAML and writes it back
// as a string in JSON.
type Duration time.Duration

// UnmarshalYAML parses Go duration syntax.
func (d *Duration) UnmarshalYAML(b []byte) error {
	s := strings.Trim(string(b), "\"' \n")
	if s == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("policy: bad duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML writes the duration as a string.
func (d Duration) MarshalYAML() ([]byte, error) { return []byte(d.String()), nil }

// MarshalJSON writes the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// String returns Go duration syntax.
func (d Duration) String() string { return time.Duration(d).String() }

// Policy is one policy file.
type Policy struct {
	// Version is the schema version; only 1 is defined.
	Version int `yaml:"version" json:"version"`
	// Defaults hold behaviour that applies before and after the rules.
	Defaults Defaults `yaml:"defaults" json:"defaults"`
	// Rules are evaluated in order; the first match wins.
	Rules []Rule `yaml:"rules" json:"rules"`
}

// Defaults are the policy-wide settings.
type Defaults struct {
	// UnknownTarget is the effect for requests naming a device no provider
	// resolved: "deny", "allow" (let rules decide) or empty (deny writes,
	// let rules decide for reads).
	UnknownTarget Effect `yaml:"unknown_target,omitempty" json:"unknown_target,omitempty"`
	// Session caps per-session blast radius.
	Session SessionLimits `yaml:"session,omitempty" json:"session"`
}

// SessionLimits cap what one agent session may do. Zero means unlimited.
type SessionLimits struct {
	// MaxDevices is the maximum number of distinct devices a session may
	// touch, including the targets of the request being evaluated.
	MaxDevices int `yaml:"max_devices,omitempty" json:"max_devices,omitempty"`
	// MaxPending is the maximum number of simultaneously pending holds.
	MaxPending int `yaml:"max_pending,omitempty" json:"max_pending,omitempty"`
}

// Rule is one entry in the rules list.
type Rule struct {
	// ID names the rule in decisions, traces, errors and audit events.
	ID string `yaml:"id" json:"id"`
	// Match selects requests by class, role, tag, tool and server.
	Match Match `yaml:"match,omitempty" json:"match"`
	// When adds numeric conditions.
	When *When `yaml:"when,omitempty" json:"when,omitempty"`
	// Effect is allow, hold or deny.
	Effect Effect `yaml:"effect" json:"effect"`
	// Reason is shown to the agent and written to the audit log.
	Reason string `yaml:"reason,omitempty" json:"reason,omitempty"`
	// Obligations are side conditions the proxy must honour when forwarding
	// (dry_run, diff, timed_rollback, ...).
	Obligations []string `yaml:"obligations,omitempty" json:"obligations,omitempty"`
	// Approval configures the hold; only meaningful with effect hold.
	Approval *Approval `yaml:"approval,omitempty" json:"approval,omitempty"`
}

// Match is the equality and set-membership matcher. Empty lists match
// everything. Tools and Servers accept shell-style globs.
type Match struct {
	Class       []classify.Class `yaml:"class,omitempty" json:"class,omitempty"`
	DeviceRoles []string         `yaml:"device_roles,omitempty" json:"device_roles,omitempty"`
	DeviceTags  []string         `yaml:"device_tags,omitempty" json:"device_tags,omitempty"`
	Tools       []string         `yaml:"tools,omitempty" json:"tools,omitempty"`
	Servers     []string         `yaml:"servers,omitempty" json:"servers,omitempty"`
}

// When holds numeric range conditions.
type When struct {
	// TargetsCount constrains the number of targets in the request.
	TargetsCount *Range `yaml:"targets_count,omitempty" json:"targets_count,omitempty"`
}

// Range is a numeric comparison; every set field must hold.
type Range struct {
	GT  *int `yaml:"gt,omitempty" json:"gt,omitempty"`
	GTE *int `yaml:"gte,omitempty" json:"gte,omitempty"`
	LT  *int `yaml:"lt,omitempty" json:"lt,omitempty"`
	LTE *int `yaml:"lte,omitempty" json:"lte,omitempty"`
	EQ  *int `yaml:"eq,omitempty" json:"eq,omitempty"`
}

// Contains reports whether n satisfies every set bound.
func (r *Range) Contains(n int) bool {
	if r == nil {
		return true
	}
	if r.GT != nil && n <= *r.GT {
		return false
	}
	if r.GTE != nil && n < *r.GTE {
		return false
	}
	if r.LT != nil && n >= *r.LT {
		return false
	}
	if r.LTE != nil && n > *r.LTE {
		return false
	}
	if r.EQ != nil && n != *r.EQ {
		return false
	}
	return true
}

// Empty reports whether no bound is set.
func (r *Range) Empty() bool {
	return r == nil || (r.GT == nil && r.GTE == nil && r.LT == nil && r.LTE == nil && r.EQ == nil)
}

// Approval configures a hold.
type Approval struct {
	// TTL is how long the pending record lives before it expires.
	TTL Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`
	// ApproverMustDiffer requires the approver to be someone other than the
	// principal who made the request.
	ApproverMustDiffer bool `yaml:"approver_must_differ,omitempty" json:"approver_must_differ,omitempty"`
}

// Request is the normalised, classified, role-resolved tool call.
type Request struct {
	Server  string         `yaml:"server" json:"server"`
	Tool    string         `yaml:"tool" json:"tool"`
	Class   classify.Class `yaml:"class" json:"class"`
	Targets []Target       `yaml:"targets,omitempty" json:"targets,omitempty"`
	Session Session        `yaml:"session,omitempty" json:"session"`
}

// Target is one device the request touches, after role resolution.
type Target struct {
	Name string   `yaml:"name" json:"name"`
	Role string   `yaml:"role,omitempty" json:"role,omitempty"`
	Tags []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Site string   `yaml:"site,omitempty" json:"site,omitempty"`
	// Known is false when no inventory provider resolved the name.
	Known bool `yaml:"known" json:"known"`
}

// Session carries the per-session counters the defaults compare against.
type Session struct {
	// DevicesTouched is the number of distinct devices already touched.
	DevicesTouched int `yaml:"devices_touched,omitempty" json:"devices_touched"`
	// PendingHolds is the number of holds currently pending.
	PendingHolds int `yaml:"pending_holds,omitempty" json:"pending_holds"`
}

// Decision is the result of Evaluate.
type Decision struct {
	Effect      Effect       `json:"effect"`
	RuleID      string       `json:"rule_id"`
	Reason      string       `json:"reason,omitempty"`
	Obligations []string     `json:"obligations,omitempty"`
	Approval    *Approval    `json:"approval,omitempty"`
	Trace       []TraceEntry `json:"trace"`
}

// TraceEntry records one rule or default check.
type TraceEntry struct {
	RuleID  string `json:"rule_id"`
	Matched bool   `json:"matched"`
	Note    string `json:"note,omitempty"`
}

// Rule ids used for decisions made by defaults rather than by a rule.
const (
	RuleUnknownTarget = "default:unknown_target"
	RuleMaxDevices    = "default:session.max_devices"
	RuleMaxPending    = "default:session.max_pending"
	RuleNoMatch       = "default:no-match"
)

// KnownObligations is the vocabulary the proxy understands. Validate rejects
// anything else so a typo cannot silently drop a safeguard.
var KnownObligations = []string{
	"dry_run", "diff", "timed_rollback", "redact", "canary_first",
	"require_ticket", "notify",
}
