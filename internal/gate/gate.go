// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/inventory"
	"github.com/fathomgate/fathomgate/internal/policy"
)

// Config is what a Gate decides with. Every field is read-only after New;
// the caller must not change the policy, a profile or the inventory while
// the Gate is in use.
type Config struct {
	// Policy is the loaded policy. nil denies every call with
	// default:no-match (policy-schema section 4).
	Policy *policy.Policy
	// Profiles maps an upstream's server name (the tool prefix) to its
	// profile, as classify.LoadProfileDir returns them. A server with no
	// profile is classified by the fallback classifier and its arguments are
	// not checked against a closed list.
	Profiles map[string]*classify.Profile
	// Inventory resolves target names. nil means no name is known.
	Inventory inventory.Resolver
}

// Gate runs ADR 0026 steps 1 to 6 for one call at a time. It keeps no state
// between calls and is safe for concurrent use.
type Gate struct {
	policy    *policy.Policy
	profiles  map[string]*classify.Profile
	inventory inventory.Resolver
}

// New checks the configuration and returns a Gate. A profile stored under a
// name other than its own server name is an error, because the policy's
// match.servers and the log line would then name different things.
func New(cfg Config) (*Gate, error) {
	profiles := make(map[string]*classify.Profile, len(cfg.Profiles))
	for name, p := range cfg.Profiles {
		if p == nil {
			return nil, fmt.Errorf("gate: profile for server %q is nil", name)
		}
		if p.Server != name {
			return nil, fmt.Errorf("gate: profile for server %q names server %q", name, p.Server)
		}
		profiles[name] = p
	}
	return &Gate{policy: cfg.Policy, profiles: profiles, inventory: cfg.Inventory}, nil
}

// CallInfo is one tools/call as the proxy sees it at dispatch. It is plain
// data: the proxy fills it without importing classify, inventory or policy.
type CallInfo struct {
	// Server is the upstream's prefix (the profile's server name) and Tool
	// the upstream's own tool name, without the prefix. The proxy has
	// already checked both against [A-Za-z0-9_.-].
	Server, Tool string
	// Arguments is the call's arguments object as the agent sent it.
	Arguments json.RawMessage
	// ReadOnlyHint and DestructiveHint are the tool's annotations from the
	// upstream's tools/list, nil when the upstream did not send them. They
	// can only raise a read class to EXEC_ARBITRARY (explicit false and
	// explicit true respectively); nothing lowers a class.
	ReadOnlyHint, DestructiveHint *bool
	// AgentProtocol and UpstreamProtocol are the negotiated protocol
	// versions; AgentEra and UpstreamEra their era labels (stateful or
	// stateless). The era is a label for the record, never a capability.
	AgentProtocol, AgentEra, UpstreamProtocol, UpstreamEra string
	// Transport is the agent transport (stdio or http), Principal the
	// server-side identity of the agent, and Session fathomgate's short
	// session hash. They are recorded, never used to decide.
	Transport, Principal, Session string
	// DevicesTouched and PendingHolds are the counters of this call's
	// counter key (ADR 0026, Session counters), read before the call.
	DevicesTouched, PendingHolds int
}

// Verdict is the gate's answer for one call.
type Verdict struct {
	// Forward is true only for an allow whose obligations fathomgate can
	// meet or carry (no dry_run, diff or timed_rollback in M1).
	Forward bool
	// Effect is what Evaluate returned (allow, hold or deny), or deny for a
	// call refused before Evaluate. A hold stays hold here even though it is
	// not forwarded.
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
	// Trace is the rule trace as one attribute, for the same line at Debug.
	Trace slog.Attr
}

// changeSafety are the obligations nothing in M1 can meet, so an allow that
// carries one is not forwarded (ADR 0026 decision 1).
var changeSafety = []string{"dry_run", "diff", "timed_rollback"}

// Decide runs steps 1 to 6 of ADR 0026 on one call and says whether to
// forward it. It never fails: every problem is a deny with a rule id.
func (g *Gate) Decide(_ context.Context, in CallInfo) Verdict {
	d := decision{in: in}
	profile := g.profiles[in.Server]

	// 1. Parse.
	args, err := parseArguments(in.Arguments)
	if err != nil {
		// Classify without arguments so the refusal still names a class.
		d.classify(profile, nil, in)
		return d.refuse(reasonNotObject)
	}

	// 2 and 3. Normalise and classify.
	d.classify(profile, args, in)
	var spec classify.ToolSpec
	var inProfile bool
	if profile != nil {
		spec, inProfile = profile.Lookup(in.Tool)
	}
	if unnamedArguments(d.res) {
		return d.refuse(reasonUnnamed)
	}
	if inProfile {
		names, groups, problem := targets(spec, args)
		if problem == targetBadName {
			return d.refuse(reasonBadTarget)
		}
		d.targets = names
		// The exemption follows the profile's class, which says what the
		// tool is; an annotation raise makes the call EXEC_ARBITRARY, which
		// the rules then decide.
		exempt := spec.Class == classify.InventoryRead || spec.Class == classify.LocalAdmin
		if !exempt && groups {
			return d.refuse(reasonGroup)
		}
		if !exempt && declaresTargets(spec) && len(names) == 0 {
			return d.refuse(reasonNoTarget)
		}
	}

	// 4. Resolve.
	req := policy.Request{
		Server:  in.Server,
		Tool:    in.Tool,
		Class:   d.class,
		Targets: make([]policy.Target, 0, len(d.targets)),
		// 5. Session counters, as the proxy counted them.
		Session: policy.Session{DevicesTouched: in.DevicesTouched, PendingHolds: in.PendingHolds},
	}
	for _, name := range d.targets {
		req.Targets = append(req.Targets, g.resolve(name))
	}
	d.resolved = req.Targets

	// 6. Evaluate.
	d.dec = policy.Evaluate(g.policy, req)
	return d.verdict()
}

// resolve looks one name up in the inventory. The name is known only when
// the record carries exactly the string the upstream receives (the static
// resolver matches case-insensitively; a case variant may be a different
// entry, or none, in the upstream's own device table, so it is unknown here)
// and the record did not come from a hostname pattern alone (ADR 0031: a
// pattern never makes a target known). An unknown name carries no role,
// site or tags, not even a pattern's.
func (g *Gate) resolve(name string) policy.Target {
	if g.inventory == nil {
		return policy.Target{Name: name}
	}
	t, ok := g.inventory.Resolve(name)
	// TODO(M1-34 follow-up): when inventory.Target carries per-field
	// provenance (ADR 0031 decision 3), test the name's source instead of
	// Status.
	if !ok || t.Name != name || t.Status == "pattern" {
		return policy.Target{Name: name}
	}
	return policy.Target{Name: name, Role: t.Role, Tags: slices.Clone(t.Tags), Site: t.Site, Known: true}
}

// decision carries one call through Decide.
type decision struct {
	in       CallInfo
	res      classify.Result
	class    classify.Class
	source   classify.Source
	targets  []string
	resolved []policy.Target
	dec      policy.Decision
}

// classify runs classify.Classify and then the annotations. An annotation
// that says a read tool is not read-only (readOnlyHint false) or destroys
// (destructiveHint true) raises the tool's profile class to EXEC_ARBITRARY
// before its commands are inspected, as classification.md section 2 orders
// it: a raised tool that carries commands is then downgraded exactly as an
// EXEC_ARBITRARY tool would be, and one without commands stays
// EXEC_ARBITRARY with class_source annotation_raise.
func (d *decision) classify(profile *classify.Profile, args map[string]any, in CallInfo) {
	d.res = classify.Classify(profile, in.Tool, args)
	d.class, d.source = d.res.Class, d.res.ClassSource
	if !d.res.Known || !raises(in) || !isReadClass(d.res.ProfileClass) {
		return
	}
	spec, _ := profile.Lookup(in.Tool)
	spec.Class = classify.ExecArbitrary
	raised := classify.Classify(&classify.Profile{Server: profile.Server, Tools: map[string]classify.ToolSpec{in.Tool: spec}}, in.Tool, args)
	d.class = raised.Class
	d.source = raised.ClassSource
	if raised.ClassSource == classify.SourceProfile {
		d.source = classify.SourceAnnotationRaise
	}
}

// raises reports whether the annotations ask for a raise.
func raises(in CallInfo) bool {
	return (in.ReadOnlyHint != nil && !*in.ReadOnlyHint) || (in.DestructiveHint != nil && *in.DestructiveHint)
}

// isReadClass reports whether annotations may raise the class.
func isReadClass(c classify.Class) bool {
	return c == classify.ReadOperational || c == classify.ReadConfig || c == classify.InventoryRead
}

// refuse is a deny with default:bad_arguments, decided before Evaluate.
func (d *decision) refuse(reason string) Verdict {
	d.targets, d.resolved = nil, nil
	d.dec = policy.Decision{
		Effect: policy.Deny,
		RuleID: policy.RuleBadArguments,
		Reason: reason,
		Trace:  []policy.TraceEntry{{RuleID: policy.RuleBadArguments, Matched: true, Note: reason}},
	}
	return d.verdict()
}

// verdict turns the decision into what the proxy does and records.
func (d *decision) verdict() Verdict {
	v := Verdict{
		Effect:      string(d.dec.Effect),
		RuleID:      d.dec.RuleID,
		Class:       string(d.class),
		ClassSource: string(d.source),
		Targets:     d.targets,
	}
	unmet := ""
	switch d.dec.Effect {
	case policy.Allow:
		for _, o := range d.dec.Obligations {
			if slices.Contains(changeSafety, o) {
				unmet = o
				break
			}
		}
		v.Forward = unmet == ""
	case policy.Hold, policy.Deny:
	default:
		// Evaluate returns only the three effects; anything else is not
		// forwarded.
		v.Effect = string(policy.Deny)
	}
	if !v.Forward {
		v.Error = errorText(d.in.Server, d.in.Tool, d.dec, v.Class, unmet, d.hasUnknown())
	}
	v.Record = d.record(v)
	v.Trace = traceAttr(d.dec.Trace)
	return v
}

// hasUnknown reports whether any resolved target is unknown.
func (d *decision) hasUnknown() bool {
	for _, t := range d.resolved {
		if !t.Known {
			return true
		}
	}
	return false
}
