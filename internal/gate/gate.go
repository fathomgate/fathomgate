// SPDX-License-Identifier: FSL-1.1-ALv2

package gate

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/gate/seam"
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
	// Inventory resolves target names. nil means no name is known. Decide
	// calls it from every session at once, so it must be safe for
	// concurrent use; the M1 resolvers (static file, patterns, their Chain)
	// are read-only after load and are.
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

// forwardable reports whether an allow may be forwarded while carrying the
// obligation. In M1 fathomgate carries these in the log line and enforces
// them later (redact in M2, the others in M4); every other obligation,
// including dry_run, diff, timed_rollback and any name a policy built in Go
// without Validate might hold, stops the call (ADR 0026 decision 1).
func forwardable(obligation string) bool {
	switch obligation {
	case "redact", "notify", "require_ticket", "canary_first":
		return true
	}
	return false
}

// Decide runs steps 1 to 6 of ADR 0026 on one call and says whether to
// forward it. It never fails: every problem is a deny with a rule id. ctx
// is not used yet; it is there for a resolver that takes one (the M2
// upstream-provider record).
func (g *Gate) Decide(ctx context.Context, in seam.CallInfo) seam.Verdict {
	return g.decide(ctx, in).verdict()
}

// Explanation is one call as Explain decided it: the Verdict Decide
// returns, and the detail an operator needs to see why. It is for
// fathomgate policy test and policy eval (ADR 0035), never for the agent:
// Decision carries Evaluate's own reasons, which name targets and
// counters, and Unnamed and Malformed are agent-chosen argument names,
// uncapped.
type Explanation struct {
	// Verdict is exactly what Decide returns for the same call.
	Verdict seam.Verdict
	// Decision is Evaluate's decision, or the gate's default:bad_arguments
	// refusal before Evaluate ran. Its Trace is the rule trace.
	Decision policy.Decision
	// Targets are the call's targets as resolved (role, site, tags,
	// known), empty for a refusal before Evaluate.
	Targets []policy.Target
	// ProfileClass is the profile's class for the tool before its
	// arguments were inspected, and ClassNote the classifier's reason for
	// any change (it names a command by index and the check, never by its
	// text).
	ProfileClass classify.Class
	ClassNote    string
	// ParseError is the log line's parse_error code, empty when none.
	ParseError string
	// Unnamed and Malformed are the argument names the closed argument
	// list refused (ADR 0033), sorted.
	Unnamed, Malformed []string
}

// Explain decides one call as Decide does, through the same steps, and
// also returns the operator's detail. fathomgate policy test and policy
// eval call it so that neither can disagree with serve (ADR 0035).
func (g *Gate) Explain(ctx context.Context, in seam.CallInfo) Explanation {
	d := g.decide(ctx, in)
	return Explanation{
		Verdict:      d.verdict(),
		Decision:     d.dec,
		Targets:      slices.Clone(d.resolved),
		ProfileClass: d.res.ProfileClass,
		ClassNote:    d.res.Reason,
		ParseError:   d.parseError,
		Unnamed:      slices.Clone(d.unnamed),
		Malformed:    slices.Clone(d.malformed),
	}
}

// decide runs the steps and leaves the outcome in the returned decision;
// verdict turns it into what the proxy acts on.
func (g *Gate) decide(_ context.Context, in seam.CallInfo) *decision {
	d := &decision{in: in}
	profile := g.profiles[in.Server]
	var spec classify.ToolSpec
	inProfile := false
	if profile != nil {
		// Exact lookup: an upstream tool named "eos-mcp.get_version" is not
		// get_version (Profile.Lookup would strip the prefix).
		spec, inProfile = profile.Tools[in.Tool]
	}

	// 1. Parse.
	args, parseErr := parseArguments(in.Arguments)
	if parseErr != "" {
		// Classify without arguments so the refusal still names a class.
		d.classify(profile, spec, inProfile, nil)
		d.parseError = parseErr
		return d.refuse(reasonNotObject)
	}

	// The per-call caps (profile-schema 2.4), before anything costs more
	// than a count.
	if inProfile {
		if code, reason := overCaps(spec, args); code != "" {
			d.classify(profile, spec, inProfile, nil)
			d.parseError = code
			return d.refuse(reason)
		}
	}

	// 2 and 3. Classify, then the closed argument list, then the targets.
	d.classify(profile, spec, inProfile, args)
	if profile != nil && !inProfile && len(args) > 0 {
		// ADR 0033 section 2: a tool the profile does not list has no
		// named argument, so every key is unnamed. Without this a tool the
		// upstream added later would reach the rules with zero targets,
		// past the unknown-target default and max_devices.
		d.unnamed = sortedKeys(args)
		return d.refuse(reasonUnnamed)
	}
	if unnamed, malformed := argumentFindings(d.res); len(unnamed) > 0 || len(malformed) > 0 {
		d.unnamed, d.malformed = unnamed, malformed
		if len(unnamed) > 0 {
			return d.refuse(reasonUnnamed)
		}
		return d.refuse(reasonMalformed)
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
		Session: policy.Session{DevicesTouched: devicesTouched(in, d.targets), PendingHolds: in.PendingHolds},
	}
	for _, name := range d.targets {
		req.Targets = append(req.Targets, g.resolve(name))
	}
	d.resolved = req.Targets

	// 6. Evaluate.
	d.dec = policy.Evaluate(g.policy, req)
	return d
}

// Arguments reports the argument names server's profile names for tool
// (ADR 0033, the named set), sorted, and whether the tool's argument list is
// closed. It is closed whenever the server has a profile: a tool the profile
// does not list is closed with no names, so every argument it is sent is
// refused. With no profile nothing is closed and Decide checks no argument
// names. The proxy uses it to drop from the inputSchema it advertises every
// property Decide would refuse (ADR 0033 section 4).
func (g *Gate) Arguments(server, tool string) (named []string, closed bool) {
	profile := g.profiles[server]
	if profile == nil {
		return nil, false
	}
	spec, ok := profile.Tools[tool] // exact, as Decide looks it up
	if !ok {
		return nil, true
	}
	for _, l := range [][]string{spec.TargetParams, spec.TargetsParams, spec.GroupParams, spec.CommandParams, spec.ConfigParams, spec.Args} {
		named = append(named, l...)
	}
	sort.Strings(named)
	return slices.Compact(named), true
}

// devicesTouched is the key's count before the call without the call's
// targets it has already counted (targets holds no repeats), so Evaluate's
// devices_touched plus the call's targets counts each device once. It is
// never below 0.
func devicesTouched(in seam.CallInfo, targets []string) int {
	n := in.DevicesTouched
	if in.Counted != nil {
		for _, t := range targets {
			if in.Counted(t) {
				n--
			}
		}
	}
	return max(n, 0)
}

// resolve looks one name up in the inventory. The name is known only when
// the record carries exactly the string the upstream receives (the static
// resolver matches case-insensitively; a case variant may be a different
// entry, or none, in the upstream's own device table, so it is unknown here).
// Whether a name is listed at all is the resolver's answer: a hostname
// pattern never makes a name known, and only enriches a device a name
// authority lists (ADR 0031, inventory.Chain). The role, site and tags of a
// known name may come from a pattern, and count for every rule (ADR 0031
// decision 2). An unknown name carries no role, site or tags.
func (g *Gate) resolve(name string) policy.Target {
	if g.inventory == nil {
		return policy.Target{Name: name}
	}
	t, ok := inventory.Known(g.inventory, name)
	if !ok {
		return policy.Target{Name: name}
	}
	return policy.Target{Name: name, Role: t.Role, Tags: slices.Clone(t.Tags), Site: t.Site, Known: true}
}

// decision carries one call through Decide.
type decision struct {
	in         seam.CallInfo
	res        classify.Result
	class      classify.Class
	source     classify.Source
	targets    []string
	resolved   []policy.Target
	dec        policy.Decision
	parseError string
	unnamed    []string
	malformed  []string
}

// classify sets the class. A server with no profile gets the fallback; a
// tool the profile does not list exactly gets the fallback too. Then the
// annotations: readOnlyHint false or destructiveHint true on a tool whose
// profile class is a read class makes the call EXEC_ARBITRARY, whatever its
// commands say. The upstream is saying the tool's execution context is not
// read-only, so a raised tool is never downgraded (classification.md
// section 4), and the raise can only make the class stricter: a call that
// is already EXEC_ARBITRARY keeps its own source.
func (d *decision) classify(profile *classify.Profile, spec classify.ToolSpec, inProfile bool, args map[string]any) {
	switch {
	case profile == nil:
		d.res = classify.Classify(nil, d.in.Tool, args)
	case !inProfile:
		d.res = classify.Result{Class: classify.ExecArbitrary, ClassSource: classify.SourceFallback, Reason: "tool not in profile"}
	default:
		d.res = classify.Classify(profile, d.in.Tool, args)
	}
	d.class, d.source = d.res.Class, d.res.ClassSource
	if inProfile && isReadClass(spec.Class) && raises(d.in) && d.class != classify.ExecArbitrary {
		d.class, d.source = classify.ExecArbitrary, classify.SourceAnnotationRaise
	}
}

// raises reports whether the annotations ask for a raise.
func raises(in seam.CallInfo) bool {
	return (in.ReadOnlyHint != nil && !*in.ReadOnlyHint) || (in.DestructiveHint != nil && *in.DestructiveHint)
}

// isReadClass reports whether annotations may raise the class.
func isReadClass(c classify.Class) bool {
	return c == classify.ReadOperational || c == classify.ReadConfig || c == classify.InventoryRead
}

// refuse is a deny with default:bad_arguments, decided before Evaluate.
func (d *decision) refuse(reason string) *decision {
	d.targets, d.resolved = nil, nil
	d.dec = policy.Decision{
		Effect: policy.Deny,
		RuleID: policy.RuleBadArguments,
		Reason: reason,
		Trace:  []policy.TraceEntry{{RuleID: policy.RuleBadArguments, Matched: true, Note: reason}},
	}
	return d
}

// verdict turns the decision into what the proxy does and records.
func (d *decision) verdict() seam.Verdict {
	v := seam.Verdict{
		Effect:      string(d.dec.Effect),
		RuleID:      d.dec.RuleID,
		Class:       string(d.class),
		ClassSource: string(d.source),
		Targets:     d.targets,
	}
	unmet := ""
	switch d.dec.Effect {
	case policy.Allow:
		v.Forward = true
		for _, o := range d.dec.Obligations {
			if !forwardable(o) {
				unmet, v.Forward = o, false
				break
			}
		}
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

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
