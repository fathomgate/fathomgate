package policy

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/joshscott13/netguard/internal/classify"
)

// Evaluate applies the policy to the request and returns a Decision with a
// full trace. It never panics on a nil policy: a nil policy denies.
func Evaluate(p *Policy, r Request) Decision {
	var d Decision
	if p == nil {
		d.Effect, d.RuleID, d.Reason = Deny, RuleNoMatch, "no policy loaded"
		d.Trace = []TraceEntry{{RuleID: RuleNoMatch, Matched: true, Note: d.Reason}}
		return d
	}

	// 1. Unknown targets.
	if unknown := unknownTargets(r.Targets); len(unknown) > 0 {
		note := fmt.Sprintf("unknown targets: %s", strings.Join(unknown, ", "))
		switch {
		case p.Defaults.UnknownTarget == Deny,
			p.Defaults.UnknownTarget == "" && r.Class.IsWrite():
			d.Effect, d.RuleID = Deny, RuleUnknownTarget
			d.Reason = note + "; a device absent from inventory is not a device the agent may touch"
			d.Trace = append(d.Trace, TraceEntry{RuleID: RuleUnknownTarget, Matched: true, Note: d.Reason})
			return d
		default:
			d.Trace = append(d.Trace, TraceEntry{RuleID: RuleUnknownTarget, Matched: false,
				Note: note + "; " + string(r.Class) + " continues to rules"})
		}
	}

	// 2. Session device cap.
	if max := p.Defaults.Session.MaxDevices; max > 0 {
		total := r.Session.DevicesTouched + len(r.Targets)
		if total > max {
			d.Effect, d.RuleID = Deny, RuleMaxDevices
			d.Reason = fmt.Sprintf("session would touch %d devices, cap is %d", total, max)
			d.Trace = append(d.Trace, TraceEntry{RuleID: RuleMaxDevices, Matched: true, Note: d.Reason})
			return d
		}
		d.Trace = append(d.Trace, TraceEntry{RuleID: RuleMaxDevices, Matched: false,
			Note: fmt.Sprintf("%d of %d devices", total, max)})
	}

	// 3. Rules in order, first match wins.
	for i := range p.Rules {
		rule := &p.Rules[i]
		ok, note := rule.matches(r)
		d.Trace = append(d.Trace, TraceEntry{RuleID: rule.ID, Matched: ok, Note: note})
		if !ok {
			continue
		}
		d.Effect, d.RuleID, d.Reason = rule.Effect, rule.ID, rule.Reason
		d.Obligations = slices.Clone(rule.Obligations)
		if rule.Approval != nil {
			a := *rule.Approval
			d.Approval = &a
		}
		// 4. Pending cap applies to holds.
		if d.Effect == Hold {
			if max := p.Defaults.Session.MaxPending; max > 0 && r.Session.PendingHolds >= max {
				d.Effect, d.RuleID = Deny, RuleMaxPending
				d.Reason = fmt.Sprintf("rule %s would hold but %d holds are already pending, cap is %d", rule.ID, r.Session.PendingHolds, max)
				d.Approval = nil
				d.Trace = append(d.Trace, TraceEntry{RuleID: RuleMaxPending, Matched: true, Note: d.Reason})
			}
		}
		return d
	}

	// 5. Fail closed.
	d.Effect, d.RuleID, d.Reason = Deny, RuleNoMatch, "no rule matched"
	d.Trace = append(d.Trace, TraceEntry{RuleID: RuleNoMatch, Matched: true, Note: d.Reason})
	return d
}

func unknownTargets(ts []Target) []string {
	var out []string
	for _, t := range ts {
		if !t.Known {
			out = append(out, t.Name)
		}
	}
	return out
}

// matches reports whether the rule selects the request, with a short note
// for the trace explaining the first failing matcher.
func (rule *Rule) matches(r Request) (bool, string) {
	m := rule.Match
	if len(m.Class) > 0 && !slices.Contains(m.Class, r.Class) {
		return false, fmt.Sprintf("class %s not in %s", r.Class, joinClasses(m.Class))
	}
	if len(m.Servers) > 0 && !globAny(m.Servers, r.Server) {
		return false, fmt.Sprintf("server %q not in %v", r.Server, m.Servers)
	}
	if len(m.Tools) > 0 {
		// Tools may be given bare ("get_config") or prefixed with the
		// server ("netdev-ssh-mcp.get_config"); patterns match either.
		bare := r.Tool
		if r.Server != "" {
			bare = strings.TrimPrefix(r.Tool, r.Server+".")
		}
		if !globAny(m.Tools, bare) && !globAny(m.Tools, r.Server+"."+bare) {
			return false, fmt.Sprintf("tool %q not in %v", r.Tool, m.Tools)
		}
	}
	if len(m.DeviceRoles) > 0 {
		if len(r.Targets) == 0 {
			return false, "device_roles set but request has no targets"
		}
		for _, t := range r.Targets {
			if !slices.Contains(m.DeviceRoles, t.Role) {
				return false, fmt.Sprintf("target %s role %q not in %v", t.Name, t.Role, m.DeviceRoles)
			}
		}
	}
	if len(m.DeviceTags) > 0 {
		if len(r.Targets) == 0 {
			return false, "device_tags set but request has no targets"
		}
		for _, t := range r.Targets {
			if !anyIn(t.Tags, m.DeviceTags) {
				return false, fmt.Sprintf("target %s tags %v have none of %v", t.Name, t.Tags, m.DeviceTags)
			}
		}
	}
	if rule.When != nil && rule.When.TargetsCount != nil && !rule.When.TargetsCount.Contains(len(r.Targets)) {
		return false, fmt.Sprintf("targets_count %d outside range", len(r.Targets))
	}
	return true, "matched"
}

func globAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, s); ok || p == s {
			return true
		}
	}
	return false
}

func anyIn(have, want []string) bool {
	for _, h := range have {
		if slices.Contains(want, h) {
			return true
		}
	}
	return false
}

func joinClasses(cs []classify.Class) string {
	s := make([]string, len(cs))
	for i, c := range cs {
		s[i] = string(c)
	}
	return "[" + strings.Join(s, " ") + "]"
}
