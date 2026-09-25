// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"log/slog"

	"github.com/fathomgate/fathomgate/internal/policy"
)

// record builds the decision log line (ADR 0026 step 8, msg=decision, level
// Info). Field names follow audit-event-schema section 2 where it names
// one, so M4 swaps the sink without renaming anything. No argument value,
// command, payload or upstream text is here: the command is represented by
// the class, and target names appear only after they passed
// validTargetName. The reason is the operator's or fathomgate's own text.
func (d *decision) record(v Verdict) []slog.Attr {
	targets := make([]string, len(d.resolved))
	roles := make([]string, len(d.resolved))
	for i, t := range d.resolved {
		targets[i] = t.Name
		roles[i] = t.Role
	}
	obligations := d.dec.Obligations
	if obligations == nil {
		obligations = []string{}
	}
	return []slog.Attr{
		slog.String("server", d.in.Server),
		slog.String("tool", d.in.Tool),
		slog.String("class", v.Class),
		slog.String("class_source", v.ClassSource),
		slog.Any("targets", targets),
		slog.Any("roles", roles),
		slog.Bool("unknown_target", d.hasUnknown()),
		slog.String("effect", v.Effect),
		slog.String("rule_id", v.RuleID),
		slog.String("reason", oneLine(recordReason(d.dec))),
		slog.Any("obligations", obligations),
		slog.Bool("forwarded", v.Forward),
		slog.String("agent_protocol", d.in.AgentProtocol),
		slog.String("agent_era", d.in.AgentEra),
		slog.String("upstream_protocol", d.in.UpstreamProtocol),
		slog.String("upstream_era", d.in.UpstreamEra),
		slog.String("transport", d.in.Transport),
		slog.String("principal", d.in.Principal),
		slog.String("session", d.in.Session),
	}
}

// recordReason is the reason as the operator should read it: the same text
// the agent gets for a deny, the rule's own reason otherwise.
func recordReason(dec policy.Decision) string {
	switch dec.Effect {
	case policy.Deny:
		return denyReason(dec)
	case policy.Hold:
		return reasonHeld
	}
	return dec.Reason
}

// traceAttr renders the rule trace for the Debug line: one string per check,
// "<rule_id> matched" or "<rule_id> not matched: <note>". Notes may name a
// target (already validated) and the tool; they never hold argument values.
func traceAttr(trace []policy.TraceEntry) slog.Attr {
	lines := make([]string, len(trace))
	for i, e := range trace {
		s := e.RuleID
		if e.Matched {
			s += " matched"
		} else {
			s += " not matched"
		}
		if e.Note != "" && e.Note != "matched" {
			s += ": " + e.Note
		}
		lines[i] = oneLine(s)
	}
	return slog.Any("trace", lines)
}
