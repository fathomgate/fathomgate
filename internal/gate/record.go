// SPDX-License-Identifier: FSL-1.1-ALv2

package gate

import (
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/fathomgate/fathomgate/internal/gate/seam"
	"github.com/fathomgate/fathomgate/internal/policy"
)

// Caps on the argument names the decision log line carries. The names are
// agent-chosen, so an agent could otherwise make one log line as large as
// its arguments.
const (
	maxLoggedNames     = 8
	maxLoggedNameBytes = 64
)

// record builds the decision log line (ADR 0026 step 8, msg=decision, level
// Info). Field names follow audit-event-schema section 2 where it names one
// (decision, session_id), so M4 swaps the sink without renaming anything.
// No argument value, command, payload or upstream text is here: the command
// is represented by the class, and target names appear only after they
// passed validTargetName. The reason is the operator's or fathomgate's own
// text. Refused argument names are agent text; slog escapes them, and they
// are capped by count and length.
func (d *decision) record(v seam.Verdict) []slog.Attr {
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
	attrs := make([]slog.Attr, 0, 22)
	attrs = append(attrs,
		slog.String("server", d.in.Server),
		slog.String("tool", d.in.Tool),
		slog.String("class", v.Class),
		slog.String("class_source", v.ClassSource),
		slog.Any("targets", targets),
		slog.Any("roles", roles),
		slog.Bool("unknown_target", d.hasUnknown()),
		slog.String("decision", v.Effect),
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
		slog.String("session_id", d.in.SessionID),
	)
	if d.parseError != "" {
		attrs = append(attrs, slog.String("parse_error", d.parseError))
	}
	if len(d.unnamed) > 0 {
		attrs = append(attrs, slog.Any("unnamed_args", capNames(d.unnamed)))
	}
	if len(d.malformed) > 0 {
		attrs = append(attrs, slog.Any("malformed_args", capNames(d.malformed)))
	}
	return attrs
}

// capNames keeps at most maxLoggedNames names of at most maxLoggedNameBytes
// bytes each (cut on a rune boundary, marked with "..."), and says how many
// were left out.
func capNames(names []string) []string {
	n := min(len(names), maxLoggedNames)
	out := make([]string, 0, n+1)
	for _, s := range names[:n] {
		if len(s) > maxLoggedNameBytes {
			cut := maxLoggedNameBytes
			for cut > 0 && !utf8.RuneStart(s[cut]) {
				cut--
			}
			s = s[:cut] + "..."
		}
		out = append(out, s)
	}
	if rest := len(names) - n; rest > 0 {
		out = append(out, fmt.Sprintf("(%d more)", rest))
	}
	return out
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

// traceValue renders the rule trace for the Debug line only when a handler
// resolves it: one string per check, "<rule_id> matched" or "<rule_id> not
// matched: <note>". Notes may name a target (already validated) and the
// tool; they never hold argument values.
type traceValue []policy.TraceEntry

// LogValue implements slog.LogValuer.
func (t traceValue) LogValue() slog.Value {
	lines := make([]string, len(t))
	for i, e := range t {
		var b strings.Builder
		b.WriteString(e.RuleID)
		if e.Matched {
			b.WriteString(" matched")
		} else {
			b.WriteString(" not matched")
		}
		if e.Note != "" && e.Note != "matched" {
			b.WriteString(": ")
			b.WriteString(e.Note)
		}
		lines[i] = oneLine(b.String())
	}
	return slog.AnyValue(lines)
}

func traceAttr(trace []policy.TraceEntry) slog.Attr {
	return slog.Any("trace", traceValue(trace))
}
