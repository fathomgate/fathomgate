// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"strings"

	"github.com/fathomgate/fathomgate/internal/policy"
)

// The fixed reasons for default:bad_arguments. None names an argument, a
// value or a target: the agent already has its arguments, and anything
// echoed back is a place for injected text to ride (ADR 0026).
const (
	reasonNotObject = "the arguments must be one JSON object, in UTF-8, with no key given twice"
	// reasonUnnamed and reasonMalformed are ADR 0033 section 3's texts.
	reasonUnnamed   = "an argument is not named in the server profile for this tool"
	reasonMalformed = "a target, command or config argument must be a string that does not parse as JSON, or a list of such strings"
	reasonBadTarget = "a target is not a hostname or IP address"
	reasonNoTarget  = "this tool needs at least one target named explicitly"
	reasonGroup     = "selecting devices by tag or group is not supported yet; name each target"
)

// The fixed reasons for the other default: rules, which replace Evaluate's
// own reasons because those name targets and counts.
const (
	reasonUnknownTarget = "target not in inventory"
	reasonMaxDevices    = "this session would touch more devices than its cap allows"
	reasonMaxPending    = "this session already has as many held calls as its cap allows"
	reasonNoMatch       = "no rule matched"
	reasonNoPolicy      = "no policy loaded"
	reasonNoReason      = "the policy does not allow this call"
	// reasonHeld is the maintainer's sentence (ADR 0026 decision 3).
	reasonHeld = "needs approval, and approvals aren't available yet, so this call was not run."
	// unknownSuffix is added to a denial when a target is unknown and the
	// reason does not already say so.
	unknownSuffix = "; " + reasonUnknownTarget
)

// errorText is the one-line tool error for a call that is not forwarded:
//
//	fathomgate <denied|cannot run|held> <server>.<tool>: rule <rule_id> (class <CLASS>): <reason>
//
// unmet is the first obligation of an allow that fathomgate cannot carry;
// unknown reports whether a target was not in inventory.
func errorText(server, tool string, dec policy.Decision, class, unmet string, unknown bool) string {
	var verb, reason string
	switch dec.Effect {
	case policy.Allow:
		verb = "cannot run"
		reason = unmetReason(unmet)
	case policy.Hold:
		verb = "held"
		reason = reasonHeld
	default:
		verb = "denied"
		reason = denyReason(dec)
		if unknown && reason != reasonUnknownTarget {
			reason += unknownSuffix
		}
	}
	var b strings.Builder
	b.Grow(64 + len(server) + len(tool) + len(dec.RuleID) + len(reason))
	b.WriteString("fathomgate ")
	b.WriteString(verb)
	b.WriteByte(' ')
	b.WriteString(nameText(server))
	b.WriteByte('.')
	b.WriteString(nameText(tool))
	b.WriteString(": rule ")
	b.WriteString(oneLine(dec.RuleID))
	b.WriteString(" (class ")
	b.WriteString(class)
	b.WriteString("): ")
	b.WriteString(oneLine(reason))
	return b.String()
}

// unmetReason says why an allow is not run. The change-safety obligations
// are named (ADR 0026); any other obligation fathomgate cannot carry is not
// in the vocabulary (a policy built in Go without Validate), so it is not
// named either, whatever text it holds.
func unmetReason(obligation string) string {
	switch obligation {
	case "dry_run", "diff", "timed_rollback":
		return "obligation " + obligation + " cannot be met until change-safety drivers exist"
	}
	return "an obligation fathomgate does not know cannot be met"
}

// denyReason is the policy author's reason for a rule, or fathomgate's
// fixed text for a default: rule. Evaluate's own reasons for the defaults
// are never used, because they quote target names and counters.
func denyReason(dec policy.Decision) string {
	switch dec.RuleID {
	case policy.RuleBadArguments:
		return dec.Reason // set by the gate from the fixed reasons above
	case policy.RuleUnknownTarget:
		return reasonUnknownTarget
	case policy.RuleMaxDevices:
		return reasonMaxDevices
	case policy.RuleMaxPending:
		return reasonMaxPending
	case policy.RuleNoMatch:
		if dec.Reason == reasonNoPolicy {
			return reasonNoPolicy
		}
		return reasonNoMatch
	}
	if strings.TrimSpace(dec.Reason) == "" {
		return reasonNoReason
	}
	return dec.Reason
}

// oneLine keeps operator-written text (a rule id, a reason) on one line of
// printable text: every control character, and the Unicode line and
// paragraph separators, becomes a space, so the first line stays parseable.
func oneLine(s string) string {
	clean := true
	for _, r := range s {
		if isBreak(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isBreak(r) {
			return ' '
		}
		return r
	}, s)
}

func isBreak(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == '\u2028' || r == '\u2029'
}

// nameText keeps a server or tool name to [A-Za-z0-9_.-]. The proxy has
// already refused any other name; this is defence in depth, so a name that
// slipped through is shown with '_' in place of each other character and
// never carries text of its own.
func nameText(s string) string {
	ok := true
	for i := 0; i < len(s); i++ {
		if !hostByte(s[i]) {
			ok = false
			break
		}
	}
	if ok {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x80 && hostByte(byte(r)) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
