// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"fmt"
	"strings"
)

// Normalize extracts targets, commands and configuration payload from a tool
// call's arguments using the profile's parameter mapping.
//
// Targets are gathered from target_params (single values), targets_params
// (arrays or comma-separated strings) and group_params (each value becomes
// an "@name" token that the inventory expands later). "@group" tokens
// already present in the arguments pass through unchanged. Commands are
// gathered from command_params as strings or arrays. Config payload joins
// every config_params value with newlines.
//
// An unknown tool yields empty results; callers should treat that as
// EXEC_ARBITRARY.
func Normalize(profile *Profile, tool string, args map[string]any) (targets []string, commands []string, configPayload string) {
	if profile == nil {
		return nil, nil, ""
	}
	spec, ok := profile.Lookup(tool)
	if !ok {
		return nil, nil, ""
	}
	seen := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		targets = append(targets, v)
	}
	for _, p := range spec.TargetParams {
		for _, v := range stringValues(args[p]) {
			add(v)
		}
	}
	for _, p := range spec.TargetsParams {
		for _, v := range stringValues(args[p]) {
			add(v)
		}
	}
	for _, p := range spec.GroupParams {
		for _, v := range stringValues(args[p]) {
			if !strings.HasPrefix(v, "@") {
				v = "@" + v
			}
			add(v)
		}
	}
	for _, p := range spec.CommandParams {
		for _, v := range rawValues(args[p]) {
			if v = strings.TrimSpace(v); v != "" {
				commands = append(commands, v)
			}
		}
	}
	var payload []string
	for _, p := range spec.ConfigParams {
		for _, v := range rawValues(args[p]) {
			if v = strings.TrimRight(v, "\n"); v != "" {
				payload = append(payload, v)
			}
		}
	}
	configPayload = strings.Join(payload, "\n")
	return targets, commands, configPayload
}

// Source records which step of docs/specs/classification.md section 2 set
// Result.Class. The string values are the audit event's class_source
// spellings (docs/specs/audit-event-schema.md).
type Source string

// The class sources. Classify emits SourceProfile, SourceFallback,
// SourceDowngrade and SourceReclassify today; SourceCapabilityTable (meta-tool
// capability tables) and SourceAnnotationRaise (tool annotations raising a
// read class) are reserved for the tasks that add those inputs.
const (
	// SourceProfile: the profile's class for the tool, unchanged.
	SourceProfile Source = "profile"
	// SourceCapabilityTable: resolved through a meta-tool's capability
	// table. Reserved.
	SourceCapabilityTable Source = "capability_table"
	// SourceFallback: no profile, or the tool is not in it. The class is
	// EXEC_ARBITRARY.
	SourceFallback Source = "fallback"
	// SourceAnnotationRaise: a tool annotation raised a read class to
	// EXEC_ARBITRARY. Reserved.
	SourceAnnotationRaise Source = "annotation_raise"
	// SourceDowngrade: an EXEC_ARBITRARY tool whose every command passed
	// the allow-list, now READ_OPERATIONAL.
	SourceDowngrade Source = "downgrade"
	// SourceReclassify: the commands moved the class anywhere else: an
	// EXEC_ARBITRARY or READ_OPERATIONAL call that reads configuration is
	// READ_CONFIG, and a READ_OPERATIONAL call whose command fails the
	// allow-list is EXEC_ARBITRARY.
	SourceReclassify Source = "reclassify"
)

// neverDowngrade is the token that, in a tool's profile notes, keeps an
// EXEC_ARBITRARY tool EXEC_ARBITRARY whatever its commands say, because the
// execution context (a PFE shell, a lab-node shell) is itself the risk
// (classification.md section 8).
const neverDowngrade = "never-downgrade"

// Result is the full classification of one tool call.
type Result struct {
	// Class is the final class after the downgrade or escalation rules.
	Class Class
	// ClassSource is the step that set Class.
	ClassSource Source
	// ProfileClass is the class the profile assigned before inspection.
	ProfileClass Class
	// Known reports whether the profile knew the tool at all.
	Known bool
	// Targets, Commands and ConfigPayload are the normalised arguments.
	Targets       []string
	Commands      []string
	ConfigPayload string
	// Reason explains any change from ProfileClass, or why an
	// EXEC_ARBITRARY call was not downgraded. It names the first failing
	// command (quoted, so control characters are escaped) and the check.
	Reason string
}

// Classify normalises the arguments and applies the command rules:
//
//   - EXEC_ARBITRARY tools are downgraded to READ_OPERATIONAL or
//     READ_CONFIG only when every command passes ClassifyCommand, unless
//     the profile notes carry "never-downgrade".
//   - READ_OPERATIONAL tools that carry commands are escalated to
//     READ_CONFIG when a command dumps configuration, and to
//     EXEC_ARBITRARY when a command fails the allow-list. This is
//     defence in depth against servers whose own filter is weaker than
//     their tool name suggests.
//   - Tools missing from the profile are EXEC_ARBITRARY.
func Classify(profile *Profile, tool string, args map[string]any) Result {
	var res Result
	if profile == nil {
		res.Class = ExecArbitrary
		res.ClassSource = SourceFallback
		res.Reason = "no profile for server"
		return res
	}
	spec, ok := profile.Lookup(tool)
	if !ok {
		res.Class = ExecArbitrary
		res.ClassSource = SourceFallback
		res.Reason = fmt.Sprintf("tool %q not in profile %s", tool, profile.Server)
		return res
	}
	res.Known = true
	res.ProfileClass = spec.Class
	res.Class = spec.Class
	res.ClassSource = SourceProfile
	res.Targets, res.Commands, res.ConfigPayload = Normalize(profile, tool, args)

	if len(spec.CommandParams) == 0 {
		return res
	}
	switch spec.Class {
	case ExecArbitrary:
		if strings.Contains(spec.Notes, neverDowngrade) {
			res.Reason = "tool is never downgraded (profile notes: never-downgrade)"
			return res
		}
		cmdClass, idx, check := classifyCommands(res.Commands)
		switch cmdClass {
		case ExecArbitrary:
			res.Reason = failReason(res.Commands, idx, check)
		case ReadOperational:
			res.Class = ReadOperational
			res.ClassSource = SourceDowngrade
			res.Reason = "every command passed the read allow-list"
		case ReadConfig:
			res.Class = ReadConfig
			res.ClassSource = SourceReclassify
			res.Reason = "every command passed the read allow-list; a command reads configuration"
		}
	case ReadOperational:
		cmdClass, idx, check := classifyCommands(res.Commands)
		switch cmdClass {
		case ExecArbitrary:
			res.Class = ExecArbitrary
			res.ClassSource = SourceReclassify
			res.Reason = failReason(res.Commands, idx, check)
		case ReadConfig:
			res.Class = ReadConfig
			res.ClassSource = SourceReclassify
			res.Reason = "a command reads configuration"
		}
	}
	return res
}

// failReason names the first command that failed and the check it failed.
// The command is quoted with %q and cut to 80 bytes: it is agent-supplied
// text on its way to a terminal and an audit line.
func failReason(cmds []string, idx int, check string) string {
	if idx < 0 || idx >= len(cmds) {
		return "no command to check"
	}
	c := cmds[idx]
	if len(c) > 80 {
		c = c[:80] + "..."
	}
	if len(cmds) == 1 {
		return fmt.Sprintf("command %q failed the read allow-list (%s)", c, check)
	}
	return fmt.Sprintf("command %d %q failed the read allow-list (%s)", idx+1, c, check)
}

// stringValues flattens an argument into target strings: a string is split
// on commas, an array is flattened element-wise, anything else is
// formatted. Missing arguments yield nothing.
func stringValues(v any) []string {
	var out []string
	for _, raw := range rawValues(v) {
		for _, part := range strings.Split(raw, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// rawValues flattens an argument into strings without splitting on commas,
// which matters for commands that legitimately contain commas.
func rawValues(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return []string{t}
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, rawValues(e)...)
		}
		return out
	default:
		return []string{fmt.Sprint(t)}
	}
}
