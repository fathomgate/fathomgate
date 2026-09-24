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

// Result is the full classification of one tool call.
type Result struct {
	// Class is the final class after the downgrade or escalation rules.
	Class Class
	// ProfileClass is the class the profile assigned before inspection.
	ProfileClass Class
	// Known reports whether the profile knew the tool at all.
	Known bool
	// Targets, Commands and ConfigPayload are the normalised arguments.
	Targets       []string
	Commands      []string
	ConfigPayload string
	// Reason explains any change from ProfileClass.
	Reason string
}

// Classify normalises the arguments and applies the command rules:
//
//   - EXEC_ARBITRARY tools are downgraded to READ_OPERATIONAL or
//     READ_CONFIG only when every command passes ClassifyCommand.
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
		res.Reason = "no profile for server"
		return res
	}
	spec, ok := profile.Lookup(tool)
	if !ok {
		res.Class = ExecArbitrary
		res.Reason = fmt.Sprintf("tool %q not in profile %s", tool, profile.Server)
		return res
	}
	res.Known = true
	res.ProfileClass = spec.Class
	res.Class = spec.Class
	res.Targets, res.Commands, res.ConfigPayload = Normalize(profile, tool, args)

	if len(spec.CommandParams) == 0 {
		return res
	}
	cmdClass := ClassifyCommands(res.Commands)
	switch spec.Class {
	case ExecArbitrary:
		if cmdClass != ExecArbitrary {
			res.Class = cmdClass
			res.Reason = "every command passed the read allow-list"
		} else {
			res.Reason = "command failed the read allow-list"
		}
	case ReadOperational:
		if cmdClass != ReadOperational {
			res.Class = cmdClass
			res.Reason = "command escalated by fallback classifier"
		}
	}
	return res
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
