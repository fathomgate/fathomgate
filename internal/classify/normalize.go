// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"fmt"
	"sort"
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
	// UnnamedArgs lists, sorted, the argument names the call carried that
	// the profile does not name for the tool (ADR 0033). MalformedArgs
	// lists, sorted, the target, command and config arguments whose value
	// is not a string or an array of strings. Either one non-empty means
	// the gate denies the call with default:bad_arguments before Evaluate;
	// see ArgumentsOK. The names are agent-chosen text: log them escaped,
	// never put them in the text the agent sees.
	UnnamedArgs   []string
	MalformedArgs []string
}

// ArgumentsOK reports whether the call's arguments passed CheckArguments.
func (r Result) ArgumentsOK() bool {
	return len(r.UnnamedArgs) == 0 && len(r.MalformedArgs) == 0
}

// CheckArguments enforces the profile's closed argument list (ADR 0033).
//
// unnamed holds every argument key the profile does not name for the tool,
// whatever its value: a key sent as "" or null is still sent, and the
// upstream still sees it. For a tool the profile does not list, every key is
// unnamed. malformed holds the named target, command and config arguments
// whose value is neither a string nor an array of strings (a number, a
// boolean, an object, or an array holding anything but strings); null counts
// as absent. Arguments in args are not inspected: any JSON value passes.
//
// With no profile (the fallback classifier, ADR 0027) nothing is checked
// and both are nil. Both results are sorted, so the output does not depend
// on map order.
func CheckArguments(profile *Profile, tool string, args map[string]any) (unnamed, malformed []string) {
	if profile == nil {
		return nil, nil
	}
	spec, known := profile.Lookup(tool)
	for k := range args {
		if !known || !spec.Named(k) {
			unnamed = append(unnamed, k)
		}
	}
	if known {
		for _, l := range [][]string{spec.TargetParams, spec.TargetsParams, spec.GroupParams, spec.CommandParams, spec.ConfigParams} {
			for _, name := range l {
				if v, ok := args[name]; ok && !stringOrStrings(v) {
					malformed = append(malformed, name)
				}
			}
		}
	}
	sort.Strings(unnamed)
	sort.Strings(malformed)
	return unnamed, malformed
}

// stringOrStrings reports whether v is null, a string, or an array whose
// every element is a string, as decoded from JSON.
func stringOrStrings(v any) bool {
	switch t := v.(type) {
	case nil, string, []string:
		return true
	case []any:
		for _, e := range t {
			if _, ok := e.(string); !ok {
				return false
			}
		}
		return true
	default:
		return false
	}
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
//
// Classify also runs CheckArguments and reports its findings in
// UnnamedArgs and MalformedArgs; it does not change the class for them.
// Refusing the call is the gate's job (ADR 0026 step 1, ADR 0033), so
// policy.Evaluate never sees arguments it cannot trust.
func Classify(profile *Profile, tool string, args map[string]any) Result {
	var res Result
	res.UnnamedArgs, res.MalformedArgs = CheckArguments(profile, tool, args)
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
