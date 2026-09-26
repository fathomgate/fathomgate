// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"encoding/json"
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
		// Commands are trimmed of spaces and tabs only, and empty or
		// whitespace-only elements are kept: a line break at either end is
		// still a second line to the device, and an empty element must fail
		// the downgrade (check empty) rather than vanish from the batch.
		for _, v := range rawValues(args[p]) {
			commands = append(commands, strings.Trim(v, " \t"))
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

// The class sources. Classify emits every one but SourceAnnotationRaise,
// which internal/gate sets when a tool annotation raises a read class
// (Classify has no annotation input).
const (
	// SourceProfile means the profile's class for the tool stands.
	SourceProfile Source = "profile"
	// SourceCapabilityTable means the tool is a meta-tool (its profile entry
	// has capability_param) and its capability table decided the class: the
	// table's class for a capability it lists, EXEC_ARBITRARY for any other
	// value, a missing one or one that is not a string.
	SourceCapabilityTable Source = "capability_table"
	// SourceFallback means there is no profile, or the tool is not in it,
	// and the class is EXEC_ARBITRARY.
	SourceFallback Source = "fallback"
	// SourceAnnotationRaise means a tool annotation raised a read class to
	// EXEC_ARBITRARY. Set by internal/gate, never by Classify.
	SourceAnnotationRaise Source = "annotation_raise"
	// SourceDowngrade means an EXEC_ARBITRARY call whose every command
	// passed the read allow-list is now READ_OPERATIONAL.
	SourceDowngrade Source = "downgrade"
	// SourceReclassify means the arguments moved the class anywhere else:
	// an EXEC_ARBITRARY or READ_OPERATIONAL call that reads configuration
	// is READ_CONFIG, a READ_OPERATIONAL call whose command fails the
	// allow-list is EXEC_ARBITRARY, and a call whose config payload fails
	// the config payload check is EXEC_ARBITRARY.
	SourceReclassify Source = "reclassify"
)

// Sources returns every class source in a stable order.
func Sources() []Source {
	return []Source{
		SourceProfile, SourceCapabilityTable, SourceFallback,
		SourceAnnotationRaise, SourceDowngrade, SourceReclassify,
	}
}

// ParseSource converts a string to a Source. Matching is exact: the values
// are audit spellings, not user input. It returns an error for unknown
// names.
func ParseSource(s string) (Source, error) {
	for _, src := range Sources() {
		if string(src) == s {
			return src, nil
		}
	}
	return "", fmt.Errorf("classify: unknown class source %q", s)
}

// String returns the audit spelling of the source.
func (s Source) String() string { return string(s) }

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
	// command by index and the check, never by its text.
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
// as absent. A string the upstream could itself parse as JSON is malformed
// too (upstreamMayParseJSON). A meta-tool's capability_param must be one
// string: an array is malformed there as well. Arguments in args are not
// inspected: any JSON value passes.
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
		lists := []struct {
			names  []string
			config bool
		}{
			{spec.TargetParams, false}, {spec.TargetsParams, false}, {spec.GroupParams, false},
			{spec.CommandParams, false}, {spec.ConfigParams, true},
		}
		for _, l := range lists {
			for _, name := range l.names {
				v, ok := args[name]
				if !ok {
					continue
				}
				if !stringOrStrings(v) {
					malformed = append(malformed, name)
					continue
				}
				if s, isString := v.(string); isString && upstreamMayParseJSON(s, l.config) {
					malformed = append(malformed, name)
				}
			}
		}
		if name := spec.CapabilityParam; name != "" {
			if v, ok := args[name]; ok && v != nil {
				if s, isString := v.(string); !isString || upstreamMayParseJSON(s, false) {
					malformed = append(malformed, name)
				}
			}
		}
	}
	sort.Strings(unnamed)
	sort.Strings(malformed)
	return unnamed, malformed
}

// upstreamMayParseJSON reports whether a string value of a mapped argument
// could reach the upstream as something other than that string. Python
// FastMCP (mcp 1.x, func_metadata.pre_parse_json) runs json.loads on any
// string sent for a parameter not annotated plain str, so
// hostnames: "[\"core-rtr-01\"]" arrives as a list and hostnames: "null" as
// None (eos-mcp daily_brief then runs on every device), while fathomgate
// would read one opaque target or command (security review of PR #161, H1).
//
// After TrimSpace, a value is refused when it is valid JSON starting with
// [, n, t or f (an array, null, true, false). For target, group and command
// arguments a leading [ or { is refused whether or not Go finds it valid,
// since no hostname, tag or command starts with either and Python's json
// accepts more (NaN, Infinity). A config payload may be a JSON object
// (junos config_text) or Junos text starting "[edit ...]", so there only
// valid JSON arrays and literals are refused.
func upstreamMayParseJSON(s string, config bool) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return false
	}
	switch t[0] {
	case '[', '{':
		if !config {
			return true
		}
		return t[0] == '[' && json.Valid([]byte(t))
	case 'n', 't', 'f':
		return json.Valid([]byte(t))
	}
	return false
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
//     READ_CONFIG only when every command passes ClassifyCommand, unless
//     the profile notes carry "never-downgrade".
//   - READ_OPERATIONAL tools that carry commands are escalated to
//     READ_CONFIG when a command dumps configuration, and to
//     EXEC_ARBITRARY when a command fails the allow-list. This is
//     defence in depth against servers whose own filter is weaker than
//     their tool name suggests.
//   - Tools with config arguments, unless already EXEC_ARBITRARY, are
//     escalated to EXEC_ARBITRARY when a config line leaves configuration
//     mode or runs an exec command (checkConfigPayload). This runs first.
//   - Meta-tools (capability_param in the profile) take the class their
//     capability table gives the capability the call selects, looked up
//     byte for byte; an id the table does not list, a missing id or one
//     that is not a string is EXEC_ARBITRARY. ClassSource is
//     capability_table either way (classifyCapability).
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
		res.ClassSource = SourceFallback
		res.Reason = "no profile for server"
		return res
	}
	spec, ok := profile.Lookup(tool)
	if !ok {
		res.Class = ExecArbitrary
		res.ClassSource = SourceFallback
		res.Reason = "tool not in profile"
		return res
	}
	res.Known = true
	res.ProfileClass = spec.Class
	res.Class = spec.Class
	res.ClassSource = SourceProfile
	res.Targets, res.Commands, res.ConfigPayload = Normalize(profile, tool, args)

	// A meta-tool's class is its capability table's answer. The loader
	// guarantees such a tool has class EXEC_ARBITRARY and no command or
	// config arguments, so no later rule applies.
	if spec.CapabilityParam != "" {
		res.Class, res.Reason = classifyCapability(profile, spec, args)
		res.ClassSource = SourceCapabilityTable
		return res
	}

	// A config payload that leaves configuration mode or runs an exec
	// command makes the call EXEC_ARBITRARY before any command rule runs,
	// so nothing can downgrade it again (classification.md section 11). A
	// tool already EXEC_ARBITRARY has nothing to raise.
	if spec.Class != ExecArbitrary && len(spec.ConfigParams) > 0 {
		if f := checkConfigPayload(profile, tool, spec, args); f != nil {
			res.Class = ExecArbitrary
			res.ClassSource = SourceReclassify
			res.Reason = f.reason()
			return res
		}
	}

	if len(spec.CommandParams) == 0 {
		return res
	}
	switch spec.Class {
	case ExecArbitrary:
		if strings.Contains(strings.ToLower(spec.Notes), neverDowngrade) {
			res.Reason = "tool is never downgraded (profile notes: never-downgrade)"
			return res
		}
		cmdClass, idx, check := classifyCommands(res.Commands)
		switch cmdClass {
		case ExecArbitrary:
			res.Reason = failReason(idx, check)
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
			res.Reason = failReason(idx, check)
		case ReadConfig:
			res.Class = ReadConfig
			res.ClassSource = SourceReclassify
			res.Reason = "a command reads configuration"
		}
	}
	return res
}

// classifyCapability looks the call's capability id up in the tool's
// capability table (profile-schema section 3). The id is the argument's
// value exactly as the upstream receives it: no trimming, no case folding,
// no Unicode normalisation, so a case variant, a padded id or a look-alike
// is not in the table. Anything but a listed id is EXEC_ARBITRARY: a
// missing or null argument, a value that is not a string (which
// CheckArguments also reports as malformed), and an id the table does not
// list, which covers every operation the upstream adds after the profile
// was written. The reason names the table, never the id, which is
// agent-supplied text.
func classifyCapability(profile *Profile, spec ToolSpec, args map[string]any) (Class, string) {
	v := args[spec.CapabilityParam]
	if v == nil {
		return ExecArbitrary, "no capability id"
	}
	id, ok := v.(string)
	if !ok {
		return ExecArbitrary, "capability id is not a string"
	}
	c, ok := profile.Capabilities[spec.CapabilityTable][id]
	if !ok {
		return ExecArbitrary, fmt.Sprintf("capability not in capability table %s", spec.CapabilityTable)
	}
	return c, fmt.Sprintf("capability listed in capability table %s", spec.CapabilityTable)
}

// failReason names the first command that failed, by its 1-based index,
// and the check it failed. It never quotes the command: the command is
// agent-supplied text and the reason may reach the agent and the audit line.
func failReason(idx int, check string) string {
	if idx < 0 {
		return "no command to check"
	}
	return fmt.Sprintf("command %d failed the read allow-list (%s)", idx+1, check)
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
