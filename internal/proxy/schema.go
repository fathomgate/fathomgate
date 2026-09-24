package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Elicitation schemas are rebuilt from an allow-list, never copied: whatever
// an upstream puts in requestedSchema, the agent sees only the keywords
// below, with every human-visible string escaped, the form title and every
// property title labelled with the upstream's name, and nothing that reads
// as another origin label. See profile-schema section 8.4.
//
// Error texts here never quote an upstream value (a type, a name, a
// string): they say what was expected. They reach the agent inside
// netguard's own refusal, so upstream text in them would read as netguard's.

const (
	// maxSchemaInput bounds the upstream schema netguard will parse.
	maxSchemaInput = 64 << 10
	// maxSchemaBytes bounds the rebuilt schema sent to the agent.
	maxSchemaBytes = 16 << 10
	// maxSchemaProperties bounds the properties of one form.
	maxSchemaProperties = 32
	// maxSchemaEnum bounds the enum values or oneOf options of one property.
	maxSchemaEnum = 64
	// maxPropertyName bounds a property name.
	maxPropertyName = 64
)

// Errors of the schema rebuild. Fixed texts: see the package note above.
var (
	errSchemaNotObject   = errors.New("the schema is not a JSON object")
	errSchemaRootType    = errors.New(`the root type is not "object"`)
	errSchemaTooLarge    = fmt.Errorf("the schema is larger than %d bytes", maxSchemaInput)
	errSchemaRebuiltSize = fmt.Errorf("the rebuilt schema is larger than %d bytes", maxSchemaBytes)
	errSchemaProperties  = errors.New("properties is not an object")
	errSchemaTooMany     = fmt.Errorf("more than %d properties", maxSchemaProperties)
	errSchemaName        = fmt.Errorf("a property name is empty, longer than %d bytes or has control characters", maxPropertyName)
	errSchemaPropObject  = errors.New("a property is not an object")
	errSchemaPropType    = errors.New(`a property type is not "string", "number", "integer", "boolean" or "array"`)
	errSchemaRequired    = errors.New("required is not an array")
	errSchemaEnum        = fmt.Errorf("an enum is not an array of 1 to %d plain strings, numbers or booleans", maxSchemaEnum)
	errSchemaOneOf       = fmt.Errorf("a oneOf is not an array of 1 to %d options, each with a plain const", maxSchemaEnum)
	errSchemaItems       = errors.New("an array property has no items with an enum")
	errSchemaLabel       = errors.New("a string reads as an origin label (\"[from\"); only netguard labels prompts")
)

// allowedFormats are the string formats the spec defines for elicitation;
// any other format keyword is dropped.
var allowedFormats = []string{"email", "uri", "date", "date-time"}

// relabelSchema rebuilds an upstream elicitation schema from the allow-list:
//
//   - root: type (must be "object" if present), title (labelled), description,
//     properties, required (names of kept properties only);
//   - property: type (string, number, integer, boolean or array), title
//     (labelled; the property name when absent), description, enum, oneOf
//     (const and title only), items (array only: enum and type only),
//     minimum, maximum, minLength, maxLength, format (email, uri, date or
//     date-time), default (primitives, or an array of them).
//
// Everything else ($defs, $ref, allOf, x-*, nested object properties, ...)
// is dropped or, where it changes what the form means, refused. Every string
// shown to the human is escaped; enum and const values, which must round
// trip to the upstream unchanged, are refused if they need escaping. Any
// shown string, name or value that contains "[from" after case and
// look-alike folding (hasOriginLabel) is refused.
func relabelSchema(server string, s any) (any, error) {
	if s == nil {
		return nil, nil
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("encoding the schema: %w", err)
	}
	if len(raw) > maxSchemaInput {
		return nil, errSchemaTooLarge
	}
	var in map[string]any
	if err := json.Unmarshal(raw, &in); err != nil || in == nil {
		return nil, errSchemaNotObject
	}
	if t, ok := in["type"]; ok && t != "object" {
		return nil, errSchemaRootType
	}
	out := map[string]any{"type": "object"}
	if t, ok := in["title"].(string); ok {
		if hasOriginLabel(t) {
			return nil, errSchemaLabel
		}
		out["title"] = promptLabel(server) + escapeControl(t, maxPromptText)
	}
	if d, ok := in["description"].(string); ok {
		if hasOriginLabel(d) {
			return nil, errSchemaLabel
		}
		out["description"] = escapeControl(d, maxPromptText)
	}
	props := map[string]any{}
	if p, ok := in["properties"]; ok {
		pm, ok := p.(map[string]any)
		if !ok {
			return nil, errSchemaProperties
		}
		if len(pm) > maxSchemaProperties {
			return nil, errSchemaTooMany
		}
		names := make([]string, 0, len(pm))
		for name := range pm {
			names = append(names, name)
		}
		slices.Sort(names) // deterministic errors
		for _, name := range names {
			// Names cross verbatim (the agent's accept content uses them as
			// keys), so one escapeControl would change is refused.
			if name == "" || len(name) > maxPropertyName || strings.IndexFunc(name, isControl) >= 0 || strings.IndexByte(name, backslash) >= 0 {
				return nil, errSchemaName
			}
			if hasOriginLabel(name) {
				return nil, errSchemaLabel
			}
			prop, err := relabelProperty(server, name, pm[name])
			if err != nil {
				return nil, err
			}
			props[name] = prop
		}
		out["properties"] = props
	}
	if r, ok := in["required"]; ok {
		list, ok := r.([]any)
		if !ok {
			return nil, errSchemaRequired
		}
		var req []any
		for _, x := range list {
			if n, ok := x.(string); ok && props[n] != nil {
				req = append(req, n)
			}
		}
		if len(req) > 0 {
			out["required"] = req
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("encoding the rebuilt schema: %w", err)
	}
	if len(b) > maxSchemaBytes {
		return nil, errSchemaRebuiltSize
	}
	return out, nil
}

// relabelProperty rebuilds one property from the allow-list. Its title is
// labelled with the upstream's name, so every field of the form shows its
// origin; a property without a title gets its name as the title.
func relabelProperty(server, name string, v any) (map[string]any, error) {
	pm, ok := v.(map[string]any)
	if !ok {
		return nil, errSchemaPropObject
	}
	t, _ := pm["type"].(string)
	switch t {
	case "string", "number", "integer", "boolean", "array":
	default:
		return nil, errSchemaPropType
	}
	out := map[string]any{"type": t}
	title := name
	if s, ok := pm["title"].(string); ok {
		title = s
	}
	if hasOriginLabel(title) {
		return nil, errSchemaLabel
	}
	out["title"] = promptLabel(server) + escapeControl(title, maxPromptText)
	if s, ok := pm["description"].(string); ok {
		if hasOriginLabel(s) {
			return nil, errSchemaLabel
		}
		out["description"] = escapeControl(s, maxPromptText)
	}
	if f, ok := pm["format"].(string); ok && slices.Contains(allowedFormats, f) {
		out["format"] = f
	}
	for _, k := range []string{"minimum", "maximum", "minLength", "maxLength"} {
		if n, ok := pm[k].(float64); ok {
			out[k] = n
		}
	}
	if e, ok := pm["enum"]; ok {
		vals, err := enumValues(e)
		if err != nil {
			return nil, err
		}
		out["enum"] = vals
	}
	if o, ok := pm["oneOf"]; ok {
		opts, err := oneOfOptions(o)
		if err != nil {
			return nil, err
		}
		out["oneOf"] = opts
	}
	if t == "array" {
		items, ok := pm["items"].(map[string]any)
		if !ok {
			return nil, errSchemaItems
		}
		e, ok := items["enum"]
		if !ok {
			return nil, errSchemaItems
		}
		vals, err := enumValues(e)
		if err != nil {
			return nil, err
		}
		it := map[string]any{"enum": vals}
		if ty, ok := items["type"].(string); ok && (ty == "string" || ty == "number" || ty == "integer") {
			it["type"] = ty
		}
		out["items"] = it
	}
	if d, ok := pm["default"]; ok {
		dv, ok, err := defaultValue(d)
		if err != nil {
			return nil, err
		}
		if ok {
			out["default"] = dv
		}
	}
	return out, nil
}

// enumValue accepts one enum or const value: a string that needs no
// escaping and reads as no origin label, a number or a boolean.
func enumValue(v any) bool {
	switch x := v.(type) {
	case string:
		// Enum values cross verbatim, so one that escapeControl would
		// change (a control character or a backslash) is refused.
		return len(x) <= maxPromptText && strings.IndexFunc(x, isControl) < 0 && !strings.ContainsRune(x, '\\') && !hasOriginLabel(x)
	case float64, bool:
		return true
	default:
		return false
	}
}

func enumValues(e any) ([]any, error) {
	list, ok := e.([]any)
	if !ok || len(list) == 0 || len(list) > maxSchemaEnum {
		return nil, errSchemaEnum
	}
	for _, v := range list {
		if s, ok := v.(string); ok && hasOriginLabel(s) {
			return nil, errSchemaLabel
		}
		if !enumValue(v) {
			return nil, errSchemaEnum
		}
	}
	return list, nil
}

func oneOfOptions(o any) ([]any, error) {
	list, ok := o.([]any)
	if !ok || len(list) == 0 || len(list) > maxSchemaEnum {
		return nil, errSchemaOneOf
	}
	out := make([]any, 0, len(list))
	for _, x := range list {
		opt, ok := x.(map[string]any)
		if !ok {
			return nil, errSchemaOneOf
		}
		if s, ok := opt["const"].(string); ok && hasOriginLabel(s) {
			return nil, errSchemaLabel
		}
		if !enumValue(opt["const"]) {
			return nil, errSchemaOneOf
		}
		clean := map[string]any{"const": opt["const"]}
		if t, ok := opt["title"].(string); ok {
			if hasOriginLabel(t) {
				return nil, errSchemaLabel
			}
			clean["title"] = escapeControl(t, maxPromptText)
		}
		out = append(out, clean)
	}
	return out, nil
}

// defaultValue keeps a default that is a primitive or an array of
// primitives; anything else is dropped (ok false). A default is a value the
// upstream gets back if the human accepts it, so like an enum value it must
// round-trip: a string escapeControl would change (a control character, a
// backslash, invalid UTF-8) or longer than maxPromptText is dropped, and
// the human types the value. A string that reads as an origin label is an
// error.
func defaultValue(d any) (any, bool, error) {
	switch x := d.(type) {
	case string:
		if hasOriginLabel(x) {
			return nil, false, errSchemaLabel
		}
		if len(x) > maxPromptText || escapeControl(x, 0) != x {
			return nil, false, nil
		}
		return x, true, nil
	case float64, bool:
		return x, true, nil
	case []any:
		if len(x) > maxSchemaEnum {
			return nil, false, nil
		}
		out := make([]any, 0, len(x))
		for _, e := range x {
			if _, nested := e.([]any); nested {
				return nil, false, nil
			}
			v, ok, err := defaultValue(e)
			if err != nil || !ok {
				return nil, false, err
			}
			out = append(out, v)
		}
		return out, true, nil
	default:
		return nil, false, nil
	}
}
