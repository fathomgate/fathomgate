package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Elicitation schemas are rebuilt from an allow-list, never copied: whatever
// an upstream puts in requestedSchema, the agent sees only the keywords
// below, with every human-visible string escaped and the form title
// labelled with the upstream's name. See profile-schema section 8.4.

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
	// maxSchemaFormat bounds a format keyword.
	maxSchemaFormat = 64
)

// relabelSchema rebuilds an upstream elicitation schema from the allow-list:
//
//   - root: type (must be "object" if present), title (labelled), description,
//     properties, required (names of kept properties only);
//   - property: type (string, number, integer, boolean or array), title,
//     description, enum, oneOf (const and title only), items (array only:
//     enum and type only), minimum, maximum, minLength, maxLength, format,
//     default (primitives, or an array of them).
//
// Everything else ($defs, $ref, allOf, x-*, nested object properties, ...)
// is dropped or, where it changes what the form means, refused. Every string
// shown to the human is escaped; enum and const values, which must round
// trip to the upstream unchanged, are refused if they need escaping.
func relabelSchema(server string, s any) (any, error) {
	if s == nil {
		return nil, nil
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSchemaInput {
		return nil, fmt.Errorf("larger than %d bytes", maxSchemaInput)
	}
	var in map[string]any
	if err := json.Unmarshal(raw, &in); err != nil || in == nil {
		return nil, errors.New("not a JSON object")
	}
	if t, ok := in["type"]; ok && t != "object" {
		return nil, fmt.Errorf(`type is %v, not "object"`, t)
	}
	out := map[string]any{"type": "object"}
	if t, ok := in["title"].(string); ok {
		out["title"] = promptLabel(server) + escapeControl(t, maxPromptText)
	}
	if d, ok := in["description"].(string); ok {
		out["description"] = escapeControl(d, maxPromptText)
	}
	props := map[string]any{}
	if p, ok := in["properties"]; ok {
		pm, ok := p.(map[string]any)
		if !ok {
			return nil, errors.New("properties is not an object")
		}
		if len(pm) > maxSchemaProperties {
			return nil, fmt.Errorf("more than %d properties", maxSchemaProperties)
		}
		for name, v := range pm {
			if name == "" || len(name) > maxPropertyName || strings.IndexFunc(name, isControl) >= 0 {
				return nil, errors.New("a property name is empty, too long or has control characters")
			}
			prop, err := relabelProperty(name, v)
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
			return nil, errors.New("required is not an array")
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
		return nil, err
	}
	if len(b) > maxSchemaBytes {
		return nil, fmt.Errorf("rebuilt schema is larger than %d bytes", maxSchemaBytes)
	}
	return out, nil
}

// relabelProperty rebuilds one property from the allow-list.
func relabelProperty(name string, v any) (map[string]any, error) {
	pm, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("property %q is not an object", name)
	}
	t, _ := pm["type"].(string)
	switch t {
	case "string", "number", "integer", "boolean", "array":
	default:
		return nil, fmt.Errorf("property %q has type %v; only primitives are allowed", name, pm["type"])
	}
	out := map[string]any{"type": t}
	for _, k := range []string{"title", "description"} {
		if s, ok := pm[k].(string); ok {
			out[k] = escapeControl(s, maxPromptText)
		}
	}
	if f, ok := pm["format"].(string); ok {
		out["format"] = escapeControl(f, maxSchemaFormat)
	}
	for _, k := range []string{"minimum", "maximum", "minLength", "maxLength"} {
		if n, ok := pm[k].(float64); ok {
			out[k] = n
		}
	}
	if e, ok := pm["enum"]; ok {
		vals, err := enumValues(name, e)
		if err != nil {
			return nil, err
		}
		out["enum"] = vals
	}
	if o, ok := pm["oneOf"]; ok {
		opts, err := oneOfOptions(name, o)
		if err != nil {
			return nil, err
		}
		out["oneOf"] = opts
	}
	if t == "array" {
		items, ok := pm["items"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("array property %q needs items with an enum", name)
		}
		e, ok := items["enum"]
		if !ok {
			return nil, fmt.Errorf("array property %q needs items with an enum", name)
		}
		vals, err := enumValues(name, e)
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
		if dv, ok := defaultValue(d); ok {
			out["default"] = dv
		}
	}
	return out, nil
}

// enumValue accepts one enum or const value: a string that needs no
// escaping, a number or a boolean.
func enumValue(v any) bool {
	switch x := v.(type) {
	case string:
		return len(x) <= maxPromptText && strings.IndexFunc(x, isControl) < 0
	case float64, bool:
		return true
	default:
		return false
	}
}

func enumValues(name string, e any) ([]any, error) {
	list, ok := e.([]any)
	if !ok || len(list) == 0 || len(list) > maxSchemaEnum {
		return nil, fmt.Errorf("property %q: enum must be an array of 1 to %d values", name, maxSchemaEnum)
	}
	for _, v := range list {
		if !enumValue(v) {
			return nil, fmt.Errorf("property %q: an enum value is not a plain string, number or boolean", name)
		}
	}
	return list, nil
}

func oneOfOptions(name string, o any) ([]any, error) {
	list, ok := o.([]any)
	if !ok || len(list) == 0 || len(list) > maxSchemaEnum {
		return nil, fmt.Errorf("property %q: oneOf must be an array of 1 to %d options", name, maxSchemaEnum)
	}
	out := make([]any, 0, len(list))
	for _, x := range list {
		opt, ok := x.(map[string]any)
		if !ok || !enumValue(opt["const"]) {
			return nil, fmt.Errorf("property %q: a oneOf option has no plain const", name)
		}
		clean := map[string]any{"const": opt["const"]}
		if t, ok := opt["title"].(string); ok {
			clean["title"] = escapeControl(t, maxPromptText)
		}
		out = append(out, clean)
	}
	return out, nil
}

// defaultValue keeps a default that is a primitive or an array of
// primitives, with strings escaped; anything else is dropped.
func defaultValue(d any) (any, bool) {
	switch x := d.(type) {
	case string:
		return escapeControl(x, maxPromptText), true
	case float64, bool:
		return x, true
	case []any:
		if len(x) > maxSchemaEnum {
			return nil, false
		}
		out := make([]any, 0, len(x))
		for _, e := range x {
			v, ok := defaultValue(e)
			if !ok {
				return nil, false
			}
			if _, nested := v.([]any); nested {
				return nil, false
			}
			out = append(out, v)
		}
		return out, true
	default:
		return nil, false
	}
}
