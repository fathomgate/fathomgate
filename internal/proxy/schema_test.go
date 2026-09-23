package proxy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRelabelSchema(t *testing.T) {
	str := map[string]any{"type": "string"}
	obj := func(props map[string]any, extra ...any) map[string]any {
		m := map[string]any{"type": "object", "properties": props}
		for i := 0; i+1 < len(extra); i += 2 {
			m[extra[i].(string)] = extra[i+1]
		}
		return m
	}
	manyProps := map[string]any{}
	for i := range maxSchemaProperties + 1 {
		manyProps[fmt.Sprint("p", i)] = str
	}
	manyEnum := make([]any, maxSchemaEnum+1)
	for i := range manyEnum {
		manyEnum[i] = fmt.Sprint("v", i)
	}
	cases := []struct {
		name    string
		in      any
		wantErr string
		want    string // JSON of the rebuilt schema
	}{
		{"nil", nil, "", "null"},
		{"flat", obj(map[string]any{"pw": str}), "", `{"properties":{"pw":{"type":"string"}},"type":"object"}`},
		{"no type", map[string]any{"properties": map[string]any{"pw": str}}, "", `{"properties":{"pw":{"type":"string"}},"type":"object"}`},
		{"form title labelled, description escaped", obj(map[string]any{}, "title", "NetGuard approval", "description", "a"+rlo), "",
			`{"description":"a` + bs + bs + `u202e","properties":{},"title":"[from s] NetGuard approval","type":"object"}`},
		{"unknown keywords dropped", obj(map[string]any{"pw": map[string]any{
			"type": "string", "x-ui": "danger", "$ref": "#/$defs/x", "pattern": ".*", "minLength": 4.0, "maxLength": 64.0, "format": "password",
		}}, "$defs", map[string]any{"x": str}, "allOf", []any{str}, "x-vendor", 1.0, "additionalProperties", true), "",
			`{"properties":{"pw":{"format":"password","maxLength":64,"minLength":4,"type":"string"}},"type":"object"}`},
		{"property strings escaped", obj(map[string]any{"pw": map[string]any{"type": "string", "title": "t\x1b[2J", "description": "d" + rlo, "default": "x\n"}}), "",
			`{"properties":{"pw":{"default":"x` + bs + bs + `u000a","description":"d` + bs + bs + `u202e","title":"t` + bs + bs + `u001b[2J","type":"string"}},"type":"object"}`},
		{"enum and oneOf kept, oneOf trimmed", obj(map[string]any{
			"mode": map[string]any{"type": "string", "enum": []any{"a", "b"}},
			"site": map[string]any{"type": "string", "oneOf": []any{map[string]any{"const": "lon1", "title": "London" + rlo, "description": "dropped"}}},
		}), "", `{"properties":{"mode":{"enum":["a","b"],"type":"string"},"site":{"oneOf":[{"const":"lon1","title":"London` + bs + bs + `u202e"}],"type":"string"}},"type":"object"}`},
		{"multi-select", obj(map[string]any{"tags": map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []any{"a"}, "pattern": "x"}, "default": []any{"a"}}}), "",
			`{"properties":{"tags":{"default":["a"],"items":{"enum":["a"],"type":"string"},"type":"array"}},"type":"object"}`},
		{"required keeps known names", obj(map[string]any{"pw": str}, "required", []any{"pw", "ghost", 3.0}), "",
			`{"properties":{"pw":{"type":"string"}},"required":["pw"],"type":"object"}`},
		{"non-primitive default dropped", obj(map[string]any{"n": map[string]any{"type": "number", "default": map[string]any{"a": 1.0}}}), "",
			`{"properties":{"n":{"type":"number"}},"type":"object"}`},

		{"not an object", "string", "not a JSON object", ""},
		{"root not object", map[string]any{"type": "array"}, `not "object"`, ""},
		{"properties not object", map[string]any{"type": "object", "properties": []any{}}, "properties is not an object", ""},
		{"required not array", obj(map[string]any{}, "required", "pw"), "required is not an array", ""},
		{"nested object", obj(map[string]any{"creds": map[string]any{"type": "object"}}), "only primitives", ""},
		{"property without type", obj(map[string]any{"x": map[string]any{}}), "only primitives", ""},
		{"property not object", obj(map[string]any{"x": "string"}), "is not an object", ""},
		{"control character in name", obj(map[string]any{"p\nw": str}), "control characters", ""},
		{"bidi in name", obj(map[string]any{"p" + rlo: str}), "control characters", ""},
		{"long name", obj(map[string]any{strings.Repeat("n", maxPropertyName+1): str}), "too long", ""},
		{"too many properties", obj(manyProps), "more than 32 properties", ""},
		{"too many enum values", obj(map[string]any{"e": map[string]any{"type": "string", "enum": manyEnum}}), "1 to 64", ""},
		{"enum value needing escape", obj(map[string]any{"e": map[string]any{"type": "string", "enum": []any{"a\x1b"}}}), "plain string", ""},
		{"enum value not primitive", obj(map[string]any{"e": map[string]any{"type": "string", "enum": []any{map[string]any{}}}}), "plain string", ""},
		{"oneOf without const", obj(map[string]any{"e": map[string]any{"type": "string", "oneOf": []any{map[string]any{"title": "x"}}}}), "no plain const", ""},
		{"array without enum items", obj(map[string]any{"a": map[string]any{"type": "array", "items": str}}), "needs items with an enum", ""},
		{"oversized input", obj(map[string]any{"p": map[string]any{"type": "string", "description": strings.Repeat("d", maxSchemaInput)}}), "larger than", ""},
		{"oversized rebuild", obj(func() map[string]any {
			m := map[string]any{}
			for i := range 10 {
				m[fmt.Sprint("p", i)] = map[string]any{"type": "string", "description": strings.Repeat("d", maxPromptText)}
			}
			return m
		}()), "rebuilt schema is larger", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := relabelSchema("s", tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(got)
			if string(b) != tc.want {
				t.Fatalf("got  %s\nwant %s", b, tc.want)
			}
		})
	}
}
