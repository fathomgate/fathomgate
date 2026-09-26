// SPDX-License-Identifier: FSL-1.1-ALv2

package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/fathomgate/fathomgate/internal/policy"
)

// meraki is the official Cisco Meraki server's profile name (M1-17).
const meraki = "cisco-meraki-mcp-official"

// Look-alike and invisible characters for the spoofing cases, written as
// code points so the source stays ASCII.
var (
	cyrillicE      = string(rune(0x0435))
	zeroWidthSpace = string(rune(0x200b))
)

// TestMatrixRow18Gate carries test-matrix row 18 from arguments to decision
// under read-only: the class of an execute_api call comes from the
// capability table (class_source capability_table), an id the table does
// not list is EXEC_ARBITRARY and denied by no-exec, and the capability-id
// spoofing forms of the threat model never reach a read rule.
func TestMatrixRow18Gate(t *testing.T) {
	t.Parallel()
	g := newGate(t, examplePolicy(t, "read-only"), false)
	const noExec = "fathomgate denied cisco-meraki-mcp-official.execute_api: rule no-exec (class EXEC_ARBITRARY): EXEC_ARBITRARY is denied: the call runs commands outside the read allow-list or outside configuration mode"
	allowed := func(class string) want {
		return want{effect: "allow", rule: "reads-anywhere", class: class, source: "capability_table", forward: true}
	}
	denied := want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY", source: "capability_table", text: noExec}
	for _, tc := range []struct {
		name string
		args map[string]any
		w    want
	}{
		{"inventory capability", map[string]any{"capability_id": "getOrganizations"}, allowed("INVENTORY_READ")},
		{"operational capability", map[string]any{"capability_id": "getOrganizationDevicesStatusesOverview"}, allowed("READ_OPERATIONAL")},
		{"config capability", map[string]any{"capability_id": "getNetworkWirelessSsids"}, allowed("READ_CONFIG")},
		{"unlisted write", map[string]any{"capability_id": "rebootDevice"}, denied},
		{"unlisted delete", map[string]any{"capability_id": "deleteNetwork"}, denied},
		{"case variant", map[string]any{"capability_id": "GetOrganizations"}, denied},
		{"padded", map[string]any{"capability_id": "getOrganizations "}, denied},
		{"look-alike", map[string]any{"capability_id": "g" + cyrillicE + "tOrganizations"}, denied},
		{"zero-width space", map[string]any{"capability_id": "get" + zeroWidthSpace + "Organizations"}, denied}, //nolint:misspell // Meraki API operation id
		{"trailing newline", map[string]any{"capability_id": "getOrganizations\n"}, denied},
		{"missing", map[string]any{}, denied},
		{"null", map[string]any{"capability_id": nil}, denied},
		{"empty", map[string]any{"capability_id": ""}, denied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := g.Decide(context.Background(), call(meraki, "execute_api", tc.args))
			check(t, tc.name, v, tc.w)
			if len(v.Targets) != 0 {
				t.Errorf("targets %q; execute_api names none", v.Targets)
			}
			if id, _ := tc.args["capability_id"].(string); id != "" && strings.Contains(v.Error, id) {
				t.Errorf("error quotes the capability id: %q", v.Error)
			}
		})
	}
}

// TestCapabilityArguments: the ADR 0033 closed list on the meta-tool.
// parameters is refused whatever its value; capability_id must be one
// string the upstream cannot parse as JSON. Both are default:bad_arguments
// before Evaluate, never stripped and never named to the agent.
func TestCapabilityArguments(t *testing.T) {
	t.Parallel()
	g := newGate(t, examplePolicy(t, "read-only"), false)
	for _, tc := range []struct {
		name   string
		args   map[string]any
		class  string
		reason string
	}{
		{"parameters with a listed id", map[string]any{"capability_id": "getOrganizationDevices", "parameters": map[string]any{"organizationId": "123456"}}, "INVENTORY_READ", reasonUnnamed},
		{"parameters null", map[string]any{"capability_id": "getOrganizations", "parameters": nil}, "INVENTORY_READ", reasonUnnamed},
		{"parameters with an unlisted id", map[string]any{"capability_id": "rebootDevice", "parameters": map[string]any{"serial": "Q2XX-FAKE"}}, "EXEC_ARBITRARY", reasonUnnamed},
		{"case variant of the argument name", map[string]any{"Capability_id": "getOrganizations"}, "EXEC_ARBITRARY", reasonUnnamed},
		{"number", map[string]any{"capability_id": 7}, "EXEC_ARBITRARY", reasonMalformedCapability},
		{"boolean", map[string]any{"capability_id": true}, "EXEC_ARBITRARY", reasonMalformedCapability},
		{"list", map[string]any{"capability_id": []any{"getOrganizations"}}, "EXEC_ARBITRARY", reasonMalformedCapability},
		{"object", map[string]any{"capability_id": map[string]any{"id": "getOrganizations"}}, "EXEC_ARBITRARY", reasonMalformedCapability},
		{"JSON list string", map[string]any{"capability_id": `["getOrganizations"]`}, "EXEC_ARBITRARY", reasonMalformedCapability},
		{"JSON null string", map[string]any{"capability_id": "null"}, "EXEC_ARBITRARY", reasonMalformedCapability},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := g.Decide(context.Background(), call(meraki, "execute_api", tc.args))
			check(t, tc.name, v, want{effect: "deny", rule: policy.RuleBadArguments, class: tc.class, source: "capability_table",
				text: "fathomgate denied cisco-meraki-mcp-official.execute_api: rule default:bad_arguments (class " + tc.class + "): " + tc.reason})
		})
	}

	// The proxy advertises only the named arguments (ADR 0033 section 4):
	// capability_id stays, parameters goes.
	named, closed := g.Arguments(meraki, "execute_api")
	if !closed || !reflect.DeepEqual(named, []string{"capability_id"}) {
		t.Errorf("Arguments(execute_api) = %q closed=%v", named, closed)
	}
	named, closed = g.Arguments(meraki, "semantic_search")
	if !closed || !reflect.DeepEqual(named, []string{"query", "top_k"}) {
		t.Errorf("Arguments(semantic_search) = %q closed=%v", named, closed)
	}
	v := g.Decide(context.Background(), call(meraki, "semantic_search", map[string]any{"query": "devices offline in my org", "top_k": 5}))
	check(t, "semantic_search", v, want{effect: "allow", rule: "reads-anywhere", class: "INVENTORY_READ", source: "profile", forward: true})
}

// TestCapabilityRawJSON: the id the gate looks up is the one the upstream
// receives. A JSON escape in the key or the value decodes to the same text
// in both, a lone surrogate becomes U+FFFD in Go and matches nothing,
// invalid UTF-8 and a duplicate key (also one spelt with an escape, in
// either order) are refused before classification, so two parsers cannot
// pick different ids, and the proxy forwards the re-encoded object it
// checked.
//
// The escapes are built from one backslash byte (esc), never written out,
// and each escaped case must still hold a backslash-u in its bytes: an
// editor that decodes escape sequences in source once turned these cases
// into plain text, and they then tested nothing (security review of PR
// #196, F2).
func TestCapabilityRawJSON(t *testing.T) {
	t.Parallel()
	g := newGate(t, examplePolicy(t, "read-only"), false)
	backslashU := string([]byte{0x5c, 'u'})
	esc := func(hex string) string { return backslashU + hex }
	const plain = `{"capability_id":"getOrganizations"}`
	allowed := want{effect: "allow", rule: "reads-anywhere", class: "INVENTORY_READ", source: "capability_table", forward: true}
	noExec := want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY", source: "capability_table"}
	badArgs := want{effect: "deny", rule: policy.RuleBadArguments, class: "EXEC_ARBITRARY", source: "capability_table",
		text: "fathomgate denied cisco-meraki-mcp-official.execute_api: rule default:bad_arguments (class EXEC_ARBITRARY): " + reasonNotObject}
	for _, tc := range []struct {
		name    string
		args    string
		escapes int // how many escapes the bytes must hold
		w       want
	}{
		{"escaped letter in the value", `{"capability_id":"` + esc("0067") + `etOrganizations"}`, 1, allowed},
		{"every letter of the value escaped", `{"capability_id":"` + escapeAll("getOrganizations", esc) + `"}`, len("getOrganizations"), allowed},
		{"escaped key", `{"capability` + esc("005f") + `id":"getOrganizations"}`, 1, allowed},
		{"escaped key and value", `{"capability` + esc("005f") + `id":"` + esc("0067") + `etOrganizations"}`, 2, allowed},
		{"escaped unlisted id", `{"capability_id":"` + esc("0072") + `ebootDevice"}`, 1, noExec},
		{"escaped upper-case letter", `{"capability_id":"` + esc("0047") + `etOrganizations"}`, 1, noExec},
		{"lone surrogate", `{"capability_id":"getOrganizations` + esc("d800") + `"}`, 1, noExec},
		{"escaped NUL", `{"capability_id":"getOrganizations` + esc("0000") + `"}`, 1, noExec},
		{"duplicate key", `{"capability_id":"getOrganizations","capability_id":"rebootDevice"}`, 0, badArgs},
		{"duplicate key through an escape, plain first", `{"capability_id":"getOrganizations","capability` + esc("005f") + `id":"rebootDevice"}`, 1, badArgs},
		{"duplicate key through an escape, escaped first", `{"capability` + esc("005f") + `id":"rebootDevice","capability_id":"getOrganizations"}`, 1, badArgs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if n := strings.Count(tc.args, backslashU); n != tc.escapes {
				t.Fatalf("the case holds %d escapes, want %d: %q", n, tc.escapes, tc.args)
			}
			if tc.escapes > 0 && len(tc.args) <= len(plain) {
				t.Fatalf("an escaped case is no longer than the plain form: %q", tc.args)
			}
			in := call(meraki, "execute_api", nil)
			in.Arguments = json.RawMessage(tc.args)
			check(t, tc.name, g.Decide(context.Background(), in), tc.w)
		})
	}
	in := call(meraki, "execute_api", nil)
	in.Arguments = json.RawMessage(append([]byte(`{"capability_id":"getOrganizations`), 0xff, '"', '}'))
	check(t, "invalid UTF-8", g.Decide(context.Background(), in), want{effect: "deny", rule: policy.RuleBadArguments, class: "EXEC_ARBITRARY", source: "capability_table"})
}

// escapeAll writes every byte of an ASCII string as a JSON escape.
func escapeAll(s string, esc func(string) string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteString(esc(fmt.Sprintf("%04x", s[i])))
	}
	return b.String()
}

// TestCapabilityAnnotations: invariant 3 on the meta-tool. A readOnlyHint
// false or destructiveHint true raises a listed read capability to
// EXEC_ARBITRARY (annotation_raise); readOnlyHint true, which is what the
// upstream sends, never lowers an unlisted capability.
func TestCapabilityAnnotations(t *testing.T) {
	t.Parallel()
	g := newGate(t, examplePolicy(t, "read-only"), false)
	yes, no := true, false
	for _, tc := range []struct {
		name               string
		id                 string
		readOnly, destruct *bool
		w                  want
	}{
		{"readOnlyHint false on a listed read", "getOrganizations", &no, nil,
			want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY", source: "annotation_raise"}},
		{"destructiveHint true on a listed config read", "getNetworkWirelessSsids", nil, &yes,
			want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY", source: "annotation_raise"}},
		{"readOnlyHint true on an unlisted id", "rebootDevice", &yes, &no,
			want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY", source: "capability_table"}},
		{"readOnlyHint false on an unlisted id keeps its source", "rebootDevice", &no, nil,
			want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY", source: "capability_table"}},
		{"upstream's own hints on a listed read", "getOrganizationDevicesStatusesOverview", &yes, nil,
			want{effect: "allow", rule: "reads-anywhere", class: "READ_OPERATIONAL", source: "capability_table", forward: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := call(meraki, "execute_api", map[string]any{"capability_id": tc.id})
			in.ReadOnlyHint, in.DestructiveHint = tc.readOnly, tc.destruct
			check(t, tc.name, g.Decide(context.Background(), in), tc.w)
		})
	}
}

// TestCapabilityRecord: the decision log line carries class_source
// capability_table and never the capability id, which is agent text.
func TestCapabilityRecord(t *testing.T) {
	t.Parallel()
	g := newGate(t, examplePolicy(t, "read-only"), false)
	for _, id := range []string{"getOrganizations", "rebootDeviceFAKEmarker"} {
		line := logLine(g.Decide(context.Background(), call(meraki, "execute_api", map[string]any{"capability_id": id})))
		if !strings.Contains(line, `"class_source":"capability_table"`) {
			t.Errorf("%s: no class_source in %s", id, line)
		}
		if strings.Contains(line, "FAKEmarker") {
			t.Errorf("%s: log line carries the id: %s", id, line)
		}
	}
}
