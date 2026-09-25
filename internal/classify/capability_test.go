// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// metaProfile is a small meta-tool profile for the table tests: one
// capability table, one meta-tool that reads it, one ordinary tool.
const metaProfile = `server: meta
tools:
  execute_api:
    class: EXEC_ARBITRARY
    capability_param: capability_id
    capability_table: dashboard
    args: []
    refused_args: [parameters]
  search:
    class: INVENTORY_READ
    args: [query]
capabilities:
  dashboard:
    getOrganizations: INVENTORY_READ
    getNetworkClients: READ_OPERATIONAL
    getNetworkWirelessSsids: READ_CONFIG
    rebootDevice: write_config
`

func loadMeta(t testing.TB) *Profile {
	t.Helper()
	p, err := ParseProfile([]byte(metaProfile))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestParseCapabilityFields: the loader accepts profile-schema section 3's
// three fields and refuses every malformed shape of them.
func TestParseCapabilityFields(t *testing.T) {
	p := loadMeta(t)
	spec := p.Tools["execute_api"]
	if spec.CapabilityParam != "capability_id" || spec.CapabilityTable != "dashboard" {
		t.Fatalf("fields not parsed: %+v", spec)
	}
	if got := p.Capabilities["dashboard"]["rebootDevice"]; got != WriteConfig {
		t.Errorf("class spelling not normalised: %q", got)
	}
	if !spec.Named("capability_id") || spec.Named("parameters") {
		t.Errorf("named set: capability_id %v, parameters %v", spec.Named("capability_id"), spec.Named("parameters"))
	}

	tool := func(extra string) string {
		return "server: s\ntools:\n  x:\n    class: EXEC_ARBITRARY\n    args: []\n" + extra
	}
	table := "capabilities:\n  t:\n    getA: READ_OPERATIONAL\n"
	withTable := "    capability_param: id\n    capability_table: t\n"
	for _, tc := range []struct {
		name, yaml, want string
	}{
		{"param without table", tool("    capability_param: id\n" + table), "go together"},
		{"table without param", tool("    capability_table: t\n" + table), "go together"},
		{"unknown table", tool("    capability_param: id\n    capability_table: u\n" + table), "not a table in capabilities"},
		{"no capabilities at all", tool(withTable), "not a table in capabilities"},
		{"meta-tool not EXEC_ARBITRARY", strings.Replace(tool(withTable+table), "EXEC_ARBITRARY", "READ_OPERATIONAL", 1), "must have class EXEC_ARBITRARY"},
		{"meta-tool with command_params", tool(withTable + "    command_params: [command]\n" + table), "cannot have command_params or config_params"},
		{"meta-tool with config_params", tool(withTable + "    config_params: [config]\n" + table), "cannot have command_params or config_params"},
		{"table no tool uses", tool("capabilities:\n  t:\n    getA: READ_OPERATIONAL\n"), "not the capability_table of any tool"},
		{"second table unused", tool(withTable + table + "  u:\n    getB: READ_OPERATIONAL\n"), `table "u" is not the capability_table`},
		{"empty table", tool(withTable + "capabilities:\n  t: {}\n"), "is empty"},
		{"null table", tool(withTable + "capabilities:\n  t:\n"), "is empty"},
		{"unknown class", tool(withTable + "capabilities:\n  t:\n    getA: READ_EVERYTHING\n"), "parse profile"},
		{"id with space", tool(withTable + "capabilities:\n  t:\n    \"get A\": READ_OPERATIONAL\n"), "printable ASCII"},
		{"id with trailing space", tool(withTable + "capabilities:\n  t:\n    \"getA \": READ_OPERATIONAL\n"), "printable ASCII"},
		{"id with tab", tool(withTable + "capabilities:\n  t:\n    \"get\\tA\": READ_OPERATIONAL\n"), "printable ASCII"},
		{"id non-ASCII look-alike", tool(withTable + "capabilities:\n  t:\n    \"g\u0435tA\": READ_OPERATIONAL\n"), "printable ASCII"},
		{"id zero-width space", tool(withTable + "capabilities:\n  t:\n    \"get\u200bA\": READ_OPERATIONAL\n"), "printable ASCII"},
		{"id empty", tool(withTable + "capabilities:\n  t:\n    \"\": READ_OPERATIONAL\n"), "printable ASCII"},
		{"id reads as JSON null", tool(withTable + "capabilities:\n  t:\n    \"null\": READ_OPERATIONAL\n"), "must not read as JSON"},
		{"id reads as JSON array", tool(withTable + "capabilities:\n  t:\n    \"[getA]\": READ_OPERATIONAL\n"), "must not read as JSON"},
		{"id too long", tool(withTable + "capabilities:\n  t:\n    " + strings.Repeat("g", maxCapabilityID+1) + ": READ_OPERATIONAL\n"), "printable ASCII"},
		{"ids differ only in case", tool(withTable + "capabilities:\n  t:\n    getA: READ_OPERATIONAL\n    GetA: WRITE_CONFIG\n"), "differ only in letter case"},
		{"duplicate id", tool(withTable + "capabilities:\n  t:\n    getA: READ_OPERATIONAL\n    getA: WRITE_CONFIG\n"), "parse profile"},
		{"table name padded", tool("    capability_param: id\n    capability_table: \" t\"\ncapabilities:\n  \" t\":\n    getA: READ_OPERATIONAL\n"), "surrounding space"},
		{"table as a list", tool(withTable + "capabilities:\n  t:\n    - getA\n"), "parse profile"},
		{"param also in args", strings.Replace(tool(withTable+table), "args: []", "args: [id]", 1), `"id" named twice`},
		{"param also refused", tool(withTable + "    refused_args: [id]\n" + table), "both named"},
		{"param padded", tool("    capability_param: \" id\"\n    capability_table: t\n" + table), "surrounding space"},
		{"unknown key beside the table fields", tool(withTable + "    capability_default: READ_OPERATIONAL\n" + table), "parse profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseProfile([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}

	// Two meta-tools may share one table.
	two := tool(withTable+table) + ""
	two = strings.Replace(two, "tools:\n", "tools:\n  y:\n    class: EXEC_ARBITRARY\n    capability_param: id\n    capability_table: t\n    args: []\n", 1)
	if _, err := ParseProfile([]byte(two)); err != nil {
		t.Errorf("two tools on one table: %v", err)
	}
}

// fixedCapabilityReasons are the only reasons classifyCapability gives for
// metaProfile. None of them carries the agent's id.
var fixedCapabilityReasons = map[string]bool{
	"no capability id":                                true,
	"capability id is not a string":                   true,
	"capability not in capability table dashboard":    true,
	"capability listed in capability table dashboard": true,
}

// TestCapabilityClassify: the class of a meta-tool call is the table's
// class for an id it lists byte for byte, and EXEC_ARBITRARY for anything
// else, with class_source capability_table either way. The spoofing forms
// are the threat-model row for capability-id spoofing.
func TestCapabilityClassify(t *testing.T) {
	p := loadMeta(t)
	for _, tc := range []struct {
		name string
		args map[string]any
		want Class
	}{
		{"listed inventory", map[string]any{"capability_id": "getOrganizations"}, InventoryRead},
		{"listed operational", map[string]any{"capability_id": "getNetworkClients"}, ReadOperational},
		{"listed config", map[string]any{"capability_id": "getNetworkWirelessSsids"}, ReadConfig},
		{"listed write", map[string]any{"capability_id": "rebootDevice"}, WriteConfig},
		{"not listed", map[string]any{"capability_id": "deleteNetwork"}, ExecArbitrary},
		{"missing", map[string]any{}, ExecArbitrary},
		{"no arguments at all", nil, ExecArbitrary},
		{"null", map[string]any{"capability_id": nil}, ExecArbitrary},
		{"empty string", map[string]any{"capability_id": ""}, ExecArbitrary},
		{"number", map[string]any{"capability_id": float64(1)}, ExecArbitrary},
		{"boolean", map[string]any{"capability_id": true}, ExecArbitrary},
		{"array of the id", map[string]any{"capability_id": []any{"getOrganizations"}}, ExecArbitrary},
		{"object", map[string]any{"capability_id": map[string]any{"id": "getOrganizations"}}, ExecArbitrary},
		{"lower case", map[string]any{"capability_id": "getorganizations"}, ExecArbitrary},
		{"upper first letter", map[string]any{"capability_id": "GetOrganizations"}, ExecArbitrary},
		{"all caps", map[string]any{"capability_id": "GETORGANIZATIONS"}, ExecArbitrary},
		{"leading space", map[string]any{"capability_id": " getOrganizations"}, ExecArbitrary},
		{"trailing space", map[string]any{"capability_id": "getOrganizations "}, ExecArbitrary},
		{"trailing newline", map[string]any{"capability_id": "getOrganizations\n"}, ExecArbitrary},
		{"trailing NUL", map[string]any{"capability_id": "getOrganizations\x00"}, ExecArbitrary},
		{"tab inside", map[string]any{"capability_id": "get\tOrganizations"}, ExecArbitrary}, //nolint:misspell // Meraki API operation id
		{"no-break space", map[string]any{"capability_id": "getOrganizations\u00a0"}, ExecArbitrary},
		{"zero-width space", map[string]any{"capability_id": "get\u200bOrganizations"}, ExecArbitrary},
		{"zero-width joiner", map[string]any{"capability_id": "getOrganizations\u200d"}, ExecArbitrary},
		{"byte order mark", map[string]any{"capability_id": "\ufeffgetOrganizations"}, ExecArbitrary},
		{"Cyrillic e", map[string]any{"capability_id": "g\u0435tOrganizations"}, ExecArbitrary},
		{"fullwidth", map[string]any{"capability_id": "\uff47\uff45\uff54Organizations"}, ExecArbitrary},
		{"combining mark", map[string]any{"capability_id": "getOrganizations\u0301"}, ExecArbitrary},
		{"replacement character", map[string]any{"capability_id": "getOrganizations\ufffd"}, ExecArbitrary},
		{"JSON string of the id", map[string]any{"capability_id": `"getOrganizations"`}, ExecArbitrary},
		{"JSON array string", map[string]any{"capability_id": `["getOrganizations"]`}, ExecArbitrary},
		{"prefix of an id", map[string]any{"capability_id": "getOrganization"}, ExecArbitrary},
		{"id plus suffix", map[string]any{"capability_id": "getOrganizationsX"}, ExecArbitrary},
		{"path form", map[string]any{"capability_id": "/organizations"}, ExecArbitrary}, //nolint:misspell // Meraki API path
		{"table name", map[string]any{"capability_id": "dashboard"}, ExecArbitrary},
		{"class name", map[string]any{"capability_id": "READ_OPERATIONAL"}, ExecArbitrary},
		{"listed id plus refused parameters", map[string]any{"capability_id": "getOrganizations", "parameters": map[string]any{"organizationId": "1"}}, InventoryRead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, tool := range []string{"execute_api", "meta.execute_api"} {
				r := Classify(p, tool, tc.args)
				if r.Class != tc.want || r.ClassSource != SourceCapabilityTable || r.ProfileClass != ExecArbitrary || !r.Known {
					t.Errorf("%s: class %s source %s profile %s known %v, want %s from capability_table", tool, r.Class, r.ClassSource, r.ProfileClass, r.Known, tc.want)
				}
				if !fixedCapabilityReasons[r.Reason] {
					t.Errorf("%s: reason %q is not one of the fixed texts", tool, r.Reason)
				}
			}
		})
	}

	// An ordinary tool of the same profile is untouched.
	if r := Classify(p, "search", map[string]any{"query": "getOrganizations"}); r.Class != InventoryRead || r.ClassSource != SourceProfile {
		t.Errorf("search: %s from %s", r.Class, r.ClassSource)
	}
	// A tool the profile does not list stays the fallback, even when its
	// arguments name a listed capability.
	if r := Classify(p, "execute_api_v2", map[string]any{"capability_id": "getOrganizations"}); r.Class != ExecArbitrary || r.ClassSource != SourceFallback {
		t.Errorf("unlisted tool: %s from %s", r.Class, r.ClassSource)
	}
}

// TestCapabilityCheckArguments: the capability argument is named; its value
// must be one string that the upstream cannot parse as JSON; the refused
// parameters argument is unnamed whatever its value.
func TestCapabilityCheckArguments(t *testing.T) {
	p := loadMeta(t)
	for _, tc := range []struct {
		name               string
		args               map[string]any
		unnamed, malformed []string
	}{
		{"listed id", map[string]any{"capability_id": "getOrganizations"}, nil, nil},
		{"unlisted id is not malformed", map[string]any{"capability_id": "deleteNetwork"}, nil, nil},
		{"missing", map[string]any{}, nil, nil},
		{"null is absent", map[string]any{"capability_id": nil}, nil, nil},
		{"empty string", map[string]any{"capability_id": ""}, nil, nil},
		{"number", map[string]any{"capability_id": float64(7)}, nil, []string{"capability_id"}},
		{"boolean", map[string]any{"capability_id": false}, nil, []string{"capability_id"}},
		{"array of one string", map[string]any{"capability_id": []any{"getOrganizations"}}, nil, []string{"capability_id"}},
		{"object", map[string]any{"capability_id": map[string]any{}}, nil, []string{"capability_id"}},
		{"JSON array string", map[string]any{"capability_id": `["getOrganizations"]`}, nil, []string{"capability_id"}},
		{"JSON object string", map[string]any{"capability_id": `{"a":1}`}, nil, []string{"capability_id"}},
		{"JSON null string", map[string]any{"capability_id": "null"}, nil, []string{"capability_id"}},
		{"JSON true string", map[string]any{"capability_id": " true "}, nil, []string{"capability_id"}},
		{"parameters refused", map[string]any{"capability_id": "getOrganizations", "parameters": map[string]any{"organizationId": "1"}}, []string{"parameters"}, nil},
		{"parameters null still sent", map[string]any{"capability_id": "getOrganizations", "parameters": nil}, []string{"parameters"}, nil},
		{"parameters empty object", map[string]any{"parameters": map[string]any{}}, []string{"parameters"}, nil},
		{"case variant of the param", map[string]any{"Capability_id": "getOrganizations"}, []string{"Capability_id"}, nil},
		{"padded param name", map[string]any{"capability_id ": "getOrganizations"}, []string{"capability_id "}, nil},
		{"both", map[string]any{"capability_id": 1.0, "x": 1.0}, []string{"x"}, []string{"capability_id"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unnamed, malformed := CheckArguments(p, "execute_api", tc.args)
			if !reflect.DeepEqual(unnamed, tc.unnamed) || !reflect.DeepEqual(malformed, tc.malformed) {
				t.Errorf("unnamed %q malformed %q, want %q %q", unnamed, malformed, tc.unnamed, tc.malformed)
			}
		})
	}
}

// merakiProfile loads the shipped Meraki profile.
func merakiProfile(t testing.TB) *Profile {
	t.Helper()
	p, err := LoadProfile(filepath.Join("..", "..", "profiles", "cisco-meraki-mcp-official.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// fixtureCapability is one row of tests/fixtures/meraki/capabilities.tsv.
type fixtureCapability struct {
	id, category, path string
	required           int
}

// merakiCapabilities reads the capability set the upstream indexes at the
// pinned commit (tests/fixtures/meraki/README.md).
func merakiCapabilities(t testing.TB) []fixtureCapability {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "tests", "fixtures", "meraki", "capabilities.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []fixtureCapability
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 4 {
			t.Fatalf("capabilities.tsv: %q has %d columns", line, len(cols))
		}
		required, err := strconv.Atoi(cols[2])
		if err != nil {
			t.Fatalf("capabilities.tsv: %q: %v", line, err)
		}
		out = append(out, fixtureCapability{id: cols[0], category: cols[1], required: required, path: cols[3]})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// merakiOverrides are the capability table's exceptions to the spec's
// category rule (profiles/cisco-meraki-mcp-official.yaml header). A change
// here is a security decision and needs the security reviewer.
var merakiOverrides = map[string]Class{
	// configure, but an organisation, network or device list or record.
	"getOrganizations":                InventoryRead,
	"getOrganization":                 InventoryRead,
	"getOrganizationNetworks":         InventoryRead,
	"getNetwork":                      InventoryRead,
	"getOrganizationDevices":          InventoryRead,
	"getDevice":                       InventoryRead,
	"getOrganizationInventoryDevices": InventoryRead,
	"getOrganizationInventoryDevice":  InventoryRead,
	// monitor, but carrying configuration values and secrets.
	"getOrganizationConfigurationChanges": ReadConfig,
	"getOrganizationWebhooksLogs":         ReadConfig,
}

// TestMerakiCapabilityTable holds the shipped table to the upstream's
// capability set and to the category rule: every id the upstream indexes
// whose name starts with "get" has a row, the row's class is READ_CONFIG
// for the spec's configure tag and READ_OPERATIONAL for monitor and
// liveTools unless merakiOverrides says otherwise, and the table lists
// nothing the upstream does not index. A new upstream version changes
// capabilities.tsv (generate.py), and this test then fails until the table
// has a row for each new id.
func TestMerakiCapabilityTable(t *testing.T) {
	p := merakiProfile(t)
	table := p.Capabilities[p.Tools["execute_api"].CapabilityTable]
	caps := merakiCapabilities(t)
	if len(caps) != 494 {
		t.Errorf("capabilities.tsv has %d rows; the pinned commit indexes 494", len(caps))
	}
	seen := map[string]bool{}
	counts := map[Class]int{}
	for _, c := range caps {
		seen[c.id] = true
		got, listed := table[c.id]
		if !strings.HasPrefix(c.id, "get") {
			// The upstream refuses an SDK method whose name does not start
			// with "get" (require_get_operation), so it is left out and is
			// EXEC_ARBITRARY.
			if listed {
				t.Errorf("%s: listed as %s, but the upstream refuses it; leave it out", c.id, got)
			}
			continue
		}
		want, override := merakiOverrides[c.id]
		if !override {
			switch c.category {
			case "configure":
				want = ReadConfig
			case "monitor", "liveTools":
				want = ReadOperational
			default:
				t.Errorf("%s: unknown category %q", c.id, c.category)
				continue
			}
		}
		if !listed {
			t.Errorf("%s (%s %s): no row in the capability table", c.id, c.category, c.path)
			continue
		}
		if got != want {
			t.Errorf("%s (%s): table says %s, want %s", c.id, c.category, got, want)
		}
		counts[got]++
	}
	for id := range table {
		if !seen[id] {
			t.Errorf("%s: in the table, but the upstream does not index it", id)
		}
	}
	for id := range merakiOverrides {
		if !seen[id] {
			t.Errorf("override %s names no upstream capability", id)
		}
	}
	want := map[Class]int{ReadConfig: 328, ReadOperational: 157, InventoryRead: 8}
	if !reflect.DeepEqual(counts, want) {
		t.Errorf("class counts %v, want %v", counts, want)
	}
	// No table class is a write, exec, lab or local class: the upstream only
	// reaches GET operations, so a row that says otherwise is a mistake.
	for id, c := range table {
		if !c.IsRead() {
			t.Errorf("%s: %s is not a read class", id, c)
		}
	}
}

// TestMerakiToolsListFixture: the profile's named set plus refused_args is
// exactly the property set of each tool in the upstream's own tools/list,
// and no named argument outside the capability parameter has an object
// schema (ADR 0033 section 5, the tier 2 rule, applied here to the tier 1
// fixture).
func TestMerakiToolsListFixture(t *testing.T) {
	p := merakiProfile(t)
	b, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "meraki", "tools-list.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Properties map[string]map[string]any `json:"properties"`
				Required   []string                  `json:"required"`
			} `json:"inputSchema"`
			Annotations map[string]any `json:"annotations"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Tools) != len(p.Tools) {
		t.Errorf("tools/list has %d tools, profile %d", len(doc.Tools), len(p.Tools))
	}
	for _, tool := range doc.Tools {
		spec, ok := p.Tools[tool.Name]
		if !ok {
			t.Errorf("%s: in tools/list, not in the profile", tool.Name)
			continue
		}
		props := make([]string, 0, len(tool.InputSchema.Properties))
		for k := range tool.InputSchema.Properties {
			props = append(props, k)
		}
		sort.Strings(props)
		covered := sorted(append(spec.NamedArgs(), spec.RefusedArgs...))
		if !reflect.DeepEqual(props, covered) {
			t.Errorf("%s: tools/list properties %q, profile named plus refused %q", tool.Name, props, covered)
		}
		if want := sorted(upstreamParams[p.Server][tool.Name]); !reflect.DeepEqual(props, want) {
			t.Errorf("%s: tools/list properties %q, upstreamParams %q", tool.Name, props, want)
		}
		for _, name := range spec.Args {
			if schema := tool.InputSchema.Properties[name]; schema["type"] == "object" || schema["properties"] != nil || schema["additionalProperties"] != nil {
				t.Errorf("%s.%s: named in args with an object schema", tool.Name, name)
			}
		}
		// Every argument the upstream requires is named, so the tool stays
		// usable once the proxy drops the unnamed ones from the schema.
		for _, r := range tool.InputSchema.Required {
			if !spec.Named(r) {
				t.Errorf("%s: required argument %s is not named", tool.Name, r)
			}
		}
	}
	// The capability parameter is a plain string in the upstream schema, so
	// FastMCP does not json.loads it.
	for _, tool := range doc.Tools {
		if tool.Name == "execute_api" {
			if typ := tool.InputSchema.Properties["capability_id"]["type"]; typ != "string" {
				t.Errorf("execute_api capability_id type %v", typ)
			}
			// The upstream says read-only. That hint never lowers a class:
			// an unlisted capability stays EXEC_ARBITRARY (TestMatrixRow18,
			// and internal/gate TestCapabilityAnnotations).
			if ro := tool.Annotations["readOnlyHint"]; ro != true {
				t.Errorf("execute_api readOnlyHint %v; the fixture should record the upstream's true", ro)
			}
		}
	}
}

// TestMatrixRow18 is test-matrix row 18 at tier 1: through the shipped
// Meraki profile, the class of an execute_api call comes from the
// capability_id table with class_source capability_table, and an id the
// table does not list is EXEC_ARBITRARY. The two Meraki rows of
// classification.md section 9 are the first two cases.
func TestMatrixRow18(t *testing.T) {
	p := merakiProfile(t)
	for _, tc := range []struct {
		id   any
		want Class
	}{
		{"getOrganizationDevices", InventoryRead},
		{"rebootDevice", ExecArbitrary},
		{"getOrganizations", InventoryRead},
		{"getOrganizationDevicesStatusesOverview", ReadOperational},
		{"getDeviceLiveToolsPing", ReadOperational},
		{"getNetworkWirelessSsids", ReadConfig},
		{"getNetworkSnmp", ReadConfig},
		{"getOrganizationConfigurationChanges", ReadConfig},
		{"getOrganizationWebhooksLogs", ReadConfig},
		{"clipDeviceCamera", ExecArbitrary},
		{"getNetworkDevices", ExecArbitrary}, // deprecated in the pinned spec, so not indexed
		{"updateNetwork", ExecArbitrary},
		{"deleteNetwork", ExecArbitrary},
		{"createDeviceLiveToolsPing", ExecArbitrary},
		{"claimNetworkDevices", ExecArbitrary},
		{"GetOrganizations", ExecArbitrary},
		{"getorganizations", ExecArbitrary},
		{"getOrganizations ", ExecArbitrary},
		{"g\u0435tOrganizations", ExecArbitrary},
		{"", ExecArbitrary},
		{nil, ExecArbitrary},
		{42.0, ExecArbitrary},
	} {
		args := map[string]any{"capability_id": tc.id}
		r := Classify(p, "execute_api", args)
		if r.Class != tc.want || r.ClassSource != SourceCapabilityTable {
			t.Errorf("capability_id %q: %s from %s, want %s from capability_table", tc.id, r.Class, r.ClassSource, tc.want)
		}
		if s, ok := tc.id.(string); ok && s != "" && strings.Contains(r.Reason, s) {
			t.Errorf("capability_id %q: reason %q quotes it", s, r.Reason)
		}
	}
	// The ids that work with parameters refused: those with no required
	// path or query parameter (the profile header lists them).
	var free []string
	for _, c := range merakiCapabilities(t) {
		if c.required == 0 && strings.HasPrefix(c.id, "get") {
			free = append(free, c.id)
		}
	}
	want := []string{"getAdministeredIdentitiesMe", "getAdministeredIdentitiesMeApiKeys", "getAdministeredLicensingSubscriptionEntitlements", "getOrganizations"}
	if !reflect.DeepEqual(free, want) {
		t.Errorf("capabilities with no required parameter %q, want %q (update the profile header)", free, want)
	}
}

// FuzzCapabilityLookup: for any capability_id string, a meta-tool call is
// the table's class exactly when the string is a key byte for byte, and
// EXEC_ARBITRARY otherwise; the source is always capability_table and the
// reason one of the fixed texts.
func FuzzCapabilityLookup(f *testing.F) {
	for _, s := range []string{
		"getOrganizations", "getorganizations", " getOrganizations", "getOrganizations\n",
		"g\u0435tOrganizations", "get\u200bOrganizations", "rebootDevice", "", "null", "[\"getOrganizations\"]",
		"getOrganizations\x00", "\xff\xfe", "getNetworkWirelessSsids", "READ_CONFIG",
	} {
		f.Add(s)
	}
	p := loadMeta(f)
	table := p.Capabilities["dashboard"]
	f.Fuzz(func(t *testing.T, id string) {
		r := Classify(p, "execute_api", map[string]any{"capability_id": id})
		want, listed := table[id]
		if !listed {
			want = ExecArbitrary
		}
		if r.Class != want || r.ClassSource != SourceCapabilityTable {
			t.Fatalf("%q: %s from %s, want %s", id, r.Class, r.ClassSource, want)
		}
		if !fixedCapabilityReasons[r.Reason] {
			t.Fatalf("%q: reason %q", id, r.Reason)
		}
		if listed && (!utf8.ValidString(id) || !validCapabilityID(id)) {
			t.Fatalf("%q matched but is not a valid table key", id)
		}
	})
}

// FuzzCapabilityTableKey: whatever key a profile author writes, a table
// that validates holds only keys the lookup can match exactly, and every
// variant of a key that differs from it (case, padding, a trailing
// character) is EXEC_ARBITRARY.
func FuzzCapabilityTableKey(f *testing.F) {
	for _, s := range []string{"getOrganizations", "get A", "g\u0435t", "null", "[x", "A", strings.Repeat("g", 129), "get-x.y:z"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, key string) {
		p := &Profile{
			Server: "s",
			Tools: map[string]ToolSpec{"x": {
				Class: ExecArbitrary, CapabilityParam: "id", CapabilityTable: "t", Args: []string{},
			}},
			Capabilities: map[string]map[string]Class{"t": {key: ReadOperational}},
		}
		if err := p.Validate(); err != nil {
			return
		}
		if !validCapabilityID(key) {
			t.Fatalf("%q validated but is not a valid id", key)
		}
		if r := Classify(p, "x", map[string]any{"id": key}); r.Class != ReadOperational {
			t.Fatalf("%q: exact key gives %s", key, r.Class)
		}
		for _, v := range []string{strings.ToUpper(key), strings.ToLower(key), " " + key, key + " ", key + "\u200b", key + "\x00", key[:len(key)-1]} {
			if v == key {
				continue
			}
			if r := Classify(p, "x", map[string]any{"id": v}); r.Class != ExecArbitrary {
				t.Fatalf("variant %q of %q gives %s", v, key, r.Class)
			}
		}
	})
}
