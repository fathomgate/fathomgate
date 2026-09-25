// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// M1-15, M1 exit criterion 1 (second half of the PRD metric): every tool
// that docs/research/02-network-mcp-servers.md names, on a server with no
// shipped profile, is at least fallback-classified, with a test.
//
// The servers with a shipped profile (netdev-ssh-mcp, upa, eos-mcp,
// junos-mcp-server, ntunes-netmiko-mcp-server) are covered tool by tool in
// TestRepoProfiles and are not repeated here. Meraki execute_api is left to
// M1-17 (capability tables); Meraki semantic_search is here.
//
// Each row carries the class brief 02 gives the tool: its section 2(c)
// mapping table first, its Part 1 table when 2(c) does not list the tool,
// and the stricter of the two when they disagree. A row with brief02Unclassed
// is a tool the brief names but gives no class; for it only EXEC_ARBITRARY
// is acceptable, since the fallback must deny by default.
//
// The fallback class must be at least as strict as the brief's class. A row
// that fails that is a finding for policy-engineer: fix the classifier or
// add a profile, never loosen the row.

// brief02Unclassed marks a tool brief 02 names but does not classify.
const brief02Unclassed Class = ""

// brief02Strictness orders the classes by how strictly the shipped example
// policies treat them. EXEC_ARBITRARY is denied by rule no-exec in all three
// (read-only, lab-open, prod-approval); WRITE_CONFIG is denied or held;
// LAB_LIFECYCLE and LOCAL_ADMIN are denied by read-only (no-lab-or-admin);
// READ_CONFIG is a read with mandatory redaction; READ_OPERATIONAL contacts
// a device; INVENTORY_READ does not. It is a test yardstick, not an
// interface.
var brief02Strictness = map[Class]int{
	InventoryRead:   0,
	ReadOperational: 1,
	ReadConfig:      2,
	LocalAdmin:      3,
	LabLifecycle:    3,
	WriteConfig:     4,
	ExecArbitrary:   5,
}

type brief02Row struct {
	server string
	tool   string
	args   map[string]any
	brief  Class
	// neverDowngrade marks the classification.md section 8 tools: they
	// stay EXEC_ARBITRARY whatever their commands, profile or no profile.
	neverDowngrade bool
}

// brief02Servers are the server keys of the table below. None may have a
// shipped profile: when one lands, its rows move to TestRepoProfiles.
var brief02Servers = []string{
	"scrapli-mcp", "mcp-telecom", "pan-os-mcp", "palo-mcp", "mcfortigate",
	"fortigate-mcp", "cisco-meraki-mcp", "catalyst-center-mcp",
	"catalyst-sdwan-mcp", "pyats-mcp", "netbox-mcp-server", "netbox-mcp-rw",
	"network-discovery-mcp", "clab-mcp-server",
}

const b2dev = "core-rtr-01"

// brief02Rows lists every tool of those servers that brief 02 names.
// Argument names are the brief's; values are representative, and secrets
// are FAKE. Numbers are float64, as JSON decodes them.
var brief02Rows = []brief02Row{
	// 1.2 carlmontanari/scrapli-mcp
	{"scrapli-mcp", "execute_ssh_command", map[string]any{"host": "r1", "command": "show version"}, ExecArbitrary, false},

	// 1.4 mcp-telecom: canned show tools
	{"mcp-telecom", "show_bgp_summary", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_bgp_neighbors", map[string]any{"device": b2dev}, ReadOperational, false}, //nolint:misspell // upstream tool name
	{"mcp-telecom", "show_routing_table", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_ospf_neighbors", map[string]any{"device": b2dev}, ReadOperational, false}, //nolint:misspell // upstream tool name
	{"mcp-telecom", "show_mpls_lsp", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_interfaces", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_interface_detail", map[string]any{"device": b2dev, "interface": "Ethernet1"}, ReadOperational, false},
	{"mcp-telecom", "show_lldp_neighbors", map[string]any{"device": b2dev}, ReadOperational, false}, //nolint:misspell // upstream tool name
	{"mcp-telecom", "show_lag_status", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_arp_table", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_mac_table", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_system_info", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_alarms", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_ntp_status", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_cpu", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_memory", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_environment", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_log_events", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "show_nokia_services", map[string]any{"device": b2dev}, ReadOperational, false},
	// mcp-telecom: config read
	{"mcp-telecom", "backup_config", map[string]any{"device": b2dev}, ReadConfig, false},
	{"mcp-telecom", "compare_configs", map[string]any{"device": b2dev, "backup_file": "core-rtr-01.cfg"}, ReadConfig, false},
	{"mcp-telecom", "netconf_get_config", map[string]any{"device": b2dev, "source": "running"}, ReadConfig, false},
	{"mcp-telecom", "compliance_check", map[string]any{"device": b2dev}, ReadConfig, false},
	{"mcp-telecom", "compliance_check_rule", map[string]any{"device": b2dev, "rule_name": "ntp-configured"}, ReadConfig, false},
	// mcp-telecom: free-form, server allow-list enforced
	{"mcp-telecom", "run_command", map[string]any{"device": b2dev, "command": "show version"}, ReadOperational, false},
	{"mcp-telecom", "parallel_command", map[string]any{"command": "show version", "devices": "core-rtr-01,core-rtr-02", "max_workers": float64(10)}, ReadOperational, false},
	// mcp-telecom: named operations
	{"mcp-telecom", "run_vendor_operation", map[string]any{"device": b2dev, "operation": "bgp_summary"}, ReadOperational, false},
	{"mcp-telecom", "parallel_operation", map[string]any{"operation": "bgp_summary", "devices": ""}, ReadOperational, false},
	{"mcp-telecom", "compare_devices", map[string]any{"operation": "bgp_summary", "devices": "core-rtr-01,core-rtr-02"}, ReadOperational, false},
	// mcp-telecom: inventory and health. health_check is INVENTORY_READ in
	// Part 1 and READ_OPERATIONAL in 2(c); parallel_health_check is only
	// in Part 1.
	{"mcp-telecom", "list_devices", map[string]any{}, InventoryRead, false},
	{"mcp-telecom", "list_device_capabilities", map[string]any{"device": b2dev}, InventoryRead, false},
	{"mcp-telecom", "health_check", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "parallel_health_check", map[string]any{"devices": ""}, InventoryRead, false},
	{"mcp-telecom", "pool_stats", map[string]any{}, InventoryRead, false},
	{"mcp-telecom", "get_audit_log", map[string]any{"count": float64(25)}, InventoryRead, false},
	// mcp-telecom: NETCONF, gNMI, SNMP. telemetry_(un)subscribe is
	// READ_OPERATIONAL in Part 1 and LOCAL_ADMIN in 2(c).
	{"mcp-telecom", "netconf_get_operational", map[string]any{"device": b2dev, "operation": "interfaces"}, ReadOperational, false},
	{"mcp-telecom", "netconf_capabilities", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "telemetry_subscribe", map[string]any{"device": b2dev, "paths": []any{"/interfaces/interface/state/counters"}, "interval_ms": float64(10000)}, LocalAdmin, false},
	{"mcp-telecom", "telemetry_query", map[string]any{"device": b2dev}, ReadOperational, false},
	{"mcp-telecom", "telemetry_history", map[string]any{"device": b2dev, "path": "/interfaces/interface/state/counters", "count": float64(20)}, ReadOperational, false},
	{"mcp-telecom", "telemetry_unsubscribe", map[string]any{"device": b2dev}, LocalAdmin, false},
	{"mcp-telecom", "snmp_get", map[string]any{"device": b2dev, "oids": []any{"1.3.6.1.2.1.1.1.0"}, "community": "FAKEcommunity"}, ReadOperational, false},
	{"mcp-telecom", "snmp_walk", map[string]any{"device": b2dev, "base_oid": "1.3.6.1.2.1.2", "community": "FAKEcommunity"}, ReadOperational, false},
	{"mcp-telecom", "snmp_device_overview", map[string]any{"device": b2dev, "community": "FAKEcommunity"}, ReadOperational, false},
	// mcp-telecom: topology
	{"mcp-telecom", "discover_topology", map[string]any{"devices": ""}, ReadOperational, false},
	{"mcp-telecom", "show_topology", map[string]any{}, ReadOperational, false},
	{"mcp-telecom", "show_topology_json", map[string]any{}, ReadOperational, false},
	{"mcp-telecom", "show_topology_mermaid", map[string]any{}, ReadOperational, false},
	{"mcp-telecom", "find_path", map[string]any{"source": "core-rtr-01", "target": "core-rtr-02"}, ReadOperational, false},
	{"mcp-telecom", "show_device_neighbors", map[string]any{"device": b2dev}, ReadOperational, false}, //nolint:misspell // upstream tool name
	// mcp-telecom: lab and misc
	{"mcp-telecom", "clab_generate", map[string]any{"scenario": "srl-two-node"}, LocalAdmin, false},
	{"mcp-telecom", "clab_devices_yaml", map[string]any{"scenario": "srl-two-node"}, LocalAdmin, false},
	{"mcp-telecom", "clab_scenarios", map[string]any{}, LocalAdmin, false},
	{"mcp-telecom", "start_dashboard", map[string]any{"port": float64(8080)}, LocalAdmin, false},
	{"mcp-telecom", "start_metrics_endpoint", map[string]any{"port": float64(9100)}, LocalAdmin, false},

	// 1.8a cdot65/pan-os-mcp (no parameters; one firewall per instance)
	{"pan-os-mcp", "show_system_info", map[string]any{}, ReadOperational, false},
	{"pan-os-mcp", "retrieve_address_objects", map[string]any{}, ReadConfig, false},
	{"pan-os-mcp", "retrieve_security_zones", map[string]any{}, ReadConfig, false},
	{"pan-os-mcp", "retrieve_security_policies", map[string]any{}, ReadConfig, false},

	// 1.8b apius-tech/Palo-MCP: the four tools the brief names. Parameters
	// other than firewall are not in the brief [doc]; these are
	// representative.
	{"palo-mcp", "list_firewalls", map[string]any{}, InventoryRead, false},
	{"palo-mcp", "set_config", map[string]any{"firewall": "fw-01", "xpath": "/config/devices/entry/vsys/entry/address", "element": "<entry name='FAKE-host'/>"}, WriteConfig, false},
	{"palo-mcp", "delete_config", map[string]any{"firewall": "fw-01", "xpath": "/config/devices/entry/vsys/entry/address/entry[@name='FAKE-host']"}, WriteConfig, false},
	{"palo-mcp", "commit", map[string]any{"firewall": "fw-01"}, WriteConfig, false},

	// 1.9a rsp2k/mcfortigate
	{"mcfortigate", "list_targets", map[string]any{}, InventoryRead, false},
	{"mcfortigate", "get_system_status", map[string]any{"target": "fw-01"}, ReadOperational, false},
	{"mcfortigate", "search_config", map[string]any{"term": "admin", "target": "fw-01"}, ReadConfig, false},
	{"mcfortigate", "list_address_objects", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, ReadConfig, false},
	{"mcfortigate", "list_address_groups", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, ReadConfig, false},
	{"mcfortigate", "list_services", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, ReadConfig, false},
	{"mcfortigate", "list_policies", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, ReadConfig, false},
	{"mcfortigate", "list_vips", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, ReadConfig, false},
	{"mcfortigate", "find_references", map[string]any{"object_name": "web-servers", "target": "fw-01"}, ReadConfig, false},
	{"mcfortigate", "list_interfaces", map[string]any{"target": "fw-01"}, ReadConfig, false},
	{"mcfortigate", "list_vlans", map[string]any{"target": "fw-01"}, ReadConfig, false},
	{"mcfortigate", "list_static_routes", map[string]any{"target": "fw-01"}, ReadConfig, false},
	{"mcfortigate", "get_routing_table", map[string]any{"target": "fw-01"}, ReadOperational, false},
	{"mcfortigate", "list_wifi_clients", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, ReadOperational, false},
	{"mcfortigate", "list_dhcp_leases", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, ReadOperational, false},
	{"mcfortigate", "get_arp_table", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, ReadOperational, false},
	{"mcfortigate", "find_device", map[string]any{"mac": "00:00:5e:00:53:01", "target": "fw-01"}, ReadOperational, false},

	// 1.9b oscardagrach/fortigate-mcp: 393 tools in four families
	// (get_*, create_*, update_*, delete_*); the brief names the families,
	// not the tools. One representative name per family, from the objects
	// the brief lists.
	{"fortigate-mcp", "get_firewall_policies", map[string]any{"vdom": "root"}, ReadConfig, false},
	{"fortigate-mcp", "create_firewall_policy", map[string]any{"vdom": "root", "name": "allow-web"}, WriteConfig, false},
	{"fortigate-mcp", "update_static_route", map[string]any{"vdom": "root", "seq_num": float64(1), "gateway": "192.0.2.1"}, WriteConfig, false},
	{"fortigate-mcp", "delete_address", map[string]any{"vdom": "root", "name": "FAKE-host"}, WriteConfig, false},

	// 1.10 Cisco Meraki official: semantic_search only; execute_api is
	// M1-17's (capability tables).
	{"cisco-meraki-mcp", "semantic_search", map[string]any{"query": "list switches", "top_k": float64(5)}, InventoryRead, false},

	// 1.10 richbibby/catalyst-center-mcp. get_api_compatible_time_range is
	// named in Part 1 only, which gives no class.
	{"catalyst-center-mcp", "fetch_devices", map[string]any{}, ReadOperational, false},
	{"catalyst-center-mcp", "fetch_sites", map[string]any{}, ReadOperational, false},
	{"catalyst-center-mcp", "fetch_interfaces", map[string]any{}, ReadOperational, false},
	{"catalyst-center-mcp", "get_clients_list", map[string]any{}, ReadOperational, false},
	{"catalyst-center-mcp", "get_client_details_by_mac", map[string]any{"mac": "00:00:5e:00:53:01"}, ReadOperational, false},
	{"catalyst-center-mcp", "get_clients_count", map[string]any{}, ReadOperational, false},
	{"catalyst-center-mcp", "get_api_compatible_time_range", map[string]any{}, brief02Unclassed, false},

	// 1.10 CiscoDevNet/catalyst-sdwan-mcp-community: the brief names three
	// of 39 tools and classes none of them ("mostly read").
	{"catalyst-sdwan-mcp", "list_devices", map[string]any{}, brief02Unclassed, false},
	{"catalyst-sdwan-mcp", "get_control_connections", map[string]any{}, brief02Unclassed, false},
	{"catalyst-sdwan-mcp", "get_bfd_summary", map[string]any{}, brief02Unclassed, false},

	// 1.10 automateyournetwork/pyATS_MCP
	{"pyats-mcp", "pyats_list_devices", map[string]any{}, InventoryRead, false},
	{"pyats-mcp", "pyats_search_devices", map[string]any{"name": "core"}, InventoryRead, false},
	{"pyats-mcp", "pyats_run_show_command", map[string]any{"device": b2dev, "command": "show version"}, ReadOperational, false},
	{"pyats-mcp", "pyats_run_show_command_on_multiple_devices", map[string]any{"devices": []any{"core-rtr-01", "core-rtr-02"}, "command": "show version"}, ReadOperational, false},
	{"pyats-mcp", "pyats_ping_from_network_device", map[string]any{"device": b2dev, "target": "192.0.2.1"}, ReadOperational, false},
	{"pyats-mcp", "pyats_run_linux_command", map[string]any{"host": "jump-01", "command": "ping 192.0.2.1"}, ExecArbitrary, true},
	{"pyats-mcp", "pyats_configure_device", map[string]any{"device": b2dev, "commands": []any{"interface Gi1", " description uplink"}}, WriteConfig, false},
	{"pyats-mcp", "pyats_configure_devices_multi", map[string]any{"devices": []any{"core-rtr-01", "core-rtr-02"}, "commands": []any{"ntp server 192.0.2.10"}}, WriteConfig, false},
	{"pyats-mcp", "pyats_configure_with_diff", map[string]any{"device": b2dev, "commands": []any{"ntp server 192.0.2.10"}}, WriteConfig, false},
	{"pyats-mcp", "pyats_rollback_config", map[string]any{"device": b2dev}, WriteConfig, false},
	{"pyats-mcp", "pyats_device_health", map[string]any{"device": b2dev}, ReadOperational, false},
	{"pyats-mcp", "pyats_get_neighbors", map[string]any{"device": b2dev}, ReadOperational, false}, //nolint:misspell // upstream tool name
	{"pyats-mcp", "pyats_find_interface_by_ip", map[string]any{"device": b2dev, "ip": "192.0.2.1"}, ReadOperational, false},
	{"pyats-mcp", "pyats_run_dynamic_test", map[string]any{"script": "print('FAKE')"}, ExecArbitrary, true},
	{"pyats-mcp", "pyats_get_operation_log", map[string]any{}, InventoryRead, false},

	// 1.11 netboxlabs/netbox-mcp-server
	{"netbox-mcp-server", "netbox_get_objects", map[string]any{"object_type": "dcim.device", "filters": map[string]any{"site": "lab"}, "limit": float64(5)}, InventoryRead, false},
	{"netbox-mcp-server", "netbox_get_object_by_id", map[string]any{"object_type": "dcim.device", "object_id": float64(1)}, InventoryRead, false},
	{"netbox-mcp-server", "netbox_get_changelogs", map[string]any{"filters": map[string]any{"action": "update"}}, InventoryRead, false},
	{"netbox-mcp-server", "netbox_search_objects", map[string]any{"query": "core-rtr"}, InventoryRead, false},

	// 1.11 alexkiwi1/netbox-mcp-rw. Part 1 says INVENTORY_WRITE, which is
	// not a class; 2(c) maps the writes to WRITE_CONFIG.
	{"netbox-mcp-rw", "netbox_get_objects", map[string]any{"object_type": "dcim.device", "filters": map[string]any{}}, InventoryRead, false},
	{"netbox-mcp-rw", "netbox_get_object_by_id", map[string]any{"object_type": "dcim.device", "object_id": float64(1)}, InventoryRead, false},
	{"netbox-mcp-rw", "netbox_get_changelogs", map[string]any{"filters": map[string]any{}}, InventoryRead, false},
	{"netbox-mcp-rw", "netbox_create_object", map[string]any{"object_type": "dcim.device", "data": map[string]any{"name": "FAKE-new"}}, WriteConfig, false},
	{"netbox-mcp-rw", "netbox_update_object", map[string]any{"object_type": "dcim.device", "object_id": float64(1), "data": map[string]any{"status": "offline"}}, WriteConfig, false},
	{"netbox-mcp-rw", "netbox_delete_object", map[string]any{"object_type": "dcim.device", "object_id": float64(1)}, WriteConfig, false},
	{"netbox-mcp-rw", "netbox_bulk_create_objects", map[string]any{"object_type": "ipam.ipaddress", "data": []any{map[string]any{"address": "192.0.2.5/24"}}}, WriteConfig, false},
	{"netbox-mcp-rw", "netbox_bulk_update_objects", map[string]any{"object_type": "ipam.ipaddress", "data": []any{map[string]any{"id": float64(5), "status": "reserved"}}}, WriteConfig, false},
	{"netbox-mcp-rw", "netbox_bulk_delete_objects", map[string]any{"object_type": "ipam.ipaddress", "ids": []any{float64(5)}}, WriteConfig, false},

	// 1.12 Presidio-Federal/network-discovery-mcp. The brief names the
	// tools and gives them no class (its Batfish line covers offline
	// snapshots; these contact live devices). Parameters are not in the
	// brief; these are representative.
	{"network-discovery-mcp", "seed_device", map[string]any{"host": "192.0.2.1"}, brief02Unclassed, false},
	{"network-discovery-mcp", "scan_targets", map[string]any{"targets": []any{"192.0.2.1"}}, brief02Unclassed, false},
	{"network-discovery-mcp", "scan_from_subnets", map[string]any{"subnets": []any{"192.0.2.0/24"}}, brief02Unclassed, false},
	{"network-discovery-mcp", "fingerprint_devices", map[string]any{"job_id": "FAKE-job"}, brief02Unclassed, false},
	{"network-discovery-mcp", "collect_device_configs", map[string]any{"job_id": "FAKE-job"}, brief02Unclassed, false},
	{"network-discovery-mcp", "validate_device_credentials", map[string]any{"host": "192.0.2.1", "username": "FAKEuser", "password": "FAKEpassword"}, brief02Unclassed, false},
	{"network-discovery-mcp", "generate_topology_visualization", map[string]any{"job_id": "FAKE-job"}, brief02Unclassed, false}, //nolint:misspell // upstream tool name
	{"network-discovery-mcp", "resume_failed_job", map[string]any{"job_id": "FAKE-job"}, brief02Unclassed, false},

	// 1.12 seanerama/clab-mcp-server
	{"clab-mcp-server", "authenticate", map[string]any{}, LocalAdmin, false},
	{"clab-mcp-server", "listLabs", map[string]any{}, ReadOperational, false},
	{"clab-mcp-server", "deployLab", map[string]any{"topologyContent": map[string]any{"name": "srl2"}}, LabLifecycle, false},
	{"clab-mcp-server", "inspectLab", map[string]any{"labName": "srl2", "details": true}, ReadOperational, false},
	{"clab-mcp-server", "execCommand", map[string]any{"labName": "srl2", "nodeName": "srl1", "command": "show version"}, ExecArbitrary, true},
	{"clab-mcp-server", "destroyLab", map[string]any{"labName": "srl2", "cleanup": true, "graceful": true}, LabLifecycle, false},
}

// brief02Known lists rows whose fallback class is less strict than brief
// 02 says, keyed "server.tool", each naming its finding. The test skips
// them with that name instead of failing the build. Empty: at this commit
// the fallback is EXEC_ARBITRARY for every tool.
var brief02Known = map[string]string{}

// TestFallbackBrief02 classifies every row the two ways a call reaches the
// fallback: with no profile at all (Classify(nil, ...)), and with the empty
// profile fathomgate serve gives a --server that has none (ADR 0027,
// orchestrator decision of 2026-09-25), by bare and by prefixed tool name.
func TestFallbackBrief02(t *testing.T) {
	for _, row := range brief02Rows {
		key := row.server + "." + row.tool
		t.Run(key, func(t *testing.T) {
			if finding, ok := brief02Known[key]; ok {
				t.Skipf("known finding for policy-engineer: %s", finding)
			}
			empty := &Profile{Server: row.server, Tools: map[string]ToolSpec{}}
			wantUnnamed := sortedKeys(row.args)
			for _, c := range []struct {
				name    string
				profile *Profile
				tool    string
				unnamed []string
			}{
				{"no profile", nil, row.tool, nil},
				{"empty profile", empty, row.tool, wantUnnamed},
				{"empty profile, prefixed", empty, key, wantUnnamed},
			} {
				r := Classify(c.profile, c.tool, row.args)
				if r.ClassSource != SourceFallback {
					t.Errorf("%s: class_source %q, want %q", c.name, r.ClassSource, SourceFallback)
				}
				if r.Known || r.ProfileClass != "" {
					t.Errorf("%s: Known %v ProfileClass %q, want an unknown tool", c.name, r.Known, r.ProfileClass)
				}
				if !r.Class.Valid() {
					t.Fatalf("%s: class %q is not a class", c.name, r.Class)
				}
				switch {
				case row.brief == brief02Unclassed && r.Class != ExecArbitrary:
					t.Errorf("%s: class %s; brief 02 gives this tool no class, so only %s is acceptable", c.name, r.Class, ExecArbitrary)
				case row.brief != brief02Unclassed && brief02Strictness[r.Class] < brief02Strictness[row.brief]:
					t.Errorf("%s: class %s is less strict than brief 02's %s (finding for policy-engineer)", c.name, r.Class, row.brief)
				}
				if row.neverDowngrade && r.Class != ExecArbitrary {
					t.Errorf("%s: class %s, want %s (classification.md section 8: never downgraded)", c.name, r.Class, ExecArbitrary)
				}
				// Every argument of an unlisted tool is unnamed under a
				// profile, so the gate denies the call with
				// default:bad_arguments (ADR 0033); with no profile
				// nothing is checked.
				if !reflect.DeepEqual(r.UnnamedArgs, c.unnamed) {
					t.Errorf("%s: UnnamedArgs %q, want %q", c.name, r.UnnamedArgs, c.unnamed)
				}
				if r.MalformedArgs != nil {
					t.Errorf("%s: MalformedArgs %q, want none", c.name, r.MalformedArgs)
				}
			}
		})
	}
}

// TestFallbackBrief02Table checks the table itself: every row is on a
// declared server, no row repeats, every brief class is a class, no
// declared server has a shipped profile (its rows would belong in
// TestRepoProfiles), and no stale entry sits in brief02Known.
func TestFallbackBrief02Table(t *testing.T) {
	declared := map[string]bool{}
	for _, s := range brief02Servers {
		declared[s] = true
	}
	seen := map[string]bool{}
	perServer := map[string]int{}
	for _, row := range brief02Rows {
		key := row.server + "." + row.tool
		if !declared[row.server] {
			t.Errorf("%s: server not in brief02Servers", key)
		}
		if seen[key] {
			t.Errorf("%s: row repeated", key)
		}
		seen[key] = true
		perServer[row.server]++
		if row.brief != brief02Unclassed && !row.brief.Valid() {
			t.Errorf("%s: brief class %q is not a class", key, row.brief)
		}
		if row.neverDowngrade && row.brief != ExecArbitrary {
			t.Errorf("%s: never-downgrade row with brief class %s", key, row.brief)
		}
		if row.server == "cisco-meraki-mcp" && row.tool == "execute_api" {
			t.Errorf("%s: belongs to M1-17 (capability tables)", key)
		}
	}
	for _, s := range brief02Servers {
		if perServer[s] == 0 {
			t.Errorf("server %s has no rows", s)
		}
	}
	for key := range brief02Known {
		if !seen[key] {
			t.Errorf("brief02Known entry %s has no row", key)
		}
	}
	shipped, err := LoadProfileDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	for server := range shipped {
		if declared[server] {
			t.Errorf("server %s now has a shipped profile: move its rows to TestRepoProfiles", server)
		}
	}
	if len(brief02Strictness) != len(All()) {
		t.Errorf("brief02Strictness ranks %d classes, want %d", len(brief02Strictness), len(All()))
	}
	t.Logf("%d tools on %d servers fallback-classified", len(brief02Rows), len(brief02Servers))
}

func sortedKeys(m map[string]any) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
