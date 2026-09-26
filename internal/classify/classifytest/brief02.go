// SPDX-License-Identifier: FSL-1.1-ALv2

// Package classifytest holds the brief 02 tool table of M1-15 (M1 exit
// criterion 1): every tool docs/research/02-network-mcp-servers.md names on
// a server with no shipped profile. internal/classify runs it through
// Classify and internal/gate through Decide, so both levels are checked
// against the same rows.
//
// Package classifytest is for tests only: nothing the fathomgate binary
// links may import it (TestNotInBinary checks cmd/fathomgate's
// dependencies).
//
// The servers with a shipped profile (netdev-ssh-mcp, upa, eos-mcp,
// junos-mcp-server, ntunes-netmiko-mcp-server, cisco-meraki-mcp-official)
// are covered tool by tool in classify's TestRepoProfiles and are not here.
// Meraki's semantic_search and execute_api moved out when its profile
// shipped (M1-17, capability tables).
//
// A tool with no profile entry is always EXEC_ARBITRARY with class_source
// fallback and is never downgraded, whatever its arguments (maintainer
// decision of 2026-09-25 not to build the classification.md section 3
// fallback classifier). Brief is therefore documentation, not the expected
// class: it is the class brief 02 gives the tool, from its section 2(c)
// mapping table first, its Part 1 table when 2(c) does not list the tool,
// and the stricter of the two when they disagree. Unclassed marks a tool
// the brief names but gives no class.
package classifytest

import (
	"maps"

	"github.com/fathomgate/fathomgate/internal/classify"
)

// Unclassed is Brief for a tool brief 02 names but does not classify.
const Unclassed classify.Class = ""

// Brief02Tool is one surveyed tool.
type Brief02Tool struct {
	// Server is the server key a profile for it would carry.
	Server string
	// Tool is the upstream's tool name, exactly.
	Tool string
	// Args are representative arguments, with the brief's argument names;
	// values are FAKE where they are secrets, numbers are float64 as JSON
	// decodes them. Where the brief gives no parameters the rows say so.
	Args map[string]any
	// Brief is brief 02's class for the tool, as documentation.
	Brief classify.Class
}

// Key is "server.tool".
func (r Brief02Tool) Key() string { return r.Server + "." + r.Tool }

// Brief02Servers are the server keys of the table. None has a shipped
// profile: when one lands, its rows move to TestRepoProfiles.
var Brief02Servers = []string{
	"scrapli-mcp", "mcp-telecom", "pan-os-mcp", "palo-mcp", "mcfortigate",
	"fortigate-mcp", "catalyst-center-mcp",
	"catalyst-sdwan-mcp", "pyats-mcp", "netbox-mcp-server", "netbox-mcp-rw",
	"network-discovery-mcp", "clab-mcp-server",
}

// NeverDowngrade are the classification.md section 8 tools in the table,
// keyed "server.tool". The two that take a command carry one the read
// allow-list would pass, so a downgrade would show.
var NeverDowngrade = map[string]bool{
	"pyats-mcp.pyats_run_linux_command": true,
	"pyats-mcp.pyats_run_dynamic_test":  true,
	"clab-mcp-server.execCommand":       true,
}

// Brief02 returns the table, one row per tool, with fresh argument maps
// (top level only) so a test may not change another's rows.
func Brief02() []Brief02Tool {
	out := make([]Brief02Tool, len(brief02))
	for i, r := range brief02 {
		r.Args = maps.Clone(r.Args)
		out[i] = r
	}
	return out
}

const dev = "core-rtr-01"

var brief02 = []Brief02Tool{
	// 1.2 carlmontanari/scrapli-mcp
	{"scrapli-mcp", "execute_ssh_command", map[string]any{"host": "r1", "command": "show version"}, classify.ExecArbitrary},

	// 1.4 mcp-telecom: canned show tools
	{"mcp-telecom", "show_bgp_summary", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_bgp_neighbors", map[string]any{"device": dev}, classify.ReadOperational}, //nolint:misspell // upstream tool name
	{"mcp-telecom", "show_routing_table", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_ospf_neighbors", map[string]any{"device": dev}, classify.ReadOperational}, //nolint:misspell // upstream tool name
	{"mcp-telecom", "show_mpls_lsp", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_interfaces", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_interface_detail", map[string]any{"device": dev, "interface": "Ethernet1"}, classify.ReadOperational},
	{"mcp-telecom", "show_lldp_neighbors", map[string]any{"device": dev}, classify.ReadOperational}, //nolint:misspell // upstream tool name
	{"mcp-telecom", "show_lag_status", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_arp_table", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_mac_table", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_system_info", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_alarms", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_ntp_status", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_cpu", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_memory", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_environment", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_log_events", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "show_nokia_services", map[string]any{"device": dev}, classify.ReadOperational},
	// mcp-telecom: config read
	{"mcp-telecom", "backup_config", map[string]any{"device": dev}, classify.ReadConfig},
	{"mcp-telecom", "compare_configs", map[string]any{"device": dev, "backup_file": "core-rtr-01.cfg"}, classify.ReadConfig},
	{"mcp-telecom", "netconf_get_config", map[string]any{"device": dev, "source": "running"}, classify.ReadConfig},
	{"mcp-telecom", "compliance_check", map[string]any{"device": dev}, classify.ReadConfig},
	{"mcp-telecom", "compliance_check_rule", map[string]any{"device": dev, "rule_name": "ntp-configured"}, classify.ReadConfig},
	// mcp-telecom: free-form, server allow-list enforced
	{"mcp-telecom", "run_command", map[string]any{"device": dev, "command": "show version"}, classify.ReadOperational},
	{"mcp-telecom", "parallel_command", map[string]any{"command": "show version", "devices": "core-rtr-01,core-rtr-02", "max_workers": float64(10)}, classify.ReadOperational},
	// mcp-telecom: named operations
	{"mcp-telecom", "run_vendor_operation", map[string]any{"device": dev, "operation": "bgp_summary"}, classify.ReadOperational},
	{"mcp-telecom", "parallel_operation", map[string]any{"operation": "bgp_summary", "devices": ""}, classify.ReadOperational},
	{"mcp-telecom", "compare_devices", map[string]any{"operation": "bgp_summary", "devices": "core-rtr-01,core-rtr-02"}, classify.ReadOperational},
	// mcp-telecom: inventory and health. health_check is INVENTORY_READ in
	// Part 1 and READ_OPERATIONAL in 2(c); parallel_health_check is only
	// in Part 1.
	{"mcp-telecom", "list_devices", map[string]any{}, classify.InventoryRead},
	{"mcp-telecom", "list_device_capabilities", map[string]any{"device": dev}, classify.InventoryRead},
	{"mcp-telecom", "health_check", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "parallel_health_check", map[string]any{"devices": ""}, classify.InventoryRead},
	{"mcp-telecom", "pool_stats", map[string]any{}, classify.InventoryRead},
	{"mcp-telecom", "get_audit_log", map[string]any{"count": float64(25)}, classify.InventoryRead},
	// mcp-telecom: NETCONF, gNMI, SNMP. telemetry_(un)subscribe is
	// READ_OPERATIONAL in Part 1 and LOCAL_ADMIN in 2(c).
	{"mcp-telecom", "netconf_get_operational", map[string]any{"device": dev, "operation": "interfaces"}, classify.ReadOperational},
	{"mcp-telecom", "netconf_capabilities", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "telemetry_subscribe", map[string]any{"device": dev, "paths": []any{"/interfaces/interface/state/counters"}, "interval_ms": float64(10000)}, classify.LocalAdmin},
	{"mcp-telecom", "telemetry_query", map[string]any{"device": dev}, classify.ReadOperational},
	{"mcp-telecom", "telemetry_history", map[string]any{"device": dev, "path": "/interfaces/interface/state/counters", "count": float64(20)}, classify.ReadOperational},
	{"mcp-telecom", "telemetry_unsubscribe", map[string]any{"device": dev}, classify.LocalAdmin},
	{"mcp-telecom", "snmp_get", map[string]any{"device": dev, "oids": []any{"1.3.6.1.2.1.1.1.0"}, "community": "FAKEcommunity"}, classify.ReadOperational},
	{"mcp-telecom", "snmp_walk", map[string]any{"device": dev, "base_oid": "1.3.6.1.2.1.2", "community": "FAKEcommunity"}, classify.ReadOperational},
	{"mcp-telecom", "snmp_device_overview", map[string]any{"device": dev, "community": "FAKEcommunity"}, classify.ReadOperational},
	// mcp-telecom: topology
	{"mcp-telecom", "discover_topology", map[string]any{"devices": ""}, classify.ReadOperational},
	{"mcp-telecom", "show_topology", map[string]any{}, classify.ReadOperational},
	{"mcp-telecom", "show_topology_json", map[string]any{}, classify.ReadOperational},
	{"mcp-telecom", "show_topology_mermaid", map[string]any{}, classify.ReadOperational},
	{"mcp-telecom", "find_path", map[string]any{"source": "core-rtr-01", "target": "core-rtr-02"}, classify.ReadOperational},
	{"mcp-telecom", "show_device_neighbors", map[string]any{"device": dev}, classify.ReadOperational}, //nolint:misspell // upstream tool name
	// mcp-telecom: lab and misc
	{"mcp-telecom", "clab_generate", map[string]any{"scenario": "srl-two-node"}, classify.LocalAdmin},
	{"mcp-telecom", "clab_devices_yaml", map[string]any{"scenario": "srl-two-node"}, classify.LocalAdmin},
	{"mcp-telecom", "clab_scenarios", map[string]any{}, classify.LocalAdmin},
	{"mcp-telecom", "start_dashboard", map[string]any{"port": float64(8080)}, classify.LocalAdmin},
	{"mcp-telecom", "start_metrics_endpoint", map[string]any{"port": float64(9100)}, classify.LocalAdmin},

	// 1.8a cdot65/pan-os-mcp (no parameters; one firewall per instance)
	{"pan-os-mcp", "show_system_info", map[string]any{}, classify.ReadOperational},
	{"pan-os-mcp", "retrieve_address_objects", map[string]any{}, classify.ReadConfig},
	{"pan-os-mcp", "retrieve_security_zones", map[string]any{}, classify.ReadConfig},
	{"pan-os-mcp", "retrieve_security_policies", map[string]any{}, classify.ReadConfig},

	// 1.8b apius-tech/Palo-MCP: the four tools the brief names. Parameters
	// other than firewall are not in the brief [doc]; these are
	// representative.
	{"palo-mcp", "list_firewalls", map[string]any{}, classify.InventoryRead},
	{"palo-mcp", "set_config", map[string]any{"firewall": "fw-01", "xpath": "/config/devices/entry/vsys/entry/address", "element": "<entry name='FAKE-host'/>"}, classify.WriteConfig},
	{"palo-mcp", "delete_config", map[string]any{"firewall": "fw-01", "xpath": "/config/devices/entry/vsys/entry/address/entry[@name='FAKE-host']"}, classify.WriteConfig},
	{"palo-mcp", "commit", map[string]any{"firewall": "fw-01"}, classify.WriteConfig},

	// 1.9a rsp2k/mcfortigate
	{"mcfortigate", "list_targets", map[string]any{}, classify.InventoryRead},
	{"mcfortigate", "get_system_status", map[string]any{"target": "fw-01"}, classify.ReadOperational},
	{"mcfortigate", "search_config", map[string]any{"term": "admin", "target": "fw-01"}, classify.ReadConfig},
	{"mcfortigate", "list_address_objects", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, classify.ReadConfig},
	{"mcfortigate", "list_address_groups", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, classify.ReadConfig},
	{"mcfortigate", "list_services", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, classify.ReadConfig},
	{"mcfortigate", "list_policies", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, classify.ReadConfig},
	{"mcfortigate", "list_vips", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, classify.ReadConfig},
	{"mcfortigate", "find_references", map[string]any{"object_name": "web-servers", "target": "fw-01"}, classify.ReadConfig},
	{"mcfortigate", "list_interfaces", map[string]any{"target": "fw-01"}, classify.ReadConfig},
	{"mcfortigate", "list_vlans", map[string]any{"target": "fw-01"}, classify.ReadConfig},
	{"mcfortigate", "list_static_routes", map[string]any{"target": "fw-01"}, classify.ReadConfig},
	{"mcfortigate", "get_routing_table", map[string]any{"target": "fw-01"}, classify.ReadOperational},
	{"mcfortigate", "list_wifi_clients", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, classify.ReadOperational},
	{"mcfortigate", "list_dhcp_leases", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, classify.ReadOperational},
	{"mcfortigate", "get_arp_table", map[string]any{"limit": float64(50), "offset": float64(0), "target": "fw-01"}, classify.ReadOperational},
	{"mcfortigate", "find_device", map[string]any{"mac": "00:00:5e:00:53:01", "target": "fw-01"}, classify.ReadOperational},

	// 1.9b oscardagrach/fortigate-mcp: 393 tools in four families
	// (get_*, create_*, update_*, delete_*); the brief names the families,
	// not the tools. One representative name per family, from the objects
	// the brief lists.
	{"fortigate-mcp", "get_firewall_policies", map[string]any{"vdom": "root"}, classify.ReadConfig},
	{"fortigate-mcp", "create_firewall_policy", map[string]any{"vdom": "root", "name": "allow-web"}, classify.WriteConfig},
	{"fortigate-mcp", "update_static_route", map[string]any{"vdom": "root", "seq_num": float64(1), "gateway": "192.0.2.1"}, classify.WriteConfig},
	{"fortigate-mcp", "delete_address", map[string]any{"vdom": "root", "name": "FAKE-host"}, classify.WriteConfig},

	// 1.10 richbibby/catalyst-center-mcp. get_api_compatible_time_range is
	// named in Part 1 only, which gives no class.
	{"catalyst-center-mcp", "fetch_devices", map[string]any{}, classify.ReadOperational},
	{"catalyst-center-mcp", "fetch_sites", map[string]any{}, classify.ReadOperational},
	{"catalyst-center-mcp", "fetch_interfaces", map[string]any{}, classify.ReadOperational},
	{"catalyst-center-mcp", "get_clients_list", map[string]any{}, classify.ReadOperational},
	{"catalyst-center-mcp", "get_client_details_by_mac", map[string]any{"mac": "00:00:5e:00:53:01"}, classify.ReadOperational},
	{"catalyst-center-mcp", "get_clients_count", map[string]any{}, classify.ReadOperational},
	{"catalyst-center-mcp", "get_api_compatible_time_range", map[string]any{}, Unclassed},

	// 1.10 CiscoDevNet/catalyst-sdwan-mcp-community: the brief names three
	// of 39 tools and classes none of them ("mostly read").
	{"catalyst-sdwan-mcp", "list_devices", map[string]any{}, Unclassed},
	{"catalyst-sdwan-mcp", "get_control_connections", map[string]any{}, Unclassed},
	{"catalyst-sdwan-mcp", "get_bfd_summary", map[string]any{}, Unclassed},

	// 1.10 automateyournetwork/pyATS_MCP
	{"pyats-mcp", "pyats_list_devices", map[string]any{}, classify.InventoryRead},
	{"pyats-mcp", "pyats_search_devices", map[string]any{"name": "core"}, classify.InventoryRead},
	{"pyats-mcp", "pyats_run_show_command", map[string]any{"device": dev, "command": "show version"}, classify.ReadOperational},
	{"pyats-mcp", "pyats_run_show_command_on_multiple_devices", map[string]any{"devices": []any{"core-rtr-01", "core-rtr-02"}, "command": "show version"}, classify.ReadOperational},
	{"pyats-mcp", "pyats_ping_from_network_device", map[string]any{"device": dev, "target": "192.0.2.1"}, classify.ReadOperational},
	{"pyats-mcp", "pyats_run_linux_command", map[string]any{"host": "jump-01", "command": "ping 192.0.2.1"}, classify.ExecArbitrary},
	{"pyats-mcp", "pyats_configure_device", map[string]any{"device": dev, "commands": []any{"interface Gi1", " description uplink"}}, classify.WriteConfig},
	{"pyats-mcp", "pyats_configure_devices_multi", map[string]any{"devices": []any{"core-rtr-01", "core-rtr-02"}, "commands": []any{"ntp server 192.0.2.10"}}, classify.WriteConfig},
	{"pyats-mcp", "pyats_configure_with_diff", map[string]any{"device": dev, "commands": []any{"ntp server 192.0.2.10"}}, classify.WriteConfig},
	{"pyats-mcp", "pyats_rollback_config", map[string]any{"device": dev}, classify.WriteConfig},
	{"pyats-mcp", "pyats_device_health", map[string]any{"device": dev}, classify.ReadOperational},
	{"pyats-mcp", "pyats_get_neighbors", map[string]any{"device": dev}, classify.ReadOperational}, //nolint:misspell // upstream tool name
	{"pyats-mcp", "pyats_find_interface_by_ip", map[string]any{"device": dev, "ip": "192.0.2.1"}, classify.ReadOperational},
	{"pyats-mcp", "pyats_run_dynamic_test", map[string]any{"script": "print('FAKE')"}, classify.ExecArbitrary},
	{"pyats-mcp", "pyats_get_operation_log", map[string]any{}, classify.InventoryRead},

	// 1.11 netboxlabs/netbox-mcp-server
	{"netbox-mcp-server", "netbox_get_objects", map[string]any{"object_type": "dcim.device", "filters": map[string]any{"site": "lab"}, "limit": float64(5)}, classify.InventoryRead},
	{"netbox-mcp-server", "netbox_get_object_by_id", map[string]any{"object_type": "dcim.device", "object_id": float64(1)}, classify.InventoryRead},
	{"netbox-mcp-server", "netbox_get_changelogs", map[string]any{"filters": map[string]any{"action": "update"}}, classify.InventoryRead},
	{"netbox-mcp-server", "netbox_search_objects", map[string]any{"query": "core-rtr"}, classify.InventoryRead},

	// 1.11 alexkiwi1/netbox-mcp-rw. Part 1 says INVENTORY_WRITE, which is
	// not a class; 2(c) maps the writes to WRITE_CONFIG.
	{"netbox-mcp-rw", "netbox_get_objects", map[string]any{"object_type": "dcim.device", "filters": map[string]any{}}, classify.InventoryRead},
	{"netbox-mcp-rw", "netbox_get_object_by_id", map[string]any{"object_type": "dcim.device", "object_id": float64(1)}, classify.InventoryRead},
	{"netbox-mcp-rw", "netbox_get_changelogs", map[string]any{"filters": map[string]any{}}, classify.InventoryRead},
	{"netbox-mcp-rw", "netbox_create_object", map[string]any{"object_type": "dcim.device", "data": map[string]any{"name": "FAKE-new"}}, classify.WriteConfig},
	{"netbox-mcp-rw", "netbox_update_object", map[string]any{"object_type": "dcim.device", "object_id": float64(1), "data": map[string]any{"status": "offline"}}, classify.WriteConfig},
	{"netbox-mcp-rw", "netbox_delete_object", map[string]any{"object_type": "dcim.device", "object_id": float64(1)}, classify.WriteConfig},
	{"netbox-mcp-rw", "netbox_bulk_create_objects", map[string]any{"object_type": "ipam.ipaddress", "data": []any{map[string]any{"address": "192.0.2.5/24"}}}, classify.WriteConfig},
	{"netbox-mcp-rw", "netbox_bulk_update_objects", map[string]any{"object_type": "ipam.ipaddress", "data": []any{map[string]any{"id": float64(5), "status": "reserved"}}}, classify.WriteConfig},
	{"netbox-mcp-rw", "netbox_bulk_delete_objects", map[string]any{"object_type": "ipam.ipaddress", "ids": []any{float64(5)}}, classify.WriteConfig},

	// 1.12 Presidio-Federal/network-discovery-mcp. The brief names the
	// tools and gives them no class (its Batfish line covers offline
	// snapshots; these contact live devices). Parameters are not in the
	// brief; these are representative.
	{"network-discovery-mcp", "seed_device", map[string]any{"host": "192.0.2.1"}, Unclassed},
	{"network-discovery-mcp", "scan_targets", map[string]any{"targets": []any{"192.0.2.1"}}, Unclassed},
	{"network-discovery-mcp", "scan_from_subnets", map[string]any{"subnets": []any{"192.0.2.0/24"}}, Unclassed},
	{"network-discovery-mcp", "fingerprint_devices", map[string]any{"job_id": "FAKE-job"}, Unclassed},
	{"network-discovery-mcp", "collect_device_configs", map[string]any{"job_id": "FAKE-job"}, Unclassed},
	{"network-discovery-mcp", "validate_device_credentials", map[string]any{"host": "192.0.2.1", "username": "FAKEuser", "password": "FAKEpassword"}, Unclassed},
	{"network-discovery-mcp", "generate_topology_visualization", map[string]any{"job_id": "FAKE-job"}, Unclassed}, //nolint:misspell // upstream tool name
	{"network-discovery-mcp", "resume_failed_job", map[string]any{"job_id": "FAKE-job"}, Unclassed},

	// 1.12 seanerama/clab-mcp-server
	{"clab-mcp-server", "authenticate", map[string]any{}, classify.LocalAdmin},
	{"clab-mcp-server", "listLabs", map[string]any{}, classify.ReadOperational},
	{"clab-mcp-server", "deployLab", map[string]any{"topologyContent": map[string]any{"name": "srl2"}}, classify.LabLifecycle},
	{"clab-mcp-server", "inspectLab", map[string]any{"labName": "srl2", "details": true}, classify.ReadOperational},
	{"clab-mcp-server", "execCommand", map[string]any{"labName": "srl2", "nodeName": "srl1", "command": "show version"}, classify.ExecArbitrary},
	{"clab-mcp-server", "destroyLab", map[string]any{"labName": "srl2", "cleanup": true, "graceful": true}, classify.LabLifecycle},
}
