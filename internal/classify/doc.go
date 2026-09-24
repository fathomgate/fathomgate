// Package classify assigns a network-semantic class to every MCP tool call
// before the policy engine sees it.
//
// It is the second stage of the Fathomgate pipeline
// (normalise -> classify -> resolve role -> evaluate policy). The package
// contains three cooperating pieces:
//
//   - Class: the closed set of command classes the policy DSL speaks
//     (READ_OPERATIONAL, READ_CONFIG, WRITE_CONFIG, EXEC_ARBITRARY,
//     INVENTORY_READ, LAB_LIFECYCLE, LOCAL_ADMIN).
//   - Profile: a per-upstream-server YAML file (profiles/<server>.yaml) that
//     maps each tool name to a class and names the parameters that carry
//     targets, commands and configuration payloads.
//   - Normalize and ClassifyCommand: the argument normaliser and the fallback
//     command classifier. Together they implement the downgrade rule from the
//     plan: an EXEC_ARBITRARY tool is downgraded to a read class only when
//     every command it carries passes the allow-list and blocklist.
//
// Tool annotations such as readOnlyHint are never consulted; the spec marks
// them untrusted, so classification is driven by the profile and by
// inspecting the actual arguments.
package classify
