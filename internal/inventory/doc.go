// SPDX-License-Identifier: FSL-1.1-ALv2

// Package inventory resolves a target hostname to its role, site, tags and
// status.
//
// It is the third stage of the pipeline (normalise -> classify -> resolve
// role -> evaluate). A source of truth is not a requirement: the proxy tries
// a chain of Resolver providers in order and the first hit wins.
//
//  1. StaticFile   inventory.yaml, or a CSV imported with ImportCSV
//  2. Patterns     hostname regexes (^core-|^border- -> role core)
//  3. (M2)         the upstream server's own INVENTORY_READ tools
//  4. NetBox       stub (live NetBox and Nautobot connectors: paid edition)
//
// A name no provider resolves is unknown, and the policy's
// defaults.unknown_target decides what happens to it. Resolvers compare
// names case-insensitively; internal/gate then counts a target as known only
// when the record's stored name is the exact string the upstream receives
// (inventory-schema section 7).
package inventory
