// SPDX-License-Identifier: Apache-2.0

// Package inventory resolves a target hostname to its role, site, tags and
// status.
//
// It is the third stage of the pipeline (normalise -> classify -> resolve
// role -> evaluate). A source of truth is not a requirement: the proxy tries
// a chain of Resolver providers in order and the first hit wins.
//
//  1. StaticFile   inventory.yaml, or a CSV imported with ImportCSV
//  2. Patterns     hostname regexes (^core-|^border- -> role core)
//  3. (M1)         the upstream server's own INVENTORY_READ tools
//  4. NetBox       NetBox or Nautobot REST with a cached snapshot (stub)
//
// A name no provider resolves is unknown, and the policy's
// defaults.unknown_target decides what happens to it. Names are compared
// case-insensitively because device hostnames are.
package inventory
