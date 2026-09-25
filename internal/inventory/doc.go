// SPDX-License-Identifier: FSL-1.1-ALv2

// Package inventory resolves a target hostname to its role, site, tags and
// status.
//
// It is the third stage of the pipeline (normalise -> classify -> resolve
// role -> evaluate). A source of truth is not a requirement. The Chain has
// two kinds of provider (ADR 0031):
//
//	order  provider     kind
//	1      StaticFile   name authority  inventory.yaml, or a CSV imported with ImportCSV
//	2      Patterns     enricher        hostname regexes (^core-|^border- -> role core)
//	3      (M2)         name authority  the upstream server's own INVENTORY_READ tools
//	4      NetBox       name authority  stub (live NetBox and Nautobot connectors: paid edition)
//
// Name authorities (Resolver) decide whether a name is known. The first to
// list the name supplies every field it sets. Enrichers (Enricher) then run,
// only for a listed name, and fill an empty role or site and add their tags.
// A later authority that also lists the name runs last and fills only an
// empty site or status: never role or tags, which unlock writes, because
// from M2 a later authority may be an upstream's untrusted device list.
//
// A hostname pattern never makes a name known: a name no authority lists is
// unknown whatever patterns it matches, and the policy's
// defaults.unknown_target decides what happens to it. Every hit carries the
// provider of each field in Target.Sources. Resolvers compare
// names case-insensitively; internal/gate then counts a target as known only
// when the record's stored name is the exact string the upstream receives
// (inventory-schema section 7).
package inventory
