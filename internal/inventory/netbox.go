// SPDX-License-Identifier: FSL-1.1-ALv2

package inventory

// NetBox is a stub for the source-of-truth provider for NetBox and Nautobot.
// It is the last link in the chain and never a dependency: the proxy works
// with a static file, a CSV import and hostname patterns alone.
//
// The live connectors (API lookup, auto-sync, caching and freshness checks)
// are in the paid edition (ADR 0034, Amendments, 2026-09-25). The core keeps
// the Resolver interface, the snapshot format and stale marking. This type
// satisfies Resolver and resolves nothing; it stays until the paid resolver
// exists, then leaves the core. The seam is Resolver, not this stub.
type NetBox struct {
	// URL is the base URL of the NetBox or Nautobot instance.
	URL string
	// Token is the API token. Keep it out of policy files.
	Token string
	// Flavor is "netbox" or "nautobot"; the two APIs differ in role field
	// names (device_role vs role) and in tag representation.
	Flavor string
}

// Resolve implements Resolver. It always returns false, so a chain that
// includes the stub fails closed rather than inventing roles.
func (n *NetBox) Resolve(string) (Target, bool) {
	return Target{}, false
}
