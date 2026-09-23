package inventory

// NetBox is the source-of-truth provider for NetBox and Nautobot. It is the
// last link in the chain and never a dependency: the proxy works with a
// static file and hostname patterns alone.
//
// TODO(M2): implement the REST lookup (GET /api/dcim/devices/?name=<name>
// for NetBox, /api/dcim/devices/?name=<name> for Nautobot), a TTL cache, a
// snapshot written by `netguard inventory sync`, and stale marking so that an
// unreachable source of truth never silently loosens policy. Until then this
// type satisfies Resolver and resolves nothing.
type NetBox struct {
	// URL is the base URL of the NetBox or Nautobot instance.
	URL string
	// Token is the API token. Keep it out of policy files.
	Token string
	// Flavor is "netbox" or "nautobot"; the two APIs differ in role field
	// names (device_role vs role) and in tag representation.
	Flavor string
}

// Resolve implements Resolver. It returns false until M2 lands so that a
// misconfigured chain fails closed rather than inventing roles.
func (n *NetBox) Resolve(string) (Target, bool) {
	return Target{}, false
}
