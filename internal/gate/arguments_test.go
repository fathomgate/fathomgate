// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"reflect"
	"testing"
)

// TestArguments: the named set the proxy keeps in the advertised
// inputSchema (ADR 0033 section 4). A listed tool gives its named set, an
// unlisted tool on a profiled server is closed with no names, and a server
// with no profile is not closed.
func TestArguments(t *testing.T) {
	t.Parallel()
	g := newGate(t, examplePolicy(t, "read-only"), false)
	if named, closed := g.Arguments(eos, "get_device_facts_batch"); !closed || !reflect.DeepEqual(named, []string{"hostnames", "max_workers", "tags"}) {
		t.Errorf("get_device_facts_batch: %q closed=%v", named, closed)
	}
	if named, closed := g.Arguments(eos, "get_version"); !closed || !reflect.DeepEqual(named, []string{"hostname"}) {
		t.Errorf("get_version: %q closed=%v (config_path is refused, never named)", named, closed)
	}
	if named, closed := g.Arguments(eos, "not_in_profile"); !closed || len(named) != 0 {
		t.Errorf("unlisted tool: %q closed=%v", named, closed)
	}
	if named, closed := g.Arguments(eos, "eos-mcp.get_version"); !closed || len(named) != 0 {
		t.Errorf("a prefixed name is looked up exactly: %q closed=%v", named, closed)
	}
	if named, closed := g.Arguments("no-such-server", "x"); closed || named != nil {
		t.Errorf("no profile: %q closed=%v", named, closed)
	}
}
