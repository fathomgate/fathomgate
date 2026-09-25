// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// methodToolsList is the MCP method whose answers hintCapture reads.
const methodToolsList = "tools/list"

// hintCapture reads each tool's readOnlyHint from the upstream's tools/list
// answers as they arrive on the wire, before go-sdk decodes them.
//
// go-sdk v1.8 decodes readOnlyHint into a plain bool, so a tool that sends
// no readOnlyHint and one that sends false look the same. The gate raises a
// read class to EXEC_ARBITRARY on an explicit false (ADR 0010), so reading
// absence as false would raise every read tool that sends annotations
// without the hint. The capture keeps absence as nil.
//
// It sees only connections trackedTransport wraps (tracksConn: stdio and
// in-memory transports). For any other transport it sees nothing, and every
// readOnlyHint is nil: the raise then rests on destructiveHint alone, which
// go-sdk keeps as a pointer (New logs a Warn when a Gate is set). It records
// only while New lists the upstream's tools; readOnlyHints stops it.
type hintCapture struct {
	mu       sync.Mutex
	stopped  bool
	pending  map[jsonrpc.ID]struct{} // ids of tools/list requests sent
	readOnly map[string]*bool        // by upstream tool name
	wired    bool                    // a connection was wrapped
}

// sent notes a tools/list request's id.
func (h *hintCapture) sent(m jsonrpc.Message) {
	req, ok := m.(*jsonrpc.Request)
	if !ok || req.Method != methodToolsList || !req.ID.IsValid() {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopped {
		return
	}
	if h.pending == nil {
		h.pending = make(map[jsonrpc.ID]struct{})
	}
	h.pending[req.ID] = struct{}{}
}

// received reads the readOnlyHints of a tools/list answer. An answer that
// does not parse adds nothing: go-sdk then fails the listing, or the tools
// it lists have no hint here (nil, no raise on readOnlyHint).
func (h *hintCapture) received(m jsonrpc.Message) {
	res, ok := m.(*jsonrpc.Response)
	if !ok || res.Error != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.pending[res.ID]; h.stopped || !ok {
		return
	}
	delete(h.pending, res.ID)
	var page struct {
		Tools []struct {
			Name        string `json:"name"`
			Annotations *struct {
				ReadOnlyHint *bool `json:"readOnlyHint"`
			} `json:"annotations"`
		} `json:"tools"`
	}
	if json.Unmarshal(res.Result, &page) != nil {
		return
	}
	if h.readOnly == nil {
		h.readOnly = make(map[string]*bool, len(page.Tools))
	}
	for _, t := range page.Tools {
		if t.Annotations != nil && t.Annotations.ReadOnlyHint != nil {
			v := *t.Annotations.ReadOnlyHint
			h.readOnly[t.Name] = &v
		}
	}
}

// readOnlyHints stops the capture and returns what it read, by tool name,
// and whether the transport's connection was wrapped at all.
func (t *trackedTransport) readOnlyHints() (map[string]*bool, bool) {
	h := &t.hints
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopped, h.pending = true, nil
	out := h.readOnly
	h.readOnly = nil
	return out, h.wired
}
