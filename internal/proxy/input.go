package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Upstream input requests (ADR 0008; profile-schema section 8.4).
//
// An upstream asks for user input in one of two shapes: a stateless upstream
// returns an MRTR input_required result, a stateful one sends a
// server-initiated elicitation/create while the call is open. Whatever the
// shape, only form elicitation crosses to the agent, and only after
// relabelling: the message gets the prefix "[from <server>] " and every
// string in it and in its schema has control characters escaped. Sampling,
// roots, URL-mode elicitation and anything unrecognised are refused. The
// agent's answer crosses back only as an elicitation result with action
// accept (with its content), decline or cancel; nothing else, and no _meta.

const (
	// maxPromptText caps each relabelled string of an upstream prompt.
	maxPromptText = 2048
	// maxInputRequests caps how many input requests one result may carry.
	maxInputRequests = 16
	// maxInputRequestID caps the length of an upstream input request id.
	maxInputRequestID = 128
)

// promptLabel is the origin label every upstream prompt carries.
func promptLabel(server string) string { return "[from " + server + "] " }

// refusal is netguard declining to pass an upstream input request on. Its
// text is safe to show the agent: it names the upstream and the kind of
// request, never the upstream's prompt.
type refusal struct {
	server, tool, kind, reason string
}

func (r *refusal) Error() string {
	if r.tool == "" {
		return fmt.Sprintf("netguard refused an input request (%s) from upstream %s: %s", r.kind, r.server, r.reason)
	}
	return fmt.Sprintf("netguard refused an input request (%s) from upstream %s during %s: %s", r.kind, r.server, r.tool, r.reason)
}

// relabelInputRequests checks every input request of an upstream
// input_required result and returns the agent-facing copies, or the reason
// netguard will not pass them on.
func relabelInputRequests(server, tool string, reqs mcp.InputRequestMap) (mcp.InputRequestMap, *refusal) {
	if len(reqs) > maxInputRequests {
		return nil, &refusal{server, tool, "input_required", fmt.Sprintf("more than %d input requests", maxInputRequests)}
	}
	out := make(mcp.InputRequestMap, len(reqs))
	for id, ir := range reqs {
		if id == "" || len(id) > maxInputRequestID || strings.IndexFunc(id, isControl) >= 0 {
			return nil, &refusal{server, tool, "input_required", "an input request id is empty, too long or has control characters"}
		}
		ep, ok := ir.(*mcp.ElicitParams)
		if !ok {
			return nil, &refusal{server, tool, inputKind(ir), "only form elicitation is passed to the agent"}
		}
		clean, r := relabelElicit(server, tool, ep)
		if r != nil {
			return nil, r
		}
		out[id] = clean
	}
	return out, nil
}

// inputKind names an input request for a refusal message.
func inputKind(ir mcp.InputRequest) string {
	switch ir.(type) {
	case *mcp.CreateMessageParams, *mcp.CreateMessageWithToolsParams: //nolint:staticcheck // SA1019: deprecated sampling is named here to refuse it
		return "sampling"
	case *mcp.ListRootsParams: //nolint:staticcheck // SA1019: deprecated roots is named here to refuse it
		return "roots"
	case *mcp.ElicitParams:
		return "elicitation"
	default:
		return "unknown"
	}
}

// relabelElicit returns the agent-facing copy of one upstream elicitation:
// form mode only, message labelled with its origin, control characters in
// every string escaped, _meta dropped.
func relabelElicit(server, tool string, ep *mcp.ElicitParams) (*mcp.ElicitParams, *refusal) {
	if ep == nil {
		return nil, &refusal{server, tool, "elicitation", "empty request"}
	}
	if (ep.Mode != "" && ep.Mode != "form") || ep.URL != "" || ep.ElicitationID != "" {
		return nil, &refusal{server, tool, "URL elicitation", "only form elicitation is passed to the agent"}
	}
	schema, err := relabelSchema(ep.RequestedSchema)
	if err != nil {
		return nil, &refusal{server, tool, "elicitation", "requested schema: " + err.Error()}
	}
	return &mcp.ElicitParams{
		Mode:            "form",
		Message:         promptLabel(server) + escapeControl(ep.Message, maxPromptText),
		RequestedSchema: schema,
	}, nil
}

// relabelSchema checks an elicitation schema is the flat object the spec
// allows (primitive, or array for multi-select, properties) and returns a
// copy with control characters escaped in every string value. Property names
// with control characters are refused rather than rewritten.
func relabelSchema(s any) (any, error) {
	if s == nil {
		return nil, nil
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, errors.New("not a JSON object")
	}
	if t, ok := m["type"]; ok && t != "object" {
		return nil, fmt.Errorf(`type is %v, not "object"`, t)
	}
	if p, ok := m["properties"]; ok {
		props, ok := p.(map[string]any)
		if !ok {
			return nil, errors.New("properties is not an object")
		}
		for name, v := range props {
			if strings.IndexFunc(name, isControl) >= 0 {
				return nil, errors.New("a property name has control characters")
			}
			pm, ok := v.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("property %q is not an object", name)
			}
			switch pm["type"] {
			case "string", "number", "integer", "boolean", "array":
			default:
				return nil, fmt.Errorf("property %q has type %v; only primitives are allowed", name, pm["type"])
			}
		}
	}
	return escapeStrings(m), nil
}

// escapeStrings returns v with escapeControl applied to every string value
// at any depth. Object keys are left alone.
func escapeStrings(v any) any {
	switch x := v.(type) {
	case string:
		return escapeControl(x, maxPromptText)
	case map[string]any:
		for k, e := range x {
			x[k] = escapeStrings(e)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = escapeStrings(e)
		}
		return x
	default:
		return v
	}
}

// cleanElicitResult is the allow-list for an agent's answer to an upstream
// prompt: action accept with its content, or decline or cancel with nothing.
// _meta is dropped.
func cleanElicitResult(r *mcp.ElicitResult) (*mcp.ElicitResult, error) {
	if r == nil {
		return nil, errors.New("empty elicitation result")
	}
	switch r.Action {
	case "accept":
		return &mcp.ElicitResult{Action: r.Action, Content: r.Content}, nil
	case "decline", "cancel":
		return &mcp.ElicitResult{Action: r.Action}, nil
	default:
		return nil, fmt.Errorf("elicitation action %q is not accept, decline or cancel", clip(r.Action))
	}
}

// Reasons in the data of an invalid-retry JSON-RPC error.
const (
	reasonInvalidRequestState  = "invalid_request_state"
	reasonInvalidInputResponse = "invalid_input_responses"
)

// retryErrorData is the structured data of an invalid-retry error.
type retryErrorData struct {
	Tool   string `json:"tool"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

// invalidRetry is the JSON-RPC invalid-params error for an MRTR retry
// netguard will not forward.
func invalidRetry(prefixed, reason string, detail error) error {
	d := retryErrorData{Tool: clip(prefixed), Reason: reason, Detail: detail.Error()}
	data, err := json.Marshal(d)
	if err != nil {
		data = nil
	}
	return &jsonrpc.Error{
		Code:    jsonrpc.CodeInvalidParams,
		Message: fmt.Sprintf("%s: %s: %s", reason, d.Tool, d.Detail),
		Data:    data,
	}
}

// resume verifies a stateless agent's MRTR retry and returns what to send
// the upstream: the allow-listed responses, the upstream's own requestState
// and the round count. Any mismatch is a JSON-RPC invalid-params error and
// nothing reaches the upstream.
func (p *Proxy) resume(c call) (mcp.InputResponseMap, string, int, error) {
	name := prefixName(c.up.name, c.tool)
	if c.requestState == "" {
		return nil, "", 0, invalidRetry(name, reasonInvalidRequestState, errors.New("inputResponses sent without the requestState netguard issued"))
	}
	st, err := p.states.open(c.requestState)
	if err != nil {
		return nil, "", 0, invalidRetry(name, reasonInvalidRequestState, err)
	}
	switch {
	case st.Server != c.up.name || st.Tool != c.tool:
		return nil, "", 0, invalidRetry(name, reasonInvalidRequestState, fmt.Errorf("requestState was issued for %s", clip(prefixName(st.Server, st.Tool))))
	case st.Args != argsDigest(c.arguments):
		return nil, "", 0, invalidRetry(name, reasonInvalidRequestState, errors.New("arguments differ from the call that asked for input"))
	}
	out := make(mcp.InputResponseMap, len(c.inputResponses))
	for id, r := range c.inputResponses {
		if !slices.Contains(st.IDs, id) {
			return nil, "", 0, invalidRetry(name, reasonInvalidInputResponse, fmt.Errorf("no input request %q is outstanding", clip(id)))
		}
		er, ok := r.(*mcp.ElicitResult)
		if !ok {
			return nil, "", 0, invalidRetry(name, reasonInvalidInputResponse, fmt.Errorf("response %q is not an elicitation result", clip(id)))
		}
		clean, err := cleanElicitResult(er)
		if err != nil {
			return nil, "", 0, invalidRetry(name, reasonInvalidInputResponse, err)
		}
		out[id] = clean
	}
	return out, st.Up, st.Round, nil
}

// askAgent puts relabelled input requests to a stateful agent as
// server-initiated elicitation/create requests, one at a time in id order,
// and returns the allow-listed answers. A non-nil result is a tool error to
// return instead.
func (p *Proxy) askAgent(ctx context.Context, c call, reqs mcp.InputRequestMap) (mcp.InputResponseMap, *mcp.CallToolResult, error) {
	ids := make([]string, 0, len(reqs))
	for id := range reqs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := make(mcp.InputResponseMap, len(ids))
	for _, id := range ids {
		r, err := c.agent.session.Elicit(ctx, reqs[id].(*mcp.ElicitParams))
		if err == nil {
			r, err = cleanElicitResult(r)
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			p.logger.Warn("relaying an upstream prompt to the agent failed", "server", c.up.name, "tool", c.tool, "error", err)
			return nil, toolError(fmt.Sprintf("netguard could not relay an input request from upstream %s during %s to the agent: %s",
				c.up.name, c.tool, escapeControl(err.Error(), maxRelayedMessage))), nil
		}
		out[id] = r
	}
	return out, nil, nil
}

// inflight is one call open on an upstream. A stateful upstream's
// elicitation/create names no call, so the proxy attributes it to the only
// call in flight on that upstream, and refuses it when there is not exactly
// one.
type inflight struct {
	ctx   context.Context // the agent's request context
	agent agentPeer
	tool  string

	refused *refusal // set by the elicitation handler; guarded by upstream.mu
}

// begin registers a call as in flight on u.
func (u *upstream) begin(ctx context.Context, c call) *inflight {
	f := &inflight{ctx: ctx, agent: c.agent, tool: c.tool}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.calls == nil {
		u.calls = make(map[*inflight]struct{})
	}
	u.calls[f] = struct{}{}
	return f
}

// end removes f from the calls in flight.
func (u *upstream) end(f *inflight) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.calls, f)
}

// refusedFor reads f's recorded refusal.
func (u *upstream) refusedFor(f *inflight) *refusal {
	u.mu.Lock()
	defer u.mu.Unlock()
	return f.refused
}

// sole returns the only call in flight on u and the number in flight.
func (u *upstream) sole() (*inflight, int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for f := range u.calls {
		if len(u.calls) == 1 {
			return f, 1
		}
	}
	return nil, len(u.calls)
}

// refuse records r against f, or against every call in flight on u when the
// request could not be attributed (any of them may be waiting on it), logs
// it and returns it as the error the upstream receives.
func (p *Proxy) refuse(u *upstream, f *inflight, r *refusal) error {
	u.mu.Lock()
	for c := range u.calls {
		if (f == nil || c == f) && c.refused == nil {
			c.refused = r
		}
	}
	u.mu.Unlock()
	p.logger.Warn("netguard refused an upstream input request", "server", u.name, "tool", r.tool, "kind", r.kind, "reason", r.reason)
	return r
}

// upstreamElicitation handles a server-initiated elicitation/create from a
// stateful upstream: relabelled and relayed to a stateful agent that
// declared form elicitation, refused otherwise. The agent's cancellation of
// the call cancels the prompt.
func (p *Proxy) upstreamElicitation(u *upstream) func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
	return func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		f, n := u.sole()
		if f == nil {
			return nil, p.refuse(u, nil, &refusal{u.name, "", "elicitation", fmt.Sprintf("it cannot be attributed to one call (%d in flight)", n)})
		}
		switch {
		case f.agent.stateless():
			// ADR 0014 (proposed): converting this into input_required means
			// holding the upstream call open across agent requests.
			return nil, p.refuse(u, f, &refusal{u.name, f.tool, "elicitation", "this client speaks " + f.agent.version + " and cannot receive a server-initiated prompt; see ADR 0014"})
		case !f.agent.canElicit:
			return nil, p.refuse(u, f, &refusal{u.name, f.tool, "elicitation", "this client does not support form elicitation"})
		}
		var ep *mcp.ElicitParams
		if req != nil {
			ep = req.Params
		}
		clean, r := relabelElicit(u.name, f.tool, ep)
		if r != nil {
			return nil, p.refuse(u, f, r)
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(f.ctx, cancel)
		defer stop()
		res, err := f.agent.session.Elicit(ctx, clean)
		if err == nil {
			res, err = cleanElicitResult(res)
		}
		if err != nil {
			p.logger.Warn("relaying an upstream prompt to the agent failed", "server", u.name, "tool", f.tool, "error", err)
			// The agent's error text stays with the proxy.
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "netguard: the client did not answer the elicitation"}
		}
		return res, nil
	}
}
