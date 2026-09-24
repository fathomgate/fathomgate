package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Upstream input requests (ADR 0008, ADR 0014; profile-schema section 8.4).
//
// An upstream asks for user input in one of two shapes: a stateless upstream
// returns an MRTR input_required result, a stateful one sends a
// server-initiated elicitation/create while the call is open. Whatever the
// shape, only form elicitation crosses to the agent, and only after
// relabelling: the message gets the prefix "[from <server>] ", the schema is
// rebuilt from an allow-list (schema.go) and every human-visible string is
// escaped. Sampling, roots, URL-mode elicitation and anything unrecognised
// are refused. The agent's answer crosses back only as an elicitation result
// with action accept (with its content), decline or cancel; nothing else, and
// no _meta.

const (
	// maxPromptText caps each relabelled string of an upstream prompt.
	maxPromptText = 2048
	// maxInputRequests caps how many input requests one result may carry.
	maxInputRequests = 16
	// maxInputRequestID caps the length of an upstream input request id.
	maxInputRequestID = 128
	// maxPromptsPerCall caps the prompts one call may put to the human,
	// across every path and every MRTR round.
	maxPromptsPerCall = 10
	// maxOrphans caps the agent sessions an upstream remembers ended calls
	// for; past it, one overflow entry stands for all the others.
	maxOrphans = 1024
)

// localAgentKey is the attribution key of the local agent session: stdio
// (and the in-memory transport in tests), where one agent session owns the
// process (ADR 0012), so every call on it is the same session's.
const localAgentKey = "local"

// agentSessionKey is the id netguard gives the agent session behind a call,
// for the ended-call records an upstream keeps (J5 in the re-review of
// PR #72). Those records outlive the sessions they name, so they hold an id
// and never a *mcp.ServerSession, which would keep a closed session, and
// everything it references, alive for the whole TTL.
//
//   - A stateful session over the HTTP listener has a session id, unique for
//     all time (go-sdk generates 130 random bits and netguard never reuses
//     one); that id, tagged, is the key.
//   - A session with no id, where the proxy has an HTTP listener, is a
//     per-request session of the stateless era. Such a session serves exactly
//     one request, so it can never own another call: its key is empty and its
//     record goes to the shared bucket (upstream.orphanOverflow), which is
//     foreign to every later call.
//   - Everything else is the local agent (stdio, in-memory), which has no
//     session id and one session per process.
//
// The listener is recognised from the proxy, not only from the call's
// principal, so a call that somehow reached it unauthenticated would be
// keyed as its own session rather than grouped with the local agent's.
func (p *Proxy) agentSessionKey(c call) string {
	if ss := c.agent.session; ss != nil {
		if id := ss.ID(); id != "" {
			return "s" + id
		}
	}
	if c.principal != "" || p.limits.Load() != nil {
		return ""
	}
	return localAgentKey
}

// promptLabel is the origin label every upstream prompt carries. Server
// names cannot be "netguard" (ValidateServerName), so no upstream can wear
// the proxy's own label.
func promptLabel(server string) string { return "[from " + server + "] " }

// refusal is netguard declining to pass an upstream input request on. Its
// text is safe to show the agent: it names the upstream and the kind of
// request, never the upstream's prompt.
type refusal struct {
	server, tool, kind string
	reason             error
}

func newRefusal(server, tool, kind string, reason error) *refusal {
	return &refusal{server: server, tool: tool, kind: kind, reason: reason}
}

func (r *refusal) Error() string {
	if r.tool == "" {
		return fmt.Sprintf("netguard refused an input request (%s) from upstream %s: %v", r.kind, r.server, r.reason)
	}
	return fmt.Sprintf("netguard refused an input request (%s) from upstream %s during %s: %v", r.kind, r.server, r.tool, r.reason)
}

func (r *refusal) Unwrap() error { return r.reason }

var errFormOnly = errors.New("only form elicitation is passed to the agent")

// relabelInputRequests checks every input request of an upstream
// input_required result and returns the agent-facing copies, or the reason
// netguard will not pass them on.
func relabelInputRequests(server, tool string, reqs mcp.InputRequestMap) (mcp.InputRequestMap, *refusal) {
	if len(reqs) > maxInputRequests {
		return nil, newRefusal(server, tool, "input_required", fmt.Errorf("more than %d input requests", maxInputRequests))
	}
	out := make(mcp.InputRequestMap, len(reqs))
	for id, ir := range reqs {
		if id == "" || len(id) > maxInputRequestID || strings.IndexFunc(id, isControl) >= 0 {
			return nil, newRefusal(server, tool, "input_required", errors.New("an input request id is empty, too long or has control characters"))
		}
		ep, ok := ir.(*mcp.ElicitParams)
		if !ok {
			return nil, newRefusal(server, tool, inputKind(ir), errFormOnly)
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
// form mode only, message labelled with its origin and escaped, schema
// rebuilt from the allow-list, _meta dropped. Both eras' paths use it.
func relabelElicit(server, tool string, ep *mcp.ElicitParams) (*mcp.ElicitParams, *refusal) {
	if ep == nil {
		return nil, newRefusal(server, tool, "elicitation", errors.New("empty request"))
	}
	if (ep.Mode != "" && ep.Mode != "form") || ep.URL != "" || ep.ElicitationID != "" {
		return nil, newRefusal(server, tool, "URL elicitation", errFormOnly)
	}
	if hasOriginLabel(ep.Message) {
		return nil, newRefusal(server, tool, "elicitation", errors.New("the message reads as an origin label (\"[from\"); only netguard labels prompts"))
	}
	schema, err := relabelSchema(server, ep.RequestedSchema)
	if err != nil {
		return nil, newRefusal(server, tool, "elicitation", fmt.Errorf("requested schema: %w", err))
	}
	return &mcp.ElicitParams{
		Mode:            "form",
		Message:         promptLabel(server) + escapeControl(ep.Message, maxPromptText),
		RequestedSchema: schema,
	}, nil
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

// resumed is what a verified MRTR retry carries on to the upstream call.
type resumed struct {
	responses mcp.InputResponseMap // allow-listed answers
	upState   string               // the upstream's own requestState
	round     int                  // input rounds so far in this call
	prompts   int                  // prompts put to the human so far in this call
}

// resume verifies a stateless agent's MRTR retry, which carries a
// requestState, and returns what to send the upstream. A requestState that
// fails any check, or an answer to an outstanding input request that is not
// an allow-listed elicitation result, is a JSON-RPC invalid-params error and
// nothing reaches the upstream. Answers to ids that are not outstanding are
// ignored and never forwarded (SEP-2322: ignore what is not recognised); the
// upstream decides whether a missing answer means asking again.
func (p *Proxy) resume(c call) (resumed, error) {
	name := prefixName(c.up.name, c.tool)
	st, err := p.states.open(c.requestState)
	if err != nil {
		return resumed{}, invalidRetry(name, reasonInvalidRequestState, err)
	}
	switch {
	case st.Server != c.up.name || st.Tool != c.tool:
		return resumed{}, invalidRetry(name, reasonInvalidRequestState, fmt.Errorf("requestState was issued for %s", clip(prefixName(st.Server, st.Tool))))
	case st.Args != argsDigest(c.arguments):
		return resumed{}, invalidRetry(name, reasonInvalidRequestState, errors.New("arguments differ from the call that asked for input"))
	}
	out := make(mcp.InputResponseMap, len(c.inputResponses))
	for id, r := range c.inputResponses {
		if !slices.Contains(st.IDs, id) {
			continue
		}
		er, ok := r.(*mcp.ElicitResult)
		if !ok {
			return resumed{}, invalidRetry(name, reasonInvalidInputResponse, fmt.Errorf("response %q is not an elicitation result", clip(id)))
		}
		clean, err := cleanElicitResult(er)
		if err != nil {
			return resumed{}, invalidRetry(name, reasonInvalidInputResponse, err)
		}
		out[id] = clean
	}
	return resumed{responses: out, upState: st.Up, round: st.Round, prompts: st.Prompts}, nil
}

// askAgent puts relabelled input requests to a stateful agent as
// server-initiated elicitation/create requests, one at a time in id order,
// and returns the allow-listed answers. Each prompt takes the call's single
// prompt slot and counts toward its prompt limit, the same slot and limit a
// stateful upstream's elicitation/create uses, so the two paths cannot open
// prompts side by side or add up past the limit. A non-nil result is a tool
// error to return instead.
func (p *Proxy) askAgent(ctx context.Context, c call, f *inflight, reqs mcp.InputRequestMap) (mcp.InputResponseMap, *mcp.CallToolResult, error) {
	ids := make([]string, 0, len(reqs))
	for id := range reqs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := make(mcp.InputResponseMap, len(ids))
	for _, id := range ids {
		if err := c.up.startPrompt(f); err != nil {
			r := newRefusal(c.up.name, c.tool, "input_required", err)
			_ = p.refuse(c.up, f, r)
			return nil, toolError(r.Error()), nil
		}
		r, err := c.agent.session.Elicit(ctx, reqs[id].(*mcp.ElicitParams))
		c.up.endPrompt(f)
		if err == nil {
			r, err = cleanElicitResult(r)
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			p.logger.Warn("relaying an upstream prompt to the agent failed", "server", c.up.name, "tool", c.tool, "error", err)
			// The error can quote the upstream's schema (a validation
			// failure names properties and values), so it stays in the log;
			// netguard's own text names only the server and tool.
			return nil, toolError(fmt.Sprintf("netguard could not relay an input request from upstream %s during %s to the agent: the client did not answer it, or its answer did not fit the form",
				c.up.name, c.tool)), nil
		}
		out[id] = r
	}
	return out, nil, nil
}

// inflight is one call open on an upstream. A stateful upstream's
// elicitation/create names no call, so the proxy attributes it to the only
// call in flight on that upstream, and refuses it when there is not exactly
// one, or when another agent session's call on that upstream has ended
// recently and the upstream may still be working on it (attribute). All
// fields after sessionKey are guarded by upstream.mu.
type inflight struct {
	ctx        context.Context // the agent's request context
	agent      agentPeer
	tool       string
	principal  string // attribution only (call.principal)
	sessionKey string // the agent session, for attribution (agentSessionKey)

	// refused is netguard's refusal of this call's own prompt. The upstream
	// may fail the call because of it, so it may replace an upstream error.
	refused *refusal
	// note is a refusal of a prompt that could not be attributed to one
	// call. It is only ever appended to a result, never put in place of an
	// upstream error or result: this call may not be the one that asked.
	note *refusal
	// prompting is set while one of this call's prompts is with the agent;
	// prompts counts those put to the human, including earlier MRTR rounds.
	// Every path shares them: one prompt open per call, at most
	// maxPromptsPerCall per call.
	prompting bool
	prompts   int
}

// begin registers a call as in flight on u, with the prompts an earlier
// round of the same call already put to the human.
func (u *upstream) begin(ctx context.Context, c call, prompts int) *inflight {
	f := &inflight{ctx: ctx, agent: c.agent, tool: c.tool, principal: c.principal, sessionKey: c.sessionKey, prompts: prompts}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.calls == nil {
		u.calls = make(map[*inflight]struct{})
	}
	u.calls[f] = struct{}{}
	return f
}

// orphan is what an upstream remembers of a call one agent session made
// that has ended. The upstream may still be working on it: netguard cannot
// tell, whether the call was cancelled (by the agent, a dropped POST, a
// deleted or expired session, or netguard shutting down, after which go-sdk
// returns at once and sends notifications/cancelled, which the upstream may
// ignore) or answered (the upstream may have left a job running, and go-sdk
// can dispatch a result before a prompt the upstream sent just before it).
// So every ended call is remembered, not only a cancelled one (J1 in the
// re-review of PR #72, widening H1 in the review of PR #68). Until expires,
// a prompt may belong to that session, so it is never put to another.
type orphan struct {
	principal string // attribution only, for the log
	expires   time.Time
}

// end removes f from the calls in flight at now and, when expires is after
// now, records f's agent session as having ended a call on u until then, in
// the same critical section, so no prompt finds f gone and its orphan not
// yet there. It also forgets the orphans that have expired by now (K2 in
// the re-review of PR #72) and returns them, so the caller can log them
// outside the lock.
//
// A call whose agent session can never own another call (a per-request
// session of the stateless era: agentSessionKey returns "") is remembered
// in the shared bucket, which is foreign to every later call, so a busy
// stateless agent adds no entries to the table.
func (u *upstream) end(f *inflight, now, expires time.Time) []orphan {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.calls, f)
	reaped := u.pruneOrphans(now)
	if !now.Before(expires) {
		return reaped
	}
	key := f.sessionKey
	if key == "" {
		u.orphanOverflow = later(u.orphanOverflow, expires)
		return reaped
	}
	if u.orphans == nil {
		u.orphans = make(map[string]orphan)
	}
	if o, ok := u.orphans[key]; ok {
		u.orphans[key] = orphan{principal: f.principal, expires: later(o.expires, expires)}
		return reaped
	}
	if len(u.orphans) >= maxOrphans {
		u.orphanOverflow = later(u.orphanOverflow, expires)
		return reaped
	}
	u.orphans[key] = orphan{principal: f.principal, expires: expires}
	return reaped
}

// later returns the later of a and b.
func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// pruneOrphans forgets the orphans that have expired by now and returns
// them. Callers hold mu.
func (u *upstream) pruneOrphans(now time.Time) []orphan {
	var reaped []orphan
	for key, o := range u.orphans {
		if !now.Before(o.expires) {
			reaped = append(reaped, o)
			delete(u.orphans, key)
		}
	}
	return reaped
}

// prune forgets the orphans that have expired by now and returns them.
func (u *upstream) prune(now time.Time) []orphan {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.pruneOrphans(now)
}

// refusalsFor reads f's own refusal and its unattributed note.
func (u *upstream) refusalsFor(f *inflight) (own, note *refusal) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return f.refused, f.note
}

// attribute reports the call a stateful upstream's elicitation/create may
// be relayed to, or the reason it may not be. The request
// names no call, so it is attributed only when every call that could have
// sent it belongs to one agent session: exactly one call in flight on u,
// and every live orphan on u (a call that has ended while the upstream may
// still be working on it) left by that call's session. Anything else is
// refused rather than risk putting one agent session's prompt to another's
// human, whose answer would then go back as the answer to the first's (H1
// in the review of PR #68, widened by J1 in the re-review of PR #72: a
// prompt is refused even when the call it could belong to ended normally).
// A stateless agent's requests each have a session of their own, so each of
// its ended calls blocks every other call until it expires.
//
// It reads the orphans without pruning them, so it can run under a clock
// the caller chooses; end prunes.
func (u *upstream) attribute(now time.Time) attribution {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.calls) != 1 {
		return attribution{err: fmt.Errorf("it cannot be attributed to one call (%d in flight)", len(u.calls))}
	}
	var f *inflight
	for c := range u.calls {
		f = c
	}
	foreign := now.Before(u.orphanOverflow)
	for key, o := range u.orphans {
		if now.Before(o.expires) && key != f.sessionKey {
			foreign = true
			break
		}
	}
	if foreign {
		return attribution{sole: f, err: errEndedElsewhere}
	}
	return attribution{sole: f}
}

// attribution is what attribute found. A prompt may be relayed only when
// err is nil, and then to sole. sole is also set when there is exactly one
// call in flight but the orphan rule refuses it: the caller may word its
// refusal from that call, and must not relay anything to it.
type attribution struct {
	sole *inflight
	err  error
}

// promptable reports why f's agent cannot be shown any prompt from this
// upstream, or nil when it can.
func promptable(f *inflight) error {
	switch {
	case f.agent.stateless():
		// ADR 0014 (accepted): converting this into input_required would
		// mean holding the upstream call open across agent requests;
		// deferred to matrix row 17.
		return errStatelessClient
	case !f.agent.canElicit:
		return errNoFormElicitation
	}
	return nil
}

// promptsSoFar is the number of prompts f has put to the human.
func (u *upstream) promptsSoFar(f *inflight) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return f.prompts
}

// startPrompt reserves f's single prompt slot, or says why it cannot.
func (u *upstream) startPrompt(f *inflight) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	switch {
	case f.prompting:
		return errors.New("another prompt from this upstream is still open for this call")
	case f.prompts >= maxPromptsPerCall:
		return errTooManyPrompts
	}
	f.prompting = true
	f.prompts++
	return nil
}

// endPrompt releases f's prompt slot.
func (u *upstream) endPrompt(f *inflight) {
	u.mu.Lock()
	defer u.mu.Unlock()
	f.prompting = false
}

// logReaped logs the orphans an upstream has just forgotten, naming the
// principal each of them was blocking cross-session attribution for (J3 in
// the re-review of PR #72). It is Info: an operator who saw a refused
// prompt needs to see when the block lifted.
func (p *Proxy) logReaped(u *upstream, reaped []orphan) {
	for _, o := range reaped {
		p.logger.Info("an ended call no longer blocks prompt attribution on this upstream",
			"server", u.name, "principal", o.principal)
	}
}

// refuse records r against f, or, when the request could not be attributed
// (f is nil), as a note on every call in flight on u, since any of them may
// be the one waiting. It logs r and returns it as the error the upstream
// receives.
func (p *Proxy) refuse(u *upstream, f *inflight, r *refusal) error {
	u.mu.Lock()
	if f != nil {
		if f.refused == nil {
			f.refused = r
		}
	} else {
		for c := range u.calls {
			if c.note == nil {
				c.note = r
			}
		}
	}
	u.mu.Unlock()
	p.logger.Warn("netguard refused an upstream input request", "server", u.name, "tool", r.tool, "kind", r.kind, "reason", r.reason)
	return r
}

// withRefusals appends the refusals recorded during a call to its final
// result, so the agent learns what netguard declined on its behalf.
func withRefusals(res *mcp.CallToolResult, own, note *refusal) *mcp.CallToolResult {
	for _, r := range []*refusal{own, note} {
		if r != nil {
			res.Content = append(res.Content, &mcp.TextContent{Text: r.Error()})
		}
	}
	return res
}

// upstreamElicitation handles a server-initiated elicitation/create from a
// stateful upstream: relabelled and relayed to a stateful agent that
// declared form elicitation, one at a time and at most maxPromptsPerCall per
// call, and refused otherwise. go-sdk runs incoming requests concurrently,
// so the per-call slot is what stops a burst. The agent's cancellation of
// the call cancels the prompt.
func (p *Proxy) upstreamElicitation(u *upstream) func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
	return func(upCtx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		now := p.now()
		p.logReaped(u, u.prune(now))
		at := u.attribute(now)
		if at.err != nil {
			// When one call is in flight but the orphan rule refuses it,
			// and its agent could not have been shown any prompt anyway,
			// say that instead: nothing crosses to a human either way, and
			// "this client cannot take a server-initiated prompt" is the
			// answer the upstream and the agent can act on (ADR 0014).
			//
			// This ordering is deliberate (T0.40, accepted by the
			// orchestrator). Since J1 remembers every call that ends, a
			// stateless agent's earlier request leaves a live orphan on
			// almost every upstream it touches, so without this the
			// documented ADR 0014 refusal would be replaced by the
			// attribution refusal for practically every 2026-era agent, and
			// the era_pairs conformance check (a 2026 agent against a 2025
			// upstream) would read the wrong text. The prompt is refused
			// either way; only the reason differs. The refusal is recorded
			// against that call because it is the only call that could have
			// received the prompt at all.
			if s := at.sole; s != nil {
				if err := promptable(s); err != nil {
					return nil, p.refuse(u, s, newRefusal(u.name, s.tool, "elicitation", err))
				}
			}
			return nil, p.refuse(u, nil, newRefusal(u.name, "", "elicitation", at.err))
		}
		f := at.sole
		if err := promptable(f); err != nil {
			return nil, p.refuse(u, f, newRefusal(u.name, f.tool, "elicitation", err))
		}
		var ep *mcp.ElicitParams
		if req != nil {
			ep = req.Params
		}
		clean, r := relabelElicit(u.name, f.tool, ep)
		if r != nil {
			return nil, p.refuse(u, f, r)
		}
		if err := u.startPrompt(f); err != nil {
			return nil, p.refuse(u, f, newRefusal(u.name, f.tool, "elicitation", err))
		}
		defer u.endPrompt(f)
		// The prompt goes out under the agent's call context, not the
		// upstream request's: over Streamable HTTP, go-sdk puts a
		// server-to-client request on the POST stream of the request whose
		// context it carries, and on no stream at all otherwise. It is
		// cancelled by either side: the agent's cancellation of the call or
		// the upstream's of its request.
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		stop := context.AfterFunc(upCtx, cancel)
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

var (
	errNoFormElicitation = errors.New("this client does not support form elicitation")
	// errStatelessClient names no agent-supplied value: the text reaches
	// both the upstream and the agent.
	errStatelessClient = errors.New("this client speaks the stateless era (2026-07-28) and cannot receive a server-initiated prompt; see ADR 0014")
	errTooManyPrompts  = fmt.Errorf("more than %d prompts in one call", maxPromptsPerCall)
	// errEndedElsewhere names no session or principal: the text reaches
	// the upstream and every agent with a call in flight on it.
	errEndedElsewhere = errors.New("it cannot be attributed to one call: another agent session's call on this upstream has ended recently and the upstream may still be working on it")
)
