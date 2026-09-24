package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
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
	// maxOrphansPerPrincipal caps the keyed ended-call records one
	// principal has on one upstream. Past it, that principal's further
	// ended calls are folded into one overflow record of its own, which is
	// foreign to every call, that principal's included (T0.44). The table
	// therefore holds at most maxOrphansPerPrincipal+1 records per
	// principal, and principals are configured (HTTPOptions.Tokens) plus
	// the empty principal of the local agent.
	maxOrphansPerPrincipal = 256
)

// localKeyPrefix tags the attribution key of a local agent session: a
// session Proxy.Run serves (stdio, or the in-memory transport in tests).
// Run records the session and gives it a key of its own, "l1" for the
// first Run, so every call on it is recognised as that session's whether or
// not the proxy also has an HTTP listener (S1 in the security review of
// T0.40). `netguard serve` calls Run once (ADR 0012: one agent session owns
// the process); tests that run two agents on one proxy get two keys, never
// one shared by both.
const localKeyPrefix = "l"

// requestKeyPrefix tags the attribution key netguard makes up for a call
// whose agent session it cannot name: a per-request session of the
// stateless era over the listener (which serves exactly one request), a
// call with no session at all, or a local call whose context ended while
// it waited for Run to record its session. Each such call gets a key of
// its own, "r" and a number no other call on the proxy gets, so its ended
// call is an ordinary record: foreign to every later call, pruned at
// OrphanTTL, logged when reaped and attributed to its principal (T0.44,
// maintainer decision 2026-09-24). The tag keeps it apart from "s<id>"
// (a stateful session over the listener) and "l<n>" (a local agent).
const requestKeyPrefix = "r"

// agentSessionKey is the id netguard gives the agent session behind a call,
// for the ended-call records an upstream keeps (J5 in the re-review of
// PR #72). Those records outlive the sessions they name, so they hold an id
// and never a *mcp.ServerSession, which would keep a closed session, and
// everything it references, alive for the whole TTL.
//
// The key comes from what the session is, never from whether the proxy has
// a listener (S1 in the security review of T0.40):
//
//   - A session Proxy.Run serves is a local agent: the key Run gave it
//     (localKeyPrefix and the Run's number).
//   - A stateful session over the HTTP listener has a session id, unique for
//     all time (go-sdk generates 130 random bits and netguard never reuses
//     one); that id, tagged "s", is the key. A stateless agent's session
//     is never keyed by an id, even if go-sdk ever gives it one.
//   - Anything else gets a key of its own that no other call gets
//     (requestKey): a per-request session of the stateless era over the
//     listener, a call with no session at all, or a local call whose
//     context ended before Run recorded its session. Its record is foreign
//     to every later call, since no later call has its key, so a session
//     netguard cannot name gets the most blocking answer, never the local
//     agent's (S5 in the same review); and it is an ordinary table entry,
//     pruned, logged and attributed to its principal like any other
//     (T0.44).
//
// A call that came over the listener (it has a session id, or a principal,
// which the listener's authentication always sets, stateless requests
// included) is keyed without asking localKey, so it never waits for a
// connecting Run: that wait would happen before the listener's call caps
// admit the call (L1 in the security re-review of PR #78). Only a call with
// neither can be a local agent's.
func (p *Proxy) agentSessionKey(ctx context.Context, c call) string {
	if ss := c.agent.session; ss != nil {
		// A stateless agent's session never owns another call, whatever
		// its id: only a stateful session's id names a session (N1 in the
		// security review of PR #82). go-sdk's stateless handler gives its
		// per-request sessions no id today (TestStatelessSessionHasNoID).
		if id := ss.ID(); id != "" && !c.agent.stateless() {
			return "s" + id
		}
		if c.principal == "" {
			if key := p.localKey(ctx, ss); key != "" {
				return key
			}
		}
	}
	return p.requestKey()
}

// requestKey returns a key no other call on p has had or will have.
func (p *Proxy) requestKey() string {
	return requestKeyPrefix + strconv.FormatUint(p.requestKeys.Add(1), 10)
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
	st, err := p.states.open(c.requestState, c.binding())
	if err != nil {
		p.warnState(c, err)
		return resumed{}, invalidRetry(name, reasonInvalidRequestState, err)
	}
	// A state that opens was issued to this transport and principal, so
	// these two are a retry that kept its state and changed the call it
	// resumes. They are logged like a state that does not open (T0.48, L2
	// in the security review of PR #85), with netguard's own reason words:
	// the log names neither the tool the state was issued for nor any
	// argument.
	switch {
	case st.Server != c.up.name || st.Tool != c.tool:
		p.warnState(c, errStateOtherTool)
		return resumed{}, invalidRetry(name, reasonInvalidRequestState, fmt.Errorf("requestState was issued for %s", clip(prefixName(st.Server, st.Tool))))
	case st.Args != argsDigest(c.arguments):
		p.warnState(c, errStateOtherArgs)
		return resumed{}, invalidRetry(name, reasonInvalidRequestState, errStateOtherArgs)
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

// errStateOtherTool and errStateOtherArgs are the reasons warnState logs
// for a state that opened but was issued for another call: netguard's own
// words, naming nothing read from the envelope or the arguments. The agent
// is told which prefixed tool the state was issued for (its own earlier
// call); the log says only that it was another.
var (
	errStateOtherTool = errors.New("requestState was issued for another tool")
	errStateOtherArgs = errors.New("arguments differ from the call that asked for input")
)

// warnState logs a requestState netguard refused, naming the principal and
// transport that presented it, so an operator can tell whose client
// replays, forges or holds stale states, or keeps a valid state and changes
// the call it resumes (errStateOtherTool, errStateOtherArgs). A state
// issued to another principal or transport cannot be told from a forgery
// (errStateAuth), so the line says what failed, never whose state it was.
// err is always one of netguard's fixed reasons, never text from the
// envelope or the arguments.
//
// It is rate-limited like the refusal lines (refusalLog), since the agent
// decides how often it happens. The limiter key is the server, transport,
// principal and reason, and has no tool: a client that cycles through an
// upstream's tools gets one line per reason per refusalLogInterval, not one
// per tool. The line itself names the tool it was refused on.
func (p *Proxy) warnState(c call, err error) {
	key := "state\x00" + c.up.name + "\x00" + string(c.transport) + "\x00" + c.principal + "\x00" + err.Error()
	ok, suppressed, lost := p.refusalLog.allow(key, p.now())
	if !ok {
		return
	}
	args := []any{"server", c.up.name, "tool", c.tool, "transport", string(c.transport), "principal", logPrincipal(c.principal), "reason", err, "suppressed", suppressed}
	if lost > 0 {
		args = append(args, "suppressed_lost", lost)
	}
	p.logger.Warn("netguard refused a requestState", args...)
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
	// note is a refusal of a prompt netguard did not attribute to this call:
	// one that could not be attributed to one call, or one the orphan rule
	// refused (the ADR 0014 wording included). It is only ever appended to a
	// result, never put in place of an upstream error or result: this call
	// may not be the one that asked.
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
	// overflow is the number of ended calls an overflow record stands for
	// (a principal's calls past maxOrphansPerPrincipal); zero for a keyed
	// record.
	overflow int
}

// end removes f from the calls in flight at now and, when expires is after
// now, records f's agent session as having ended a call on u until then, in
// the same critical section, so no prompt finds f gone and its orphan not
// yet there. It also forgets the orphans that have expired by now (K2 in
// the re-review of PR #72) and returns them, so the caller can log them
// outside the lock. overflowed reports that f's principal has just gone
// over its quota on u, which the caller logs too.
//
// agentSessionKey gives every call a key, so every ended call is a table
// entry of its principal's. A principal holds at most
// maxOrphansPerPrincipal of them per upstream (T0.44). Past that, its
// further ended calls are folded into one overflow record of its own,
// which is foreign to every call, that principal's own sessions included:
// netguard no longer knows which of its sessions they were, and refusing
// is the safe answer. It fails closed, it is attributed to the principal,
// it is pruned and logged like any record, and it cannot crowd out another
// principal's records, so another principal's session is never pushed
// into anonymity by someone else's volume. It blocks other principals'
// prompts exactly as long as the ended calls it stands for would have as
// keyed records: an overflow gives a principal no reach over others that
// its ordinary ended calls do not already have.
func (u *upstream) end(f *inflight, now, expires time.Time) (reaped []orphan, overflowed bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.calls, f)
	reaped = u.pruneOrphans(now)
	if !now.Before(expires) {
		return reaped, false
	}
	key := f.sessionKey
	if o, ok := u.orphans[key]; ok && key != "" {
		u.orphans[key] = orphan{principal: o.principal, expires: later(o.expires, expires)}
		return reaped, false
	}
	// The empty key never reaches here from a tool handler
	// (agentSessionKey always names a key); if it does, it is folded into
	// the overflow record, which is foreign to everyone.
	if key != "" && u.orphansOf[f.principal] < maxOrphansPerPrincipal {
		if u.orphans == nil {
			u.orphans = make(map[string]orphan)
		}
		if u.orphansOf == nil {
			u.orphansOf = make(map[string]int)
		}
		u.orphans[key] = orphan{principal: f.principal, expires: expires}
		u.orphansOf[f.principal]++
		return reaped, false
	}
	if u.overflow == nil {
		u.overflow = make(map[string]orphan)
	}
	o, had := u.overflow[f.principal]
	u.overflow[f.principal] = orphan{principal: f.principal, expires: later(o.expires, expires), overflow: o.overflow + 1}
	return reaped, !had
}

// later returns the later of a and b.
func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// pruneOrphans forgets the orphans, keyed and overflow, that have expired
// by now and returns them. Callers hold mu.
func (u *upstream) pruneOrphans(now time.Time) []orphan {
	var reaped []orphan
	for key, o := range u.orphans {
		if !now.Before(o.expires) {
			reaped = append(reaped, o)
			delete(u.orphans, key)
			if u.orphansOf[o.principal]--; u.orphansOf[o.principal] <= 0 {
				delete(u.orphansOf, o.principal)
			}
		}
	}
	for principal, o := range u.overflow {
		if !now.Before(o.expires) {
			reaped = append(reaped, o)
			delete(u.overflow, principal)
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
		in := newPrincipalSet()
		for c := range u.calls {
			in.add(c.principal)
		}
		return attribution{err: fmt.Errorf("it cannot be attributed to one call (%d in flight)", len(u.calls)), inFlightOf: in.sorted()}
	}
	var f *inflight
	for c := range u.calls {
		f = c
	}
	ended := newPrincipalSet()
	for key, o := range u.orphans {
		if now.Before(o.expires) && key != f.sessionKey {
			ended.add(o.principal)
		}
	}
	for principal, o := range u.overflow {
		if now.Before(o.expires) {
			ended.add(principal)
		}
	}
	if len(ended) > 0 {
		return attribution{sole: f, err: errEndedElsewhere, endedCallsOf: ended.sorted()}
	}
	return attribution{sole: f}
}

// principalSet collects principal names for a refusal's log line, the
// local agent (no principal) as localPrincipal.
type principalSet map[string]struct{}

func newPrincipalSet() principalSet { return make(principalSet) }

func (s principalSet) add(principal string) { s[logPrincipal(principal)] = struct{}{} }

func (s principalSet) sorted() []string { return slices.Sorted(maps.Keys(s)) }

// attribution is what attribute found. A prompt may be relayed only when
// err is nil, and then to sole. sole is also set when there is exactly one
// call in flight but the orphan rule refuses it: the caller may word its
// refusal from that call, and must not relay anything to it.
type attribution struct {
	sole *inflight
	err  error
	// endedCallsOf names the principals whose live ended calls made the
	// orphan rule refuse (err is errEndedElsewhere), and inFlightOf the
	// principals of the calls in flight when there was not exactly one.
	// Both are sorted and for the log only: they never reach the agent or
	// the upstream (T0.44; S4 in the security review of T0.40, L2 in the
	// review of PR #82). The local agent, which has no principal, is
	// localPrincipal.
	endedCallsOf []string
	inFlightOf   []string
}

// localPrincipal names the local agent (no principal) in a refusal's log
// line. It is not a valid principal name (validPrincipalName), so it
// cannot be mistaken for one.
const localPrincipal = "(local)"

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
//
// An overflow record (a principal's ended calls past its quota, T0.44) is
// logged with the number of ended calls it stood for.
func (p *Proxy) logReaped(u *upstream, reaped []orphan) {
	for _, o := range reaped {
		if o.overflow > 0 {
			p.logger.Info("ended calls over the principal's orphan quota no longer block prompt attribution on this upstream",
				"server", u.name, "principal", o.principal, "calls", o.overflow)
			continue
		}
		p.logger.Info("an ended call no longer blocks prompt attribution on this upstream",
			"server", u.name, "principal", o.principal)
	}
}

// endCall ends f on u at now: it leaves the calls in flight and becomes an
// orphan of its agent session for the orphan TTL (end). It logs the orphans
// that expired, and, at Warn, a principal going over its orphan quota on u:
// from then until the overflow record is reaped, that principal's further
// ended calls refuse every session's prompts on u, its own sessions' too.
func (p *Proxy) endCall(u *upstream, f *inflight, now time.Time) {
	reaped, overflowed := u.end(f, now, now.Add(p.orphanTTL()))
	p.logReaped(u, reaped)
	if overflowed {
		p.logger.Warn("a principal's ended calls on this upstream exceed its orphan quota; further ones refuse every agent session's prompts on it until none has ended for the orphan TTL",
			"server", u.name, "principal", f.principal, "quota", maxOrphansPerPrincipal)
	}
}

// refuse records r against f, the one call the request was attributed
// to, logs it (rate-limited, naming f's principal; warnRefusal) and
// returns it as the error the upstream receives.
func (p *Proxy) refuse(u *upstream, f *inflight, r *refusal) error {
	u.mu.Lock()
	if f.refused == nil {
		f.refused = r
	}
	u.mu.Unlock()
	name := logPrincipal(f.principal)
	p.warnRefusal(u, r, true, r.kind+":"+r.reason.Error(), []string{name}, "principal", name)
	return r
}

// refuseUnattributed refuses a prompt attribute could not attribute to one
// call: it records r as a note on every call in flight on u, since any of
// them may be the one waiting, and logs one Warn line naming the
// principals behind the refusal (ended_calls_of for the orphan rule,
// in_flight_of when not exactly one call was in flight), rate-limited
// (warnRefusal). It returns r as the error the upstream receives.
func (p *Proxy) refuseUnattributed(u *upstream, at attribution, r *refusal) error {
	u.mu.Lock()
	for c := range u.calls {
		if c.note == nil {
			c.note = r
		}
	}
	u.mu.Unlock()
	if errors.Is(at.err, errEndedElsewhere) {
		p.warnRefusal(u, r, false, "orphan", at.endedCallsOf, "ended_calls_of", at.endedCallsOf)
	} else {
		p.warnRefusal(u, r, false, "count", at.inFlightOf, "in_flight_of", at.inFlightOf)
	}
	return r
}

// warnRefusal logs a refusal of an upstream input request at Warn, with
// attrs (the principals behind it), at most once per refusalLogInterval
// for each server, attribution, class of refusal and set of principals
// (who) (L4 and L1 in the security reviews of PR #82): an upstream that
// asks in a loop, attributed or not, must not flood the log. A line
// carries suppressed, the number of lines for the same key held back since
// the last; a burst's count is reported by the next line for that key, if
// any. suppressed_lost, when present, is the number of held-back lines
// whose count was lost because the limiter swept its table to make room.
func (p *Proxy) warnRefusal(u *upstream, r *refusal, attributed bool, class string, who []string, attrs ...any) {
	key := u.name + "\x00" + strconv.FormatBool(attributed) + "\x00" + class + "\x00" + strings.Join(who, ",")
	ok, suppressed, lost := p.refusalLog.allow(key, p.now())
	if !ok {
		return
	}
	args := []any{"server", u.name, "tool", r.tool, "kind", r.kind, "reason", r.reason, "attributed", attributed}
	args = append(args, attrs...)
	args = append(args, "suppressed", suppressed)
	if lost > 0 {
		args = append(args, "suppressed_lost", lost)
	}
	p.logger.Warn("netguard refused an upstream input request", args...)
}

// logPrincipal is how a principal is named in a log line: the local agent,
// which has none, as localPrincipal.
func logPrincipal(principal string) string {
	if principal == "" {
		return localPrincipal
	}
	return principal
}

const (
	// refusalLogInterval is the least time between two Warn lines for the
	// same key: a refused upstream input request (warnRefusal) or a refused
	// requestState (warnState).
	refusalLogInterval = 10 * time.Second
	// maxRefusalLogKeys bounds the rate limiter's memory. Past it, entries
	// older than refusalLogInterval are dropped, and if that frees nothing,
	// all are: that can only let a line through early, never hide one. The
	// held-back counts of dropped entries are not reported by their own
	// key's next line; allow returns their sum, which the line that caused
	// the sweep carries as suppressed_lost.
	maxRefusalLogKeys = 1024
)

// refusalLimiter rate-limits the Warn lines of refusals: of upstream input
// requests (warnRefusal) and of requestStates (warnState), in one table;
// warnState's keys start with "state". The zero value is ready to use.
type refusalLimiter struct {
	mu   sync.Mutex
	last map[string]refusalLogEntry
}

type refusalLogEntry struct {
	at         time.Time
	suppressed int
}

// allow reports whether a line for key may be logged at now and, if so,
// how many lines for key were held back since the last one, and how many
// held-back lines of other keys were dropped uncounted to make room.
func (l *refusalLimiter) allow(key string, now time.Time) (ok bool, suppressed, lost int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, seen := l.last[key]
	if seen && now.Sub(e.at) < refusalLogInterval {
		e.suppressed++
		l.last[key] = e
		return false, 0, 0
	}
	if l.last == nil {
		l.last = make(map[string]refusalLogEntry)
	}
	if !seen && len(l.last) >= maxRefusalLogKeys {
		for k, old := range l.last {
			if now.Sub(old.at) >= refusalLogInterval {
				lost += old.suppressed
				delete(l.last, k)
			}
		}
		if len(l.last) >= maxRefusalLogKeys {
			for _, old := range l.last {
				lost += old.suppressed
			}
			clear(l.last)
		}
	}
	l.last[key] = refusalLogEntry{at: now}
	return true, e.suppressed, lost
}

// refuseAsNote records r as a note on f alone: a refusal of a prompt that
// was not attributed to f, worded from f because f is the only call that
// could have received it. Like every note it is only appended to f's
// result, never put in place of an upstream error or result. It logs r,
// rate-limited and naming f's principal as in_flight_of (warnRefusal), and
// returns it as the error the upstream receives.
func (p *Proxy) refuseAsNote(u *upstream, f *inflight, r *refusal) error {
	u.mu.Lock()
	if f.note == nil {
		f.note = r
	}
	u.mu.Unlock()
	in := newPrincipalSet()
	in.add(f.principal)
	who := in.sorted()
	p.warnRefusal(u, r, false, "sole:"+r.reason.Error(), who, "in_flight_of", who)
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
			// either way; only the reason differs.
			//
			// The refusal goes in s's note slot, never its own slot (S3 in
			// the security review of T0.40): the orphan rule fired, so this
			// is exactly a prompt netguard could NOT attribute to s, and the
			// own slot would put netguard's text in place of the upstream's
			// error. As a note it is only appended to a result s completes;
			// an upstream error stays the upstream's. It goes to s alone,
			// not to every call in flight (refuse with a nil call), because
			// its text names s's tool and a call that began since may be
			// another agent session's.
			if s := at.sole; s != nil {
				if err := promptable(s); err != nil {
					return nil, p.refuseAsNote(u, s, newRefusal(u.name, s.tool, "elicitation", err))
				}
			}
			// One Warn line per refusal, naming the principals behind it
			// (ended_calls_of or in_flight_of), so a refused prompt can be
			// explained from the log (T0.44, S4).
			return nil, p.refuseUnattributed(u, at, newRefusal(u.name, "", "elicitation", at.err))
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
