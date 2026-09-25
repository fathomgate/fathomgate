// SPDX-License-Identifier: FSL-1.1-ALv2

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fathomgate/fathomgate/internal/gate/seam"
)

// Gate decides every tools/call before the proxy forwards it (ADR 0026,
// steps 1 to 6). internal/gate implements it; the proxy names only the
// plain-data types of internal/gate/seam, so it imports none of classify,
// inventory or policy. [Options.Gate] nil keeps the M0 pass-through.
//
// Both methods must be safe for concurrent use. The proxy recovers a panic
// in Decide as a deny, but a Gate must not rely on that.
type Gate interface {
	// Decide says whether to forward one call. The proxy forwards it only
	// when the Verdict's Forward is true, and otherwise returns the
	// Verdict's Error to the agent as a tool error; it makes no upstream
	// call.
	Decide(ctx context.Context, in seam.CallInfo) seam.Verdict
	// Arguments reports the argument names the server's profile names for
	// tool, and whether the tool's argument list is closed (ADR 0033). The
	// proxy calls it once per upstream tool, in [New], and keeps the answer
	// on the tool's route: that one snapshot narrows the inputSchema it
	// advertises (every property Decide would refuse is dropped) and decides
	// whether an upstream's input request during a call to the tool is
	// refused (its answers would reach the upstream unchecked). It is never
	// called per call or per prompt. A panic in it counts as closed with no
	// names.
	Arguments(server, tool string) (named []string, closed bool)
}

// maxArgumentBytes caps a tools/call's arguments, as the agent sent them,
// when a Gate is set. A call over it is denied with default:bad_arguments
// before Decide runs: no decoder, classifier or log line sees an arguments
// object of any size the agent chooses. 64 KiB is well above any shipped
// profile's arguments (the largest are config payloads of a few KiB) and
// matches the cap on an upstream's elicitation schema (maxSchemaInput).
const maxArgumentBytes = 64 << 10

// Rule ids the proxy produces itself, beside the gate's. ruleInternalError
// is reserved by ADR 0026 (amendment of M1-19): a call fathomgate could not
// decide is never forwarded.
const (
	ruleBadArguments  = "default:bad_arguments"
	ruleInternalError = "default:internal_error"
)

// The proxy's own refusals, in the gate's one first-line shape. The class
// is EXEC_ARBITRARY because fathomgate did not classify the call, and an
// unclassified call is EXEC_ARBITRARY (classification.md section 3). The
// class_source "proxy" says the classifier never ran (policy-schema 5,
// audit-event-schema 2).
const (
	unclassified        = "EXEC_ARBITRARY"
	unclassifiedSource  = "proxy"
	reasonTooLarge      = "the arguments are larger than 64 KiB"
	reasonInternalError = "fathomgate could not decide this call, so it was not run"
	// reasonNotForwarded stands in for a Verdict that refuses a call
	// without saying why (a Gate other than internal/gate).
	reasonNotForwarded = "the policy does not allow this call"
	parseTooLarge      = "too_large"
)

// decision is one call's verdict and, when it is forwarded, the arguments
// the upstream receives.
type decision struct {
	v    seam.Verdict
	args json.RawMessage // re-encoded from the checked object; nil for none
}

// gated runs the gate on c and either refuses it or forwards it with the
// re-encoded arguments. Every call the gate decides, forwarded or not,
// writes one decision line (ADR 0026 step 8). An MRTR retry runs here
// again, on the tool and arguments the sealed state binds.
//
// What forward could still refuse without the upstream is checked first,
// so a call the gate allows is sent (forwarded=true in the line, and its
// targets counted): a retry's requestState is opened and verified (a
// forged, expired or rebound state is the JSON-RPC error resume returns,
// logged by warnState, with no decision line and nothing counted), and an
// upstream that has exited gets its tool error. An upstream that exits
// between that check and the send still has the call counted: the count
// errs high, never low.
func (p *Proxy) gated(ctx context.Context, c call) (*mcp.CallToolResult, error) {
	if c.requestState != "" {
		rs, err := p.resume(c)
		if err != nil {
			return nil, err
		}
		c.resumed = &rs
	}
	if c.up.exited() {
		return upstreamDown(c.up), nil
	}
	d, refused, err := p.decideAndRespond(ctx, c)
	if err != nil {
		return nil, err
	}
	if refused != nil {
		return refused, nil
	}
	c.gated, c.upArguments = true, d.args
	return p.forward(ctx, c)
}

// decideAndRespond is the decision stage of gated: decide, the decision
// line, and for a call that is not forwarded the tool error the agent gets
// (refused non-nil). It is everything fathomgate adds to a call before the
// upstream sees it, and the unit TestDispatchOverhead times (M1-23). err
// is decide's: ctx ended while the call waited for its counter key's lock.
func (p *Proxy) decideAndRespond(ctx context.Context, c call) (d decision, refused *mcp.CallToolResult, err error) {
	d, err = p.decide(ctx, c)
	if err != nil {
		return decision{}, nil, err
	}
	p.logDecision(ctx, d.v)
	if !d.v.Forward {
		return d, toolError(d.v.Error), nil
	}
	return d, nil, nil
}

// decide is steps 5 to 7 around Gate.Decide: the argument cap, the session
// counters (read, and for a forwarded call updated, under the counter key's
// lock, so two calls of one key cannot both pass max_devices on the same
// count), the panic guard and the re-encoding of the arguments. It fails
// only when ctx ends while it waits for the key's lock.
func (p *Proxy) decide(ctx context.Context, c call) (decision, error) {
	in := p.callInfo(c)
	if len(c.arguments) > maxArgumentBytes {
		return decision{v: p.refusalVerdict(in, ruleBadArguments, reasonTooLarge, parseTooLarge)}, nil
	}
	sc := p.counters.get(counterKey(c))
	if err := sc.lock(ctx, p.testHookCounterWait); err != nil {
		return decision{}, err
	}
	defer sc.unlock()
	return p.decideLocked(ctx, c, in, sc), nil
}

// decideLocked is decide with the counter key's lock held.
func (p *Proxy) decideLocked(ctx context.Context, c call, in seam.CallInfo, sc *sessionCounter) decision {
	in.DevicesTouched = sc.touchedCount()
	v, ok := p.safeDecide(ctx, in)
	if !ok {
		return decision{v: p.refusalVerdict(in, ruleInternalError, reasonInternalError, "")}
	}
	// max_devices counts distinct devices, with the call's own targets
	// (policy-schema 2). A target this key has already touched is counted
	// once: decide again without it in the touched count. Decide is pure,
	// so the second verdict differs from the first only by that count.
	if again := sc.alreadyTouched(v.Targets); again > 0 {
		in.DevicesTouched -= again
		if v, ok = p.safeDecide(ctx, in); !ok {
			return decision{v: p.refusalVerdict(in, ruleInternalError, reasonInternalError, "")}
		}
	}
	if !v.Forward {
		if v.Error == "" {
			v.Error = refusalText("denied", in.Server, in.Tool, orUnknown(v.RuleID), orUnclassified(v.Class), reasonNotForwarded)
		}
		return decision{v: v}
	}
	args, err := reencode(c.arguments)
	if err != nil {
		// Unreachable with internal/gate, which refuses anything reencode
		// cannot read; fail closed for any other Gate.
		return decision{v: p.refusalVerdict(in, ruleBadArguments, reasonNotObject, parseCode(err))}
	}
	sc.touch(v.Targets)
	v.Error = ""
	return decision{v: v, args: args}
}

// safeDecide calls the gate and turns a panic, in Decide or in the
// inventory resolver it calls, into ok false. The line at Error names the
// panic's kind: a runtime error's own text (an index out of range, a nil
// dereference), which carries no call data, and otherwise only the panic
// value's type, since a value may quote an argument. The agent gets only
// the fixed deny.
func (p *Proxy) safeDecide(ctx context.Context, in seam.CallInfo) (v seam.Verdict, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			// Only the runtime's own errors have fixed text; a type from
			// elsewhere that implements runtime.Error may carry anything.
			kind := fmt.Sprintf("%T", r)
			if re, isRuntime := r.(runtime.Error); isRuntime && strings.HasPrefix(strings.TrimPrefix(kind, "*"), "runtime.") {
				kind = re.Error()
			}
			p.logger.Error("the gate panicked; the call is denied", "server", in.Server, "tool", in.Tool, "panic", kind)
			v, ok = seam.Verdict{}, false
		}
	}()
	return p.gate.Decide(ctx, in), true
}

// callInfo is what the gate is told about c.
func (p *Proxy) callInfo(c call) seam.CallInfo {
	r := p.routes[prefixName(c.up.name, c.tool)]
	return seam.CallInfo{
		Server:           c.up.name,
		Tool:             c.tool,
		Arguments:        c.arguments,
		ReadOnlyHint:     r.readOnly,
		DestructiveHint:  r.destructive,
		AgentProtocol:    c.agent.version,
		AgentEra:         eraOf(c.agent.version),
		UpstreamProtocol: c.up.version,
		UpstreamEra:      c.up.era,
		Transport:        string(c.transport),
		Principal:        logPrincipal(c.principal),
		SessionID:        logSessionID(c.sessionKey),
	}
}

// logSessionID is fathomgate's short session hash for a stateful agent
// session over the listener, as the session lines of http.go log it, and
// "" for any other call (stdio, stateless): they have no session id.
func logSessionID(sessionKey string) string {
	if id, ok := strings.CutPrefix(sessionKey, "s"); ok && id != "" {
		return shortHash(id)
	}
	return ""
}

// logDecision writes the decision line at Info, with the trace when the
// logger is at Debug. The attributes are the gate's; slog quotes and
// escapes every string, so an agent-chosen argument name in unnamed_args
// cannot start a line of its own (TestDecisionLineOneLine).
func (p *Proxy) logDecision(ctx context.Context, v seam.Verdict) {
	attrs := v.Record
	if v.Trace.Key != "" && p.logger.Enabled(ctx, slog.LevelDebug) {
		attrs = append(slices.Clip(attrs), v.Trace)
	}
	p.logger.LogAttrs(ctx, slog.LevelInfo, "decision", attrs...)
}

// refusalVerdict is a deny the proxy decides itself, before or instead of
// the gate, with the gate's record fields so the line reads like every
// other decision line.
func (p *Proxy) refusalVerdict(in seam.CallInfo, rule, reason, parseError string) seam.Verdict {
	v := seam.Verdict{
		Effect: "deny", RuleID: rule, Class: unclassified, ClassSource: unclassifiedSource,
		Error: refusalText("denied", in.Server, in.Tool, rule, unclassified, reason),
	}
	v.Record = []slog.Attr{
		slog.String("server", in.Server),
		slog.String("tool", in.Tool),
		slog.String("class", v.Class),
		slog.String("class_source", v.ClassSource),
		slog.Any("targets", []string{}),
		slog.Any("roles", []string{}),
		slog.Bool("unknown_target", false),
		slog.String("decision", v.Effect),
		slog.String("rule_id", rule),
		slog.String("reason", reason),
		slog.Any("obligations", []string{}),
		slog.Bool("forwarded", false),
		slog.String("agent_protocol", in.AgentProtocol),
		slog.String("agent_era", in.AgentEra),
		slog.String("upstream_protocol", in.UpstreamProtocol),
		slog.String("upstream_era", in.UpstreamEra),
		slog.String("transport", in.Transport),
		slog.String("principal", in.Principal),
		slog.String("session_id", in.SessionID),
	}
	if parseError != "" {
		v.Record = append(v.Record, slog.String("parse_error", parseError))
	}
	return v
}

// refusalText is ADR 0026's one first-line shape:
//
//	fathomgate <denied|cannot run|held> <server>.<tool>: rule <rule_id> (class <CLASS>): <reason>
//
// Server and tool names have passed validUpstreamToolName; the rule id and
// reason are fathomgate's own text.
func refusalText(verb, server, tool, rule, class, reason string) string {
	return "fathomgate " + verb + " " + prefixName(server, tool) + ": rule " + rule + " (class " + class + "): " + reason
}

func orUnknown(rule string) string {
	if rule == "" {
		return ruleInternalError
	}
	return rule
}

func orUnclassified(class string) string {
	if class == "" {
		return unclassified
	}
	return class
}

// reasonNotObject is the gate's reason for arguments it cannot read.
const reasonNotObject = "the arguments must be one JSON object, in UTF-8, with no key given twice"

// errNotObject: the arguments are not one JSON object.
var errNotObject = errors.New("not a JSON object")

// reencode returns the arguments the upstream receives: the object the gate
// checked, decoded and encoded again, never the agent's bytes (ADR 0033,
// N2). Keys are sorted, strings are as Go decoded them (so as the gate read
// them: an invalid escape is U+FFFD for both), and numbers keep their
// literal text. A duplicate key inside a nested object keeps the one Go
// kept; the gate has already refused a duplicate at the top level. Empty,
// absent and null arguments are none (nil), as forward sends them today.
func reencode(raw json.RawMessage) (json.RawMessage, error) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(t))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errNotObject
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errTrailing
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false) // <, > and & as sent, not as \u escapes
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}

var errTrailing = errors.New("data after the arguments object")

// parseCode is the decision line's parse_error for a reencode failure.
func parseCode(err error) string {
	if errors.Is(err, errTrailing) {
		return "trailing_data"
	}
	if errors.Is(err, errNotObject) {
		return "not_object"
	}
	return "invalid_json"
}

// The session counters (ADR 0026, Session counters, decision 4 as amended
// by the maintainer on 2026-09-25). Over the HTTP listener every call is
// counted by its principal, whatever its era: a principal that opens,
// closes or has evicted its sessions keeps its count (T0.57). On stdio,
// where one agent owns the process, every call is counted as the process.
// pending_holds is always 0 in M1 (no hold is ever pending). Counters live
// in memory and reset with the process.

// maxTouchedNames caps the distinct target names one counter key remembers.
// Past it, every target not remembered is counted again on each forwarded
// call: the count can only grow too fast, which max_devices reads as more
// devices touched, never fewer.
const maxTouchedNames = 4096

// counterKey is the counter key of c: its principal over HTTP, the process
// on stdio. No key names a session, so no entry outlives what it counts.
func counterKey(c call) string {
	if c.transport == transportHTTP {
		return "principal:" + c.principal
	}
	return "process"
}

// counters holds one sessionCounter per counter key. Entries are never
// removed: the keys are the listener's configured principals plus the
// process, so the map holds at most that many entries.
type counters struct {
	mu   sync.Mutex
	keys map[string]*sessionCounter
}

func (cs *counters) get(key string) *sessionCounter {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.keys == nil {
		cs.keys = make(map[string]*sessionCounter)
	}
	sc := cs.keys[key]
	if sc == nil {
		sc = &sessionCounter{touched: make(map[string]struct{}), sem: make(chan struct{}, 1)}
		cs.keys[key] = sc
	}
	return sc
}

// sessionCounter is one counter key's devices touched. Its lock (sem, one
// slot) is held across a decision, up to two Decide calls (decide), and
// is taken with the call's context, so a call whose agent gives up does
// not wait behind another call's decision.
type sessionCounter struct {
	sem     chan struct{}
	touched map[string]struct{}
	extra   int // targets counted past maxTouchedNames
}

// lock takes the key's lock, or returns ctx's error if ctx ends first.
// waiting, when set (tests), runs when the lock is held by another call.
func (s *sessionCounter) lock(ctx context.Context, waiting func()) error {
	select {
	case s.sem <- struct{}{}:
		return nil
	default:
	}
	if waiting != nil {
		waiting()
	}
	select {
	case s.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *sessionCounter) unlock() { <-s.sem }

func (s *sessionCounter) touchedCount() int { return len(s.touched) + s.extra }

// alreadyTouched is how many of targets are remembered as touched.
func (s *sessionCounter) alreadyTouched(targets []string) int {
	n := 0
	for _, t := range dedupe(targets) {
		if _, ok := s.touched[t]; ok {
			n++
		}
	}
	return n
}

// touch counts the targets of a forwarded call.
func (s *sessionCounter) touch(targets []string) {
	for _, t := range dedupe(targets) {
		if _, ok := s.touched[t]; ok {
			continue
		}
		if len(s.touched) < maxTouchedNames {
			s.touched[t] = struct{}{}
		} else {
			s.extra++
		}
	}
}

// dedupe returns targets without repeats (internal/gate already removes
// them; another Gate may not).
func dedupe(targets []string) []string {
	if len(targets) < 2 {
		return targets
	}
	seen := make(map[string]struct{}, len(targets))
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}

// narrowSchema returns a copy of an upstream tool's inputSchema that offers
// only the named properties (ADR 0033 section 4): every other property is
// removed from properties and from required, and additionalProperties is
// false. The upstream's schema is not changed. What the agent is offered
// changes; what is checked does not (Decide still refuses an unnamed
// argument). Only the top-level properties and required are trimmed: a
// property offered through allOf, anyOf, oneOf, $defs, patternProperties
// or dependentSchemas stays in the schema, and Decide refuses it when sent.
// dropped lists the removed property names for the log.
func narrowSchema(schema any, named []string) (_ any, dropped []string) {
	m, ok := schema.(map[string]any)
	if !ok {
		return schema, nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	if props, ok := m["properties"].(map[string]any); ok {
		kept := make(map[string]any, len(props))
		for k, v := range props {
			if slices.Contains(named, k) {
				kept[k] = v
			} else {
				dropped = append(dropped, k)
			}
		}
		out["properties"] = kept
	}
	if req, ok := m["required"].([]any); ok {
		kept := make([]any, 0, len(req))
		for _, r := range req {
			if s, ok := r.(string); ok && slices.Contains(named, s) {
				kept = append(kept, r)
			}
		}
		out["required"] = kept
	}
	out["additionalProperties"] = false
	slices.Sort(dropped)
	return out, dropped
}

// argumentsClosed reports whether calls to server's tool have a closed
// argument list under the gate, from the snapshot New took (route.closed):
// then an upstream prompt during such a call is refused, because its answer
// would be an argument the profile never named (ADR 0026 and ADR 0014,
// notes after acceptance; ADR 0033 N1).
func (p *Proxy) argumentsClosed(server, tool string) bool {
	return p.routes[prefixName(server, tool)].closed
}

// toolArguments is Gate.Arguments for one upstream tool, read once in New.
// A panic is closed with no names (every argument refused), logged at
// Error.
func (p *Proxy) toolArguments(server, tool string) (named []string, closed bool) {
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("the gate panicked listing a tool's arguments; the tool takes none", "server", server, "tool", tool, "panic", fmt.Sprintf("%T", r))
			named, closed = nil, true
		}
	}()
	return p.gate.Arguments(server, tool)
}

// errPromptsUnchecked is the reason fathomgate gives the agent and the
// upstream for refusing an upstream prompt under a policy.
var errPromptsUnchecked = errors.New("a policy is enforced and fathomgate cannot check an answer against the server profile, so upstream prompts are not relayed")
