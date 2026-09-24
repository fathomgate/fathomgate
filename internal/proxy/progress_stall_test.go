package proxy

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A slow agent must not stall an upstream (T0.28, security review S2 on PR
// #53). go-sdk hands an upstream's notifications to their handler one at a
// time, so the progress relay must never write to the agent from there.

// readGate pauses what one agent reads, as an agent that stops reading its
// transport does, and records the kind of every message the agent reads.
type readGate struct {
	mu   sync.Mutex
	open chan struct{} // closed while reads flow
	seen []string      // "progress" or "response", in the order read
}

func newReadGate() *readGate {
	g := &readGate{open: make(chan struct{})}
	close(g.open)
	return g
}

// pause stops reads, and the record of what was read starts again. The
// agent's reader may already be waiting for one message, and go-sdk's
// transport decodes one more ahead, so a couple of messages still get
// through before the agent's pipe fills.
func (g *readGate) pause() {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.open:
		g.open = make(chan struct{})
		g.seen = nil
	default:
	}
}

// resume lets reads flow again. It is idempotent.
func (g *readGate) resume() {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.open:
	default:
		close(g.open)
	}
}

func (g *readGate) gate() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.open
}

func (g *readGate) record(m jsonrpc.Message) {
	var kind string
	switch m := m.(type) {
	case *jsonrpc.Response:
		kind = "response"
	case *jsonrpc.Request:
		if m.Method != "notifications/progress" {
			return
		}
		kind = "progress"
	default:
		return
	}
	g.mu.Lock()
	g.seen = append(g.seen, kind)
	g.mu.Unlock()
}

func (g *readGate) reads() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.seen...)
}

// gatedTransport is an agent transport that reads only while its gate is
// open.
type gatedTransport struct {
	mcp.Transport
	g *readGate
}

func (t gatedTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	c, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &gatedConn{Connection: c, g: t.g, closed: make(chan struct{})}, nil
}

type gatedConn struct {
	mcp.Connection
	g      *readGate
	once   sync.Once
	closed chan struct{}
}

func (c *gatedConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	select {
	case <-c.g.gate():
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, io.EOF
	}
	m, err := c.Connection.Read(ctx)
	if err == nil {
		c.g.record(m)
	}
	return m, err
}

func (c *gatedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Connection.Close()
}

// waitFor polls cond until it holds, or fails naming what did not happen.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// relayAt returns the relay on up whose newest accepted progress is last,
// or nil. It only tries the relay's lock, so a relay stuck holding it (the
// bug T0.28 fixes) reads as not there yet and waitFor fails rather than
// hangs.
func relayAt(up *upstream, last float64) *progressRelay {
	up.mu.Lock()
	defer up.mu.Unlock()
	for _, r := range up.progress {
		if !r.mu.TryLock() {
			continue
		}
		l := r.last
		r.mu.Unlock()
		if l == last {
			return r
		}
	}
	return nil
}

// addAskDirect adds "ask_direct", which asks with a server-initiated
// elicitation/create (a 2025-era upstream) and reports whether it got an
// answer.
func addAskDirect(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "ask_direct", InputSchema: objectSchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if _, err := req.Session.Elicit(ctx, promptFor("pw")); err == nil {
			return textResult("upstream got an answer"), nil
		}
		return textResult("upstream carried on without an answer"), nil
	})
}

// TestProgressStuckAgent: agent A asks for progress and then stops reading;
// agent B shares the proxy and the (stateful) upstream. The upstream's
// dispatch goroutine still reads A's whole flood; when A's call ends, its
// in-flight entry goes at once (after the short final wait), not when A
// reads again; B's later call gets the upstream's elicitation/create
// attributed to it (one call in flight, not two) and its result; and once A
// reads again it gets its result after every progress notification, and
// A's sender goroutine returns.
func TestProgressStuckAgent(t *testing.T) {
	for _, agentEra := range []string{v2025, v2026} {
		t.Run("agent "+agentEra, func(t *testing.T) {
			bg := context.Background()
			gate := newReadGate()
			h := newEraHarness(t, eraSetup{agent: agentEra, upstream: v2025, reads: gate, progress: newProgressLog(), extra: addAskDirect})
			h.proxy.progressWait = 50 * time.Millisecond
			promptsB := &promptLog{}
			agentB, _ := connectAgent(t, h.proxy, eraSetup{agent: v2025}, promptsB)
			t.Cleanup(gate.resume) // runs first, so both agents close cleanly
			up := h.proxy.upstreams[testServer]

			gate.pause()
			params := &mcp.CallToolParams{Name: "netdev-ssh-mcp.progress_flood"}
			params.SetProgressToken("stuck")
			type out struct {
				res *mcp.CallToolResult
				err error
			}
			aDone := make(chan out, 1)
			go func() {
				res, err := h.agent.CallTool(bg, params)
				aDone <- out{res, err}
			}()

			// The upstream's notifications keep flowing into the relay
			// although A reads nothing. (Before T0.28 the relay wrote to A
			// here, under the lock, and stopped at the second or third.)
			var r *progressRelay
			waitFor(t, "the relay to read the whole flood", func() bool {
				r = relayAt(up, floodSize)
				return r != nil
			})

			// A's upstream call ends. Its end() runs within the final wait
			// although A still reads nothing.
			if _, err := agentB.CallTool(bg, &mcp.CallToolParams{Name: "netdev-ssh-mcp.progress_release"}); err != nil {
				t.Fatalf("release: %v", err)
			}
			waitFor(t, "A's call to leave the calls in flight", func() bool {
				up.mu.Lock()
				defer up.mu.Unlock()
				return len(up.calls) == 0
			})
			select {
			case o := <-aDone:
				t.Fatalf("A got its result without reading: %v", o.err)
			default:
			}
			// Since T1 the call leaves the in-flight set before finish
			// waits, so wait for finish to give up as well: A must lose the
			// rest of its queue.
			waitFor(t, "A's relay to give up waiting", func() bool {
				r.mu.Lock()
				defer r.mu.Unlock()
				return r.abandoned
			})

			// The upstream's next request (elicitation/create for B's call)
			// and B's result still flow. A's ended call is an orphan of A's
			// own session (T0.43: two agents on one proxy never share a
			// key), so the prompt is refused for that reason, and not as
			// one of two calls in flight: A's call has left the set.
			refusedB(t, agentB)
			expireOrphan(t, up, localKeyPrefix+"1")
			// Once A's orphan has expired, the prompt is B's alone.
			res, err := agentB.CallTool(bg, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask_direct"})
			if err != nil || res.IsError {
				t.Fatalf("B's call: %v %q", err, text(res))
			}
			if got := text(res); got != "upstream got an answer" {
				t.Fatalf("B's result %q, want the upstream's answer", got)
			}
			if n := len(promptsB.all()); n != 1 {
				t.Fatalf("B saw %d prompts, want 1", n)
			}

			// A reads again: its result arrives, after every progress
			// notification it reads, and its sender returns.
			gate.resume()
			var o out
			select {
			case o = <-aDone:
			case <-time.After(5 * time.Second):
				t.Fatal("A's call did not return once A read again")
			}
			if o.err != nil || o.res.IsError {
				t.Fatalf("A's call: %v %q", o.err, text(o.res))
			}
			select {
			case <-r.exited:
			case <-time.After(5 * time.Second):
				t.Fatal("A's progress sender did not return")
			}
			reads := gate.reads()
			progress, sawResult := 0, false
			for _, k := range reads {
				switch {
				case k == "response":
					sawResult = true
				case sawResult:
					t.Fatalf("a progress notification followed A's result: %v", reads)
				default:
					progress++
				}
			}
			// The stall was real: A did not get the whole burst plus the
			// final update, because finish dropped what A had not read.
			if progress == 0 || progress >= progressBurst+1 {
				t.Fatalf("A read %d progress notifications, want between 1 and %d", progress, progressBurst)
			}
		})
	}
}

// TestProgressFlushOnTimer (S4 on PR #53): an update the rate limit held
// back is sent as soon as a rate slot frees up, while the call is still
// open, not only before the result.
func TestProgressFlushOnTimer(t *testing.T) {
	log := newProgressLog()
	h := newEraHarness(t, eraSetup{agent: v2026, upstream: v2026, progress: log})
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	h.proxy.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	up := h.proxy.upstreams[testServer]
	callProgressTool(t, h.agent, log, "progress_flood", "flood", func() {
		log.waitN(t, progressBurst)
		waitFor(t, "the relay to read the whole flood", func() bool { return relayAt(up, floodSize) != nil })
		// With the clock standing still no slot frees up: the sender's
		// timer fires (every 200ms) and finds none.
		time.Sleep(450 * time.Millisecond)
		if n := len(log.all()); n != progressBurst {
			t.Fatalf("agent got %d notifications with no rate slot free, want %d", n, progressBurst)
		}
		mu.Lock()
		now = now.Add(time.Second)
		mu.Unlock()
		got := log.waitN(t, progressBurst+1)
		if last := got[progressBurst]; last.Progress != floodSize {
			t.Fatalf("flushed notification progress %v, want %d", last.Progress, floodSize)
		}
	})
	// Nothing was left to send before the result.
	if _, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.get_config"}); err != nil {
		t.Fatal(err)
	}
	if n := len(log.all()); n != progressBurst+1 {
		t.Fatalf("agent got %d notifications, want %d", n, progressBurst+1)
	}
}

// TestProgressQueueBounded: a queue the agent is not draining holds at most
// progressBurst entries, the newest replacing the newest, so progress still
// increases along it.
func TestProgressQueueBounded(t *testing.T) {
	r := &progressRelay{}
	for i := 1; i <= 3*progressBurst; i++ {
		r.push(&mcp.ProgressNotificationParams{Progress: float64(i)})
	}
	if len(r.queue) != progressBurst {
		t.Fatalf("queue holds %d, want %d", len(r.queue), progressBurst)
	}
	for i, p := range r.queue[:progressBurst-1] {
		if p.Progress != float64(i+1) {
			t.Fatalf("entry %d progress %v, want %d", i, p.Progress, i+1)
		}
	}
	if last := r.queue[progressBurst-1]; last.Progress != 3*progressBurst {
		t.Fatalf("newest entry progress %v, want %d", last.Progress, 3*progressBurst)
	}
}

// TestUntilToken: the sender's timer waits for the next whole token, and
// never less than a millisecond when the clock does not move.
func TestUntilToken(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	r := newProgressRelay(context.Background(), testServer, agentPeer{session: &mcp.ServerSession{}}, "t", func() time.Time { return now }, progressFinalWait)
	defer r.cancelSend()
	for r.take() {
	}
	if d := r.untilToken(); d != time.Second/progressRate {
		t.Fatalf("empty bucket waits %v, want %v", d, time.Second/progressRate)
	}
	now = now.Add(time.Second / progressRate)
	if d := r.untilToken(); d != time.Millisecond {
		t.Fatalf("with a token due waits %v, want the 1ms floor", d)
	}
}

// TestEndBeforeFinish (T1 in the review of PR #63): a call leaves its
// upstream's in-flight set before it waits for its progress to reach the
// agent. Agent A stops reading with progress queued and its call ends; while
// A's relay is still waiting (a long final wait here), agent B's call gets
// the stateful upstream's elicitation/create attributed to it. Before the
// fix A's stale entry made two calls in flight, and B's prompt was refused.
func TestEndBeforeFinish(t *testing.T) {
	for _, agentEra := range []string{v2025, v2026} {
		t.Run("agent "+agentEra, func(t *testing.T) {
			bg := context.Background()
			gate := newReadGate()
			h := newEraHarness(t, eraSetup{agent: agentEra, upstream: v2025, reads: gate, progress: newProgressLog(), extra: addAskDirect})
			h.proxy.progressWait = 30 * time.Second
			promptsB := &promptLog{}
			agentB, _ := connectAgent(t, h.proxy, eraSetup{agent: v2025}, promptsB)
			t.Cleanup(gate.resume)
			up := h.proxy.upstreams[testServer]

			gate.pause()
			params := &mcp.CallToolParams{Name: "netdev-ssh-mcp.progress_flood"}
			params.SetProgressToken("stuck")
			aDone := make(chan error, 1)
			go func() {
				_, err := h.agent.CallTool(bg, params)
				aDone <- err
			}()
			var r *progressRelay
			waitFor(t, "the relay to read the whole flood", func() bool {
				r = relayAt(up, floodSize)
				return r != nil
			})
			if _, err := agentB.CallTool(bg, &mcp.CallToolParams{Name: "netdev-ssh-mcp.progress_release"}); err != nil {
				t.Fatalf("release: %v", err)
			}
			// A's call is in the window: finish has started and is still
			// waiting on A.
			waitFor(t, "A's relay to start finishing", func() bool {
				r.mu.Lock()
				defer r.mu.Unlock()
				return r.done
			})

			// As in TestProgressStuckAgent: A's orphan refuses the prompt,
			// as an orphan and not as one of two calls in flight, and once
			// it has expired the prompt is attributed to B.
			refusedB(t, agentB)
			expireOrphan(t, up, localKeyPrefix+"1")
			res, err := agentB.CallTool(bg, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask_direct"})
			if err != nil || res.IsError {
				t.Fatalf("B's call: %v %q", err, text(res))
			}
			if got := text(res); got != "upstream got an answer" {
				t.Fatalf("B's result %q: its prompt was not attributed to it", got)
			}
			if n := len(promptsB.all()); n != 1 {
				t.Fatalf("B saw %d prompts, want 1", n)
			}
			r.mu.Lock()
			abandoned := r.abandoned
			r.mu.Unlock()
			select {
			case <-r.exited:
				t.Fatal("A's sender finished before B's call; the window was not tested")
			default:
			}
			if abandoned {
				t.Fatal("A's relay gave up before B's call; the window was not tested")
			}

			gate.resume()
			select {
			case err := <-aDone:
				if err != nil {
					t.Fatalf("A's call: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("A's call did not return once A read again")
			}
		})
	}
}
