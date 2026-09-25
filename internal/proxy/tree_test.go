// SPDX-License-Identifier: Apache-2.0

//go:build unix || windows

package proxy

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tests for ADR 0021 (T0.46): the upstream's whole process tree is stopped
// on the ADR 0018 restart, on a failed startup, on shutdown and when the
// upstream exits mid-session. Each starts the launcher fixture (runLauncher)
// in front of a fake whose process is the upstream's grandchild, ignores
// stdin EOF and SIGTERM, and holds the upstream's stderr. "Gone" is checked
// against a watch taken before the kill (procWatch: a process handle on
// Windows, kill(pid, 0) until ESRCH on Unix).

// goneWithin bounds how long a killed grandchild may take to disappear
// (and on Unix to be reaped by init or launchd).
const goneWithin = 5 * time.Second

// launcherCommand is a Command running the launcher fixture in front of a
// fake in mode child. onEOF "exit" makes the launcher exit when its stdin
// closes; otherwise it ignores that.
func launcherCommand(t *testing.T, child, onEOF string, stderr *syncBuffer) Command {
	return Command{
		Path:   testExecutable(t),
		Args:   []string{"-test.run=^$"},
		Env:    []string{fakeUpstreamEnv + "=launcher", launchChildEnv + "=" + child, launcherEOFEnv + "=" + onEOF, childRaceEnv},
		Stderr: stderr,
	}
}

var launcherPIDRE = regexp.MustCompile(regexp.QuoteMeta(launcherPIDLine) + `(\d+)`)

// grandchildren waits until the launchers have reported n children on
// stderr and returns their PIDs in the order they were started.
func grandchildren(t *testing.T, stderr *syncBuffer, n int) []int {
	t.Helper()
	timer := time.NewTimer(goneWithin)
	defer timer.Stop()
	for {
		m := launcherPIDRE.FindAllStringSubmatch(stderr.String(), -1)
		if len(m) >= n {
			pids := make([]int, 0, n)
			for _, s := range m[:n] {
				pid, err := strconv.Atoi(s[1])
				if err != nil {
					t.Fatal(err)
				}
				pids = append(pids, pid)
			}
			return pids
		}
		select {
		case <-stderr.notify:
		case <-timer.C:
			t.Fatalf("launchers reported %d children, want %d; stderr:\n%s", len(m), n, stderr.String())
		}
	}
}

// startBehindLauncher starts a proxy on the launcher fixture in front of a
// go-sdk fake ("1", which answers server/discover, so there is no
// restart), and returns it with a watch on the grandchild.
func startBehindLauncher(t *testing.T, onEOF string) (*Proxy, *commandBuilds, *procWatch) {
	t.Helper()
	stderr := newSyncBuffer()
	b := &commandBuilds{cmd: launcherCommand(t, "1", onEOF, stderr)}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: b.build}}, Options{})
	if err != nil {
		t.Fatalf("%v\nstderr:\n%s", err, stderr.String())
	}
	return p, b, watchProcess(t, grandchildren(t, stderr, 1)[0])
}

// closeProxy closes p. Its error is logged, not checked: go-sdk's Close
// returns the upstream's Wait error, which for an upstream it had to kill,
// or whose descendant held stderr, is not nil. That is unchanged by ADR 0021.
func closeProxy(t *testing.T, p *Proxy) {
	t.Helper()
	if err := p.Close(); err != nil {
		t.Logf("Close: %v", err)
	}
}

// TestTreeRestartKillsGrandchild: the ADR 0018 restart, forced with the
// discoverExpired hook, kills the first launcher's child with the launcher,
// before the second is started; then Close, with a launcher that ignores
// stdin EOF and SIGTERM, kills the second launcher's child.
func TestTreeRestartKillsGrandchild(t *testing.T) {
	t.Parallel()
	stderr := newSyncBuffer()
	b := &commandBuilds{cmd: launcherCommand(t, "nodiscover", "ignore", stderr)}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	e := newProbeExpiry()
	type result struct {
		p   *Proxy
		err error
	}
	done := make(chan result, 1)
	go func() {
		p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: b.build}},
			Options{Logger: slog.New(slog.DiscardHandler), discoverExpired: e.ch})
		done <- result{p, err}
	}()
	stderr.waitFor(t, "fake upstream: unknown method server/discover; not reading any more\n")
	first := watchProcess(t, grandchildren(t, stderr, 1)[0])
	e.fire()
	out := <-done
	if out.err != nil {
		t.Fatalf("%v\nstderr:\n%s", out.err, stderr.String())
	}
	p := out.p
	t.Cleanup(func() { _ = p.Close() })
	if n := len(b.get()); n != 2 {
		t.Fatalf("processes started: %d, want 2", n)
	}
	first.waitGone(t, goneWithin, "the first launcher's child after the restart")

	second := watchProcess(t, grandchildren(t, stderr, 2)[1])
	// The launcher ignores stdin EOF and SIGTERM, so go-sdk kills it and
	// Close reports that kill's exit status, as for any such upstream.
	closeProxy(t, p)
	second.waitGone(t, goneWithin, "the second launcher's child after Close")
}

// TestTreeCloseSweepsAfterLauncherExits: the launcher obeys stdin EOF and
// is reaped by go-sdk's Close on its own; its child ignores both EOF and
// SIGTERM and is ended by the post-reap sweep.
func TestTreeCloseSweepsAfterLauncherExits(t *testing.T) {
	t.Parallel()
	p, b, gc := startBehindLauncher(t, "exit")
	// The child holds the stderr pipe until the sweep, which runs after
	// the reap, so the reap waits out WaitDelay (the backstop ADR 0021
	// keeps) and Close may report exec.ErrWaitDelay.
	closeProxy(t, p)
	if b.get()[0].Command.ProcessState == nil {
		t.Fatal("the launcher was not reaped")
	}
	gc.waitGone(t, goneWithin, "the launcher's child after Close")
}

// TestTreeStartupBudgetNoWaitDelay: when the startup budget runs out while
// a launcher's child holds the upstream's stderr, New returns within the
// budget and scheduling slack, not the budget plus WaitDelay (2 s): the
// child dies with the launcher, so its stderr closes (L1 in the re-review
// of PR #79).
func TestTreeStartupBudgetNoWaitDelay(t *testing.T) {
	t.Parallel()
	const budget = 3 * time.Second
	stderr := newSyncBuffer()
	b := &commandBuilds{cmd: launcherCommand(t, "silent", "ignore", stderr)}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	// The probe bound never runs out here, so only the budget ends the
	// start: no restart.
	e := newProbeExpiry()
	start := time.Now()
	type result struct {
		p   *Proxy
		err error
	}
	done := make(chan result, 1)
	go func() {
		p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: b.build}}, Options{discoverExpired: e.ch})
		done <- result{p, err}
	}()
	gc := watchProcess(t, grandchildren(t, stderr, 1)[0])
	out := <-done
	elapsed := time.Since(start)
	if out.err == nil {
		_ = out.p.Close()
		t.Fatal("New succeeded against a silent upstream")
	}
	if slack := time.Second; elapsed > budget+slack {
		t.Errorf("New took %s with a %s startup budget (WaitDelay is %s)", elapsed, budget, waitDelay)
	}
	built := b.get()
	if len(built) != 1 || built[0].Command.ProcessState == nil {
		t.Fatalf("launchers started: %d; want 1, reaped", len(built))
	}
	gc.waitGone(t, goneWithin, "the launcher's child after the startup budget ran out")
}

// TestTreeExitWatcherSweeps: the launcher exits mid-session while its
// child lives on; the exit watcher's close reaps the launcher and sweeps
// the child.
func TestTreeExitWatcherSweeps(t *testing.T) {
	t.Parallel()
	p, _, gc := startBehindLauncher(t, "ignore")
	t.Cleanup(func() { _ = p.Close() })
	up := p.upstreams[testServer]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// The launcher exits on this line, so the call gets no answer.
	_, _ = up.session.CallTool(ctx, &mcp.CallToolParams{Name: "env", Arguments: map[string]any{"name": launcherExitArg}})
	select {
	case <-up.done:
	case <-ctx.Done():
		t.Fatal("the exit watcher never saw the launcher exit")
	}
	gc.waitGone(t, goneWithin, "the launcher's child after the launcher exited")
}

// TestTreeAttachFailsClosed (L2 in the security review of PR #111): when
// the tree cannot be attached, Connect fails with the ADR 0021 error, the
// process is killed and reaped, and on Windows, where it starts suspended,
// it never ran. Not parallel: attachFault is package-wide, and parallel
// tests start only once every serial test has returned.
func TestTreeAttachFailsClosed(t *testing.T) {
	fault := errors.New("FAKE attach failure")
	attachFault.Store(&fault)
	t.Cleanup(func() { attachFault.Store(nil) })
	marker := filepath.Join(t.TempDir(), "ran")
	b := &commandBuilds{cmd: Command{
		Path: testExecutable(t),
		Args: []string{"-test.run=^$"},
		Env:  []string{fakeUpstreamEnv + "=marker", markerEnv + "=" + marker, childRaceEnv},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: b.build}}, Options{})
	if err == nil {
		_ = p.Close()
		t.Fatal("New succeeded although the process tree could not be attached")
	}
	if !errors.Is(err, fault) || !strings.Contains(err.Error(), "proxy: upstream process tree (ADR 0021): ") {
		t.Errorf("error %q: want the ADR 0021 error wrapping the fault", err)
	}
	built := b.get()
	if len(built) != 1 {
		t.Fatalf("processes started: %d, want 1 (no restart after a tree failure)", len(built))
	}
	if built[0].Command.Process == nil || built[0].Command.ProcessState == nil {
		t.Fatal("the process was not started and reaped")
	}
	_, statErr := os.Stat(marker)
	if startsSuspended && !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("the process ran before its tree was attached (marker: %v)", statErr)
	}
}

// TestCommandTransportPreparesTree: Command.Transport starts the upstream
// in a tree of its own (ADR 0021), and keeps WaitDelay as the backstop.
func TestCommandTransportPreparesTree(t *testing.T) {
	cmd := Command{Path: "x"}.Transport().Command
	if cmd.WaitDelay != waitDelay {
		t.Errorf("WaitDelay %s, want %s", cmd.WaitDelay, waitDelay)
	}
	assertPrepared(t, cmd)
}

// TestProcTreeNil: a transport that owns no process has a nil tree, and
// every method on it is a no-op.
func TestProcTreeNil(t *testing.T) {
	var tree *procTree
	tree.kill()
	tree.terminate()
	tree.sweep(time.Second)
	tree.mirrorShutdown()()
}
