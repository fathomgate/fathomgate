// SPDX-License-Identifier: FSL-1.1-ALv2

// Package gatetest is the M1-23 overhead corpus and its measurement, shared
// by the tier 1 overhead tests of internal/gate (Decide alone) and
// internal/proxy (the dispatch path around Decide).
//
// Package gatetest is for tests only: it imports testing, and nothing the
// fathomgate binary links may import it (TestNotInBinary checks
// cmd/fathomgate's dependencies).
//
// The PRD's M1 success metric is "under 5 ms at p99 for classify plus
// evaluate, measured in tier 1". The tests time every call on its own after
// a warm-up and fail when the p99 of the typical corpus is over [Budget]
// ([CheckTypical]), in every run. The worst cases, arguments at the proxy's
// 64 KiB cap, are timed one by one against the same budget ([CheckWorst]).
// Their p50 is enforced only when [Strict] is true, which the CI steps that
// run the overhead tests alone with -p 1 set: in a full parallel go test
// run, other packages' tests share the CPU and a p50 of a few milliseconds
// is not the gate's alone. In the strict steps a p50 over the budget fails
// unless the case is known ([KnownOverBudget]), and a known case back under
// the budget fails too, so its entry is removed. A p99 over the budget is
// logged as OVER BUDGET AT p99 everywhere. Their p99 is not a pass condition
// because it is set by garbage collection, not by the call: each worst case
// allocates 0.4 to 1.0 MB (0.4 to 3.4 MB before M1-39), so a collection
// starts every few calls and, on Windows with GOMAXPROCS 8 or more, stalls
// a random call for 10 to 13 ms (p99 1.5 to 2 ms with GOGC=off, or with
// GOMAXPROCS 4). The threshold never moves; the numbers are in
// docs/testing/test-strategy.md.
package gatetest

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// Budget is the PRD's p99 limit per call. It is never raised to make a run
// pass (M1-23).
const Budget = 5 * time.Millisecond

// RaceFactor relaxes the budget under -race only. The race detector
// instruments every memory access and slows CPU-bound Go code by 2 to 20
// times (Go's race detector documentation); the gate is all map, string,
// regexp and JSON work, near the top of that range. The budget holds at 1x
// in every run without -race, and the strict steps of the Linux, Windows
// and macOS CI jobs (ci.yaml) run without it. Under -race the typical
// corpus still catches an order-of-magnitude regression.
const RaceFactor = 10

// MaxArgs is the proxy's cap on a call's arguments (internal/proxy
// maxArgumentBytes). A call over it never reaches Decide, so a call at it
// is the largest Decide ever parses.
const MaxArgs = 64 << 10

// Limit is the p99 limit for this build: Budget, times RaceFactor under
// -race.
func Limit() time.Duration {
	if RaceEnabled {
		return Budget * RaceFactor
	}
	return Budget
}

// StrictEnv is the environment variable that turns on [Strict].
const StrictEnv = "FATHOMGATE_OVERHEAD_STRICT"

// Strict reports whether StrictEnv is "1": the worst cases' p50 is then
// enforced. Only the CI steps that run the overhead tests alone (-p 1, no
// -race) set it.
func Strict() bool { return os.Getenv(StrictEnv) == "1" }

// WhatGate and WhatProxy name the two measurements, for the logs and
// KnownOverBudget.
const (
	WhatGate  = "gate Decide"
	WhatProxy = "proxy decision stage"
)

// knownOverBudget holds the worst cases whose p50 is over Budget, keyed
// "<what>: <case>", with the finding and its owner. Remove an entry when its
// finding is fixed: the strict steps fail on a known case that is back
// under the budget, and on an unknown case over it. It is empty: M1-39
// fixed both M1-23 findings (commands are classified without unanchored
// regexps and capped at 64 a call, targets at 256, and the proxy runs
// Decide once).
var knownOverBudget = map[string]string{}

// KnownOverBudget returns the finding for worst case name under
// measurement what (WhatGate or WhatProxy), and whether its p50 is known to
// be over Budget.
func KnownOverBudget(what, name string) (finding string, ok bool) {
	finding, ok = knownOverBudget[what+": "+name]
	return finding, ok
}

// WorstShowCommands and the other Worst names are the worst cases' names,
// for KnownOverBudget and the logs.
const (
	WorstShowCommands = "eos run_commands, 64 show commands of 1 KiB"
	WorstOneCommand   = "upa send_command, one 64 KiB multi-line command"
	WorstConfigString = "upa core write, 64 KiB multi-line config string"
	WorstConfigLines  = "eos lab push_config, 64 KiB of config lines"
	WorstManyTargets  = "eos daily_brief, 256 distinct targets of 250 bytes"
	WorstBatch        = "eos run_commands_batch, every known target, 64 commands of 1 KiB"
	// The same 64 KiB as short commands or names, over the per-call caps.
	WorstTooManyCommands = "eos run_commands, 1,900 short show commands (over the command cap)"
	WorstTooManyTargets  = "eos daily_brief, 3,300 short targets (over the target cap)"
)

// CommandCap and TargetCap are the gate's per-call caps (internal/gate
// maxCommandsPerCall and maxTargetsPerCall, profile-schema 2.4), and
// CommandWidth and TargetWidth the longest command and name the gate reads
// in full (classify's maxCommandLen; a hostname's 253 bytes). The worst
// cases sit exactly at the caps.
const (
	CommandCap   = 64
	CommandWidth = 1024
	TargetCap    = 256
	TargetWidth  = 253
)

// Case is one call of the corpus and the verdict it must get under
// prod-approval with the repo profiles and inventory.example.yaml. The
// tests check the verdict first, so a change that turns a costly path into
// a cheap early refusal fails instead of making the measurement easier.
type Case struct {
	Name         string
	Server, Tool string // profile server key and the upstream's own tool name
	Args         json.RawMessage
	Effect, Rule string
	Worst        bool
}

// The three M1 validates_against servers, by their profile keys.
const (
	netdev = "netdev-ssh-mcp"
	upa    = "upa"
	eos    = "eos-mcp"
)

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func typical(name, server, tool string, args map[string]any, effect, rule string) Case {
	return Case{Name: name, Server: server, Tool: tool, Args: mustJSON(args), Effect: effect, Rule: rule}
}

// Typical returns the fixed mix of calls through the three M1 profiles: typed
// reads, downgraded exec, config dumps, refused exec, writes that hold,
// unknown targets, bad names, fan-out and group selectors. Its p99 is the
// PRD metric.
func Typical() []Case {
	return []Case{
		typical("netdev read", netdev, "run_show_command", map[string]any{"host": "core-rtr-01", "command": "show ip bgp summary"}, "allow", "reads-anywhere"),
		typical("netdev get_config lab", netdev, "get_config", map[string]any{"host": "lab-sw-01"}, "allow", "reads-anywhere"),
		typical("upa downgraded read", upa, "send_command_and_get_output", map[string]any{"name": "core-rtr-01", "command": "show interfaces status"}, "allow", "reads-anywhere"),
		typical("upa reload", upa, "send_command_and_get_output", map[string]any{"name": "core-rtr-01", "command": "reload"}, "deny", "no-exec"),
		typical("upa core write", upa, "set_config_commands_and_commit_or_save", map[string]any{"name": "core-rtr-01", "commands": []any{"interface Ethernet1", "description uplink"}}, "hold", "prod-core-needs-approval"),
		typical("eos show running-config", eos, "run_command", map[string]any{"hostname": "lab-sw-01", "command": "show running-config"}, "allow", "reads-anywhere"),
		typical("eos run_commands", eos, "run_commands", map[string]any{"hostname": "lab-sw-01", "commands": []any{"show version", "show clock", "show ip route"}}, "allow", "reads-anywhere"),
		typical("eos push_config core", eos, "push_config", map[string]any{"hostname": "core-rtr-01", "config_lines": []any{"hostname x"}}, "hold", "prod-core-needs-approval"),
		typical("eos attacker host", eos, "get_version", map[string]any{"hostname": "core-x.attacker.example"}, "deny", "default:unknown_target"),
		typical("eos bad name", eos, "get_version", map[string]any{"hostname": "lab-x@core-rtr-01"}, "deny", "default:bad_arguments"),
		typical("eos daily_brief four", eos, "daily_brief", map[string]any{"hostnames": []any{"lab-sw-01", "lab-sw-02", "core-rtr-01", "core-rtr-02"}}, "allow", "reads-anywhere"),
		typical("eos daily_brief tags", eos, "daily_brief", map[string]any{"tags": []any{"core"}}, "deny", "default:bad_arguments"),
	}
}

// Worst returns the worst-case corpus: arguments within 1 KiB under the
// 64 KiB cap whose every command, config line or target the gate must
// check (no input fails early, except the one multi-line command, which the
// downgrade refuses at its first line break after reading the whole
// payload). Commands and targets are at the gate's per-call caps (M1-39):
// 64 commands of about 1 KiB each (the classifier's cap per command) and
// 256 targets of about 250 bytes, each resolved. Two more cases fill the
// same 64 KiB with short commands or names, far over the caps, and must be
// the cheap default:bad_arguments refusal. known are the device names of
// the inventory under test (inventory.example.yaml, as the tests load it):
// the short target list starts with them, and the batch names all of them.
func Worst(known []string) ([]Case, error) {
	if len(known) == 0 {
		return nil, fmt.Errorf("no inventory device names")
	}
	show := func(i int) string { return fmt.Sprintf("show interfaces Ethernet%d/%d status", i/48+1, i%48+1) }
	longShow := func(i, n int) string {
		var b strings.Builder
		b.WriteString("show interfaces")
		for k := 0; b.Len() < n; k++ {
			fmt.Fprintf(&b, " Ethernet%d/%d", i+1, k%48+1)
		}
		return strings.TrimRight(b.String()[:n], " ")
	}
	cfg := func(i int) string {
		if i%2 == 0 {
			return fmt.Sprintf("interface Ethernet%d/%d", i/96+1, (i/2)%48+1)
		}
		return fmt.Sprintf("   description uplink to dc-leaf-%04d port %d", i, i%48+1)
	}
	target := func(i int) string {
		if i < len(known) {
			return known[i]
		}
		return fmt.Sprintf("lab-dev-%05d", i)
	}
	// longTarget is an unknown hostname of about n bytes, in labels of at
	// most 63 bytes, the last one not numeric. None is in the inventory:
	// its names are too short to fill the argument cap at 256 targets.
	longTarget := func(i, n int) string {
		s := fmt.Sprintf("lab-dev-%05d", i)
		for n-len(s) >= 2 {
			s += "." + strings.Repeat("x", min(63, n-len(s)-1))
		}
		return s
	}
	all := make([]any, len(known))
	for i, n := range known {
		all[i] = n
	}
	specs := []struct {
		name, server, tool string
		base               map[string]any
		key                string
		lines              bool // one newline-joined string, not a list
		item               func(int) string
		count, width       int                   // a list of exactly count items of up to width bytes
		long               func(i, n int) string // item i of about n bytes, when count is set
		effect, rule       string
	}{
		{WorstShowCommands, eos, "run_commands", map[string]any{"hostname": "lab-sw-01"}, "commands", false, nil, CommandCap, CommandWidth, longShow, "allow", "reads-anywhere"},
		{WorstOneCommand, upa, "send_command_and_get_output", map[string]any{"name": "lab-sw-01"}, "command", true, show, 0, 0, nil, "deny", "no-exec"},
		{WorstConfigString, upa, "set_config_commands_and_commit_or_save", map[string]any{"name": "core-rtr-01"}, "commands", true, cfg, 0, 0, nil, "hold", "prod-core-needs-approval"},
		{WorstConfigLines, eos, "push_config", map[string]any{"hostname": "lab-sw-01"}, "config_lines", false, cfg, 0, 0, nil, "allow", "lab-writes-free"},
		{WorstManyTargets, eos, "daily_brief", map[string]any{}, "hostnames", false, nil, TargetCap, TargetWidth, longTarget, "deny", "default:unknown_target"},
		{WorstBatch, eos, "run_commands_batch", map[string]any{"hostnames": all}, "commands", false, nil, CommandCap, CommandWidth, longShow, "deny", "default:session.max_devices"},
		{WorstTooManyCommands, eos, "run_commands", map[string]any{"hostname": "lab-sw-01"}, "commands", false, show, 0, 0, nil, "deny", "default:bad_arguments"},
		{WorstTooManyTargets, eos, "daily_brief", map[string]any{}, "hostnames", false, target, 0, 0, nil, "deny", "default:bad_arguments"},
	}
	out := make([]Case, 0, len(specs))
	for _, s := range specs {
		var v any
		switch {
		case s.count > 0:
			v = fillN(s.base, s.key, s.count, s.width, s.long)
		case s.lines:
			v = fillString(s.base, s.key, s.item)
		default:
			v = fillList(s.base, s.key, s.item)
		}
		args := mustJSON(withKey(s.base, s.key, v))
		if n := len(args); n > MaxArgs || n < MaxArgs-1024 {
			return nil, fmt.Errorf("%s: arguments are %d bytes, want within 1 KiB under %d", s.name, n, MaxArgs)
		}
		out = append(out, Case{Name: s.name, Server: s.server, Tool: s.tool, Args: args, Effect: s.effect, Rule: s.rule, Worst: true})
	}
	return out, nil
}

// fillN returns count items long(i, n), with n as large as keeps the JSON
// of the arguments at or under MaxArgs, and at most width.
func fillN(base map[string]any, key string, count, width int, long func(i, n int) string) []any {
	size := len(mustJSON(withKey(base, key, []any{})))
	// Each item adds its quotes and a comma (one fewer comma in all).
	n := min(width, (MaxArgs-size+1)/count-3)
	out := make([]any, count)
	for i := range out {
		out[i] = long(i, n)
	}
	return out
}

// fillList returns the longest list item(0), item(1), ... that keeps the
// JSON of the arguments (base plus key set to the list) at or under MaxArgs.
func fillList(base map[string]any, key string, item func(int) string) []any {
	size := len(mustJSON(withKey(base, key, []any{})))
	var out []any
	for i := 0; ; i++ {
		add := len(mustJSON(item(i)))
		if len(out) > 0 {
			add++ // the comma
		}
		if size+add > MaxArgs {
			return out
		}
		size += add
		out = append(out, item(i))
	}
}

// fillString returns the longest newline-joined item(0), item(1), ... that
// keeps the JSON of the arguments at or under MaxArgs.
func fillString(base map[string]any, key string, item func(int) string) string {
	size := len(mustJSON(withKey(base, key, "")))
	var b strings.Builder
	for i := 0; ; i++ {
		line := item(i)
		if i > 0 {
			line = "\n" + line
		}
		add := len(mustJSON(line)) - 2 // the quotes are already counted
		if size+add > MaxArgs {
			return b.String()
		}
		size += add
		b.WriteString(line)
	}
}

func withKey(base map[string]any, key string, v any) map[string]any {
	m := make(map[string]any, len(base)+1)
	for k, x := range base {
		m[k] = x
	}
	m[key] = v
	return m
}

// Rounds returns the measured and warm-up passes: over the typical corpus
// (each pass is one call of every case), and per worst case. With 200
// samples the nearest-rank p99 is the third-largest. -short and -race run
// fewer: a worst case's p99 of 10 samples is its maximum. Under -race the
// tests time no worst case at all (TimeWorst), since a worst case costs
// 100 to 200 ms a call there.
func Rounds() (typicalRounds, worstRounds, warm int) {
	if testing.Short() || RaceEnabled {
		return 100, 10, 2
	}
	return 2000, 200, 50
}

// TimeWorst reports whether the tests time the worst cases: not under
// -race, where they check each worst case's verdict once and move on.
func TimeWorst() bool { return !RaceEnabled }

// Time runs fn warm times untimed, collects garbage, then runs it n times
// and returns each run's wall time.
func Time(n, warm int, fn func()) []time.Duration {
	for range warm {
		fn()
	}
	runtime.GC()
	out := make([]time.Duration, n)
	for i := range out {
		start := time.Now()
		fn()
		out[i] = time.Since(start)
	}
	return out
}

// Quantile returns the nearest-rank q-quantile of samples (sorted in place).
func Quantile(samples []time.Duration, q float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	slices.Sort(samples)
	i := int(float64(len(samples))*q+0.999999) - 1
	return samples[min(max(i, 0), len(samples)-1)]
}

// ClockStep returns the smallest non-zero step of time.Now seen over a short
// spin. On Windows the monotonic clock advances in steps of about 0.5 ms,
// so every sample there is quantised to it and p50 of a microsecond call
// reads 0s; the p99 of a call near the budget is then within one step of
// the truth.
func ClockStep() time.Duration {
	best := time.Duration(1 << 62)
	for range 20 {
		a := time.Now()
		b := a
		for b.Sub(a) == 0 {
			b = time.Now()
		}
		best = min(best, b.Sub(a))
	}
	return best
}

// summary logs p50, p99 and max of samples and returns p50 and p99.
func summary(t testing.TB, what, name string, samples []time.Duration) (p50, p99 time.Duration) {
	t.Helper()
	p50, p99 = Quantile(samples, 0.50), Quantile(samples, 0.99)
	t.Logf("%s: %s: n=%d p50 %v p99 %v max %v", what, name, len(samples), p50, p99, samples[len(samples)-1])
	return p50, p99
}

// CheckTypical checks the PRD metric: it fails t when the p99 of samples
// is over Limit, strict or not.
func CheckTypical(t testing.TB, what, name string, samples []time.Duration) {
	t.Helper()
	if _, p99 := summary(t, what, name, samples); p99 > Limit() {
		t.Errorf("%s: %s: p99 %v over the budget %v", what, name, p99, Limit())
	}
}

// CheckWorst logs one worst case's p50, p99 and max, and a p99 over Limit
// as OVER BUDGET AT p99 (see the package doc for why p99 is reported, not
// enforced, for a worst case). When Strict is true it fails t if the p50 is
// over Limit and the case is not known (KnownOverBudget), or if the case is
// known and its p50 is back under Limit; otherwise it only logs those.
func CheckWorst(t testing.TB, what, name string, samples []time.Duration) {
	t.Helper()
	p50, p99 := summary(t, what, name, samples)
	if p99 > Limit() {
		t.Logf("%s: %s: OVER BUDGET AT p99: %v > %v", what, name, p99, Limit())
	}
	finding, known := KnownOverBudget(what, name)
	report := t.Logf
	if Strict() {
		report = t.Errorf
	}
	switch {
	case p50 > Limit() && known:
		t.Logf("%s: %s: KNOWN OVER BUDGET: p50 %v > %v (%s)", what, name, p50, Limit(), finding)
	case p50 > Limit():
		report("%s: %s: p50 %v over the budget %v (enforced with %s=1)", what, name, p50, Limit(), StrictEnv)
	case known:
		report("%s: %s: p50 %v now under budget %v; remove it from KnownOverBudget (enforced with %s=1)", what, name, p50, Limit(), StrictEnv)
	}
}

// Header logs what the numbers were measured on.
func Header(t testing.TB, what string) {
	t.Helper()
	t.Logf("%s: %s/%s, %s, race=%v, strict=%v, GOMAXPROCS=%d, clock step %v; budget p99 <= %v",
		what, runtime.GOOS, runtime.GOARCH, runtime.Version(), RaceEnabled, Strict(), runtime.GOMAXPROCS(0), ClockStep(), Limit())
}
