// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/gate"
	"github.com/fathomgate/fathomgate/internal/inventory"
	"github.com/fathomgate/fathomgate/internal/policy"
	"github.com/fathomgate/fathomgate/profiles"
)

// pipelineFlags are the serve flags that configure the M1 pipeline (ADR
// 0027): exactly one of policy and noPolicy; inventory and profiles only
// with policy.
type pipelineFlags struct {
	policy, inventory, profiles string
	noPolicy                    bool
}

// check enforces the combinations of ADR 0027. Messages name flags only;
// the paths are not secret, but none is needed to fix the command line.
func (pf pipelineFlags) check() error {
	var extra []string
	if pf.inventory != "" {
		extra = append(extra, "--inventory")
	}
	if pf.profiles != "" {
		extra = append(extra, "--profiles")
	}
	switch {
	case pf.policy != "" && pf.noPolicy:
		return errors.New("--policy and --no-policy cannot be used together: --policy decides every call, --no-policy forwards every call unchecked")
	case pf.noPolicy && len(extra) > 0:
		return fmt.Errorf("%s only configure a policy; --no-policy forwards every call unchecked, so leave them out or use --policy <file>", strings.Join(extra, " and "))
	case pf.noPolicy:
		return nil
	case pf.policy == "" && len(extra) > 0:
		return fmt.Errorf("%s only work with --policy <file>", strings.Join(extra, " and "))
	case pf.policy == "":
		return errors.New("--policy <file> or --no-policy is required: --policy decides every call before it reaches the upstream; --no-policy forwards every call unchecked, as v0.1.0 did")
	}
	return nil
}

// pipeline is what loadPipeline built: the gate for proxy.Options.Gate
// (nil with --no-policy), the attributes the start-up line carries, and
// the Warn lines serve logs before it starts the upstream.
type pipeline struct {
	gate  *gate.Gate
	attrs []any
	warns []warnLine
}

// warnLine is one start-up Warn line.
type warnLine struct {
	msg   string
	attrs []any
}

// noPolicyValue is the start-up line's policy attribute with --no-policy.
const noPolicyValue = "none (--no-policy: every call is forwarded)"

// unknownTargetAllowWarning is policy-lint's warning for an explicit
// `unknown_target: allow` (ADR 0032 point 7), word for word, so an
// operator who sees it in both places knows it is the same finding.
const unknownTargetAllowWarning = "unknown_target: allow lets the rules decide for hosts no inventory resolves; " +
	"upstreams such as eos-mcp and netdev-ssh-mcp then send device credentials " +
	"to any host the agent names (ADR 0032)"

// obligationOrder is the vocabulary's order, used to list a policy's
// obligations in the start-up warnings.
var obligationOrder = []string{"dry_run", "diff", "timed_rollback", "redact", "canary_first", "require_ticket", "notify"}

// carriedUntil names the milestone that enforces each obligation M1
// carries on a forwarded call without enforcing it (ADR 0026 decision 1).
var carriedUntil = map[string]string{"redact": "M2", "canary_first": "M4", "require_ticket": "M4", "notify": "M4"}

// loadPipeline loads and checks everything the flags name, before anything
// is bound or spawned (ADR 0027). Any error is a usage error: serve exits 2
// and starts no upstream. server is the --server name, to say whether it
// has a profile.
func loadPipeline(pf pipelineFlags, server string) (*pipeline, error) {
	if pf.noPolicy {
		return &pipeline{
			attrs: []any{"policy", noPolicyValue},
			warns: []warnLine{{msg: "--no-policy: every call is forwarded to the upstream unchecked; nothing is classified, decided or logged as a decision"}},
		}, nil
	}
	pol, err := policy.Load(pf.policy)
	if err != nil {
		return nil, fmt.Errorf("--policy: %w", err)
	}
	pl := &pipeline{attrs: []any{"policy", pf.policy, "rules", len(pol.Rules)}}

	var resolver inventory.Resolver
	if pf.inventory == "" {
		pl.attrs = append(pl.attrs, "inventory", "none (every target is unknown)")
	} else {
		if strings.EqualFold(filepath.Ext(pf.inventory), ".csv") {
			return nil, errors.New("--inventory takes an inventory.yaml; convert a CSV first with fathomgate inventory import --csv <file> --out inventory.yaml")
		}
		f, err := inventory.LoadFile(pf.inventory)
		if err != nil {
			return nil, fmt.Errorf("--inventory: %w", err)
		}
		chain, err := f.Chain()
		if err != nil {
			return nil, fmt.Errorf("--inventory: %s: %w", pf.inventory, err)
		}
		resolver = chain
		pl.attrs = append(pl.attrs, "inventory", pf.inventory, "devices", len(f.Devices))
		for _, w := range f.PatternWarnings() {
			pl.warns = append(pl.warns, warnLine{msg: w, attrs: []any{"inventory", pf.inventory}})
		}
	}

	var set []profileFile
	source := "embedded"
	if pf.profiles == "" {
		set, err = embeddedProfiles()
		if err != nil {
			return nil, fmt.Errorf("embedded profiles: %w", err)
		}
	} else {
		source = pf.profiles
		set, err = loadProfileDir(pf.profiles)
		if err != nil {
			return nil, fmt.Errorf("--profiles: %w", err)
		}
	}
	byServer := make(map[string]*classify.Profile, len(set))
	for _, p := range set {
		byServer[p.profile.Server] = p.profile
	}
	_, hasProfile := byServer[server]
	pl.attrs = append(pl.attrs, "profiles", source, "profile", profileAttr(set, server))
	if !hasProfile {
		pl.warns = append(pl.warns, warnLine{
			msg:   "no profile for this server: its calls take the fallback classifier, and their arguments are not checked",
			attrs: []any{"server", server, "profiles", source},
		})
	}

	g, err := gate.New(gate.Config{Policy: pol, Profiles: byServer, Inventory: resolver})
	if err != nil {
		return nil, err
	}
	pl.gate = g
	pl.warns = append(pl.warns, policyWarnings(pol, pf.policy)...)
	return pl, nil
}

// profileAttr is the start-up line's profile attribute: the file that
// classifies server's tools, or "none (fallback classifier)".
func profileAttr(set []profileFile, server string) string {
	for _, p := range set {
		if p.profile.Server == server {
			return p.name
		}
	}
	return "none (fallback classifier)"
}

// policyWarnings are the start-up Warn lines a loaded policy earns: an
// explicit unknown_target: allow (ADR 0032 point 7), each obligation M1
// does not enforce with the rules that use it (ADR 0027), and the rules
// whose hold is not run before approvals exist (ADR 0026 decision 3).
// Policy.Parse fills an unset unknown_target in as deny, so allow here was
// written by the operator.
func policyWarnings(pol *policy.Policy, file string) []warnLine {
	var out []warnLine
	if pol.Defaults.UnknownTarget == policy.Allow {
		out = append(out, warnLine{msg: unknownTargetAllowWarning, attrs: []any{"policy", file}})
	}
	rulesUsing := map[string][]string{}
	var holds []string
	for _, r := range pol.Rules {
		if r.Effect == policy.Hold {
			holds = append(holds, r.ID)
		}
		if r.Effect != policy.Allow {
			// A hold is not run at all in M1, and a deny never runs, so
			// their obligations change nothing yet.
			continue
		}
		for _, o := range r.Obligations {
			if !slices.Contains(rulesUsing[o], r.ID) {
				rulesUsing[o] = append(rulesUsing[o], r.ID)
			}
		}
	}
	for _, o := range obligationOrder {
		rules := rulesUsing[o]
		if len(rules) == 0 {
			continue
		}
		if until, ok := carriedUntil[o]; ok {
			out = append(out, warnLine{
				msg:   "obligation not enforced yet: a call these rules allow is forwarded without it",
				attrs: []any{"obligation", o, "rules", strings.Join(rules, ","), "enforced_from", until},
			})
			continue
		}
		out = append(out, warnLine{
			msg:   "obligation cannot be met yet: a call these rules allow is not run, and the agent is told why",
			attrs: []any{"obligation", o, "rules", strings.Join(rules, ",")},
		})
	}
	if len(holds) > 0 {
		out = append(out, warnLine{
			msg:   "hold is not run yet: approvals arrive in M3, and until then the agent is told the call needs approval",
			attrs: []any{"rules", strings.Join(holds, ",")},
		})
	}
	return out
}

// logWarnings writes the start-up Warn lines.
func (pl *pipeline) logWarnings(logger *slog.Logger) {
	for _, w := range pl.warns {
		logger.Warn(w.msg, w.attrs...)
	}
}

// profileFile is one parsed profile and where it came from.
type profileFile struct {
	name    string // file name, without a directory
	sum     [sha256.Size]byte
	profile *classify.Profile
}

// embeddedProfiles parses the profiles built into the binary.
func embeddedProfiles() ([]profileFile, error) {
	return loadProfiles(profiles.FS, "")
}

// loadProfileDir parses every *.yaml file in dir, the --profiles set. dir
// must be a directory holding at least one profile: an empty set would
// silently put every server on the fallback classifier.
func loadProfileDir(dir string) ([]profileFile, error) {
	st, err := os.Stat(dir)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err // the operating system's call name is noise here
		}
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	set, err := loadProfiles(os.DirFS(dir), dir)
	if err != nil {
		return nil, err
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("%s holds no *.yaml profile", dir)
	}
	return set, nil
}

// loadProfiles parses every *.yaml file at the top of fsys, in name order,
// as classify.LoadProfileDir does: strict decoding and Validate, and two
// files for one server key are an error. dir prefixes file names in errors.
func loadProfiles(fsys fs.FS, dir string) ([]profileFile, error) {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	out := make([]profileFile, 0, len(names))
	seen := map[string]string{}
	for _, name := range names {
		shown := name
		if dir != "" {
			shown = filepath.Join(dir, name)
		}
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		p, err := classify.ParseProfile(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", shown, err)
		}
		if first, dup := seen[p.Server]; dup {
			return nil, fmt.Errorf("%s and %s both define server %q", first, name, p.Server)
		}
		seen[p.Server] = name
		out = append(out, profileFile{name: name, sum: sha256.Sum256(b), profile: p})
	}
	return out, nil
}

// embeddedProfileLines is what `fathomgate version` prints about the
// embedded profile set (ADR 0027): one line per file with its server key,
// its tool count and the first 12 hex digits of its SHA-256, so an operator
// can tell which profile text a binary classifies with.
func embeddedProfileLines() ([]string, error) {
	set, err := embeddedProfiles()
	if err != nil {
		return nil, err
	}
	width := 0
	for _, p := range set {
		width = max(width, len(p.profile.Server))
	}
	lines := make([]string, 0, len(set))
	for _, p := range set {
		lines = append(lines, fmt.Sprintf("  %-*s  %2d tools  sha256:%s  %s", width, p.profile.Server, len(p.profile.Tools), hex.EncodeToString(p.sum[:6]), p.name))
	}
	return lines, nil
}
