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
	"github.com/fathomgate/fathomgate/internal/configfile"
	"github.com/fathomgate/fathomgate/internal/gate"
	"github.com/fathomgate/fathomgate/internal/inventory"
	"github.com/fathomgate/fathomgate/internal/policy"
	"github.com/fathomgate/fathomgate/profiles"
)

// maxConfigFile caps the policy, the inventory and each profile file.
const maxConfigFile = 16 << 20

// pipelineFlags are the serve flags that configure the M1 pipeline (ADR
// 0027): exactly one of policy and noPolicy; inventory and profiles only
// with policy.
type pipelineFlags struct {
	policy, inventory, profiles string
	noPolicy                    bool
}

// onceFlag is a string flag that may be given once. A second occurrence
// is a usage error rather than the flag package's last-one-wins, so
// `--policy a.yaml ... --policy b.yaml` never enforces a file the operator
// did not mean (security review of PR #171, L1).
type onceFlag struct {
	value    *string
	repeated bool
}

func (o *onceFlag) String() string {
	if o == nil || o.value == nil {
		return ""
	}
	return *o.value
}

func (o *onceFlag) Set(s string) error {
	if o.set() {
		o.repeated = true
		return errors.New("given more than once")
	}
	*o.value = s
	return nil
}

// set reports whether the flag already has a value. An explicit empty
// value counts as unset, as the combination checks treat it.
func (o *onceFlag) set() bool { return *o.value != "" }

// check enforces the combinations of ADR 0027. Messages name flags only.
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
		return fmt.Errorf("%s: only with --policy <file>; --no-policy forwards every call unchecked, so leave them out or use --policy <file> instead of --no-policy", strings.Join(extra, " and "))
	case pf.noPolicy:
		return nil
	case pf.policy == "" && len(extra) > 0:
		return fmt.Errorf("%s: only with --policy <file>", strings.Join(extra, " and "))
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

// Start-up texts (ADR 0027 and its notes; profile-schema 8.3).
const (
	noPolicyValue   = "none (--no-policy: every call is forwarded)"
	noPolicyWarning = "--no-policy: every call is forwarded to the upstream unchecked; nothing is classified, decided or logged as a decision; use --policy <file> in front of real devices"
	// unknownTargetAllowLint is policy-lint's warning for an explicit
	// `unknown_target: allow` (ADR 0032 point 7), word for word, so an
	// operator who sees it in both places knows it is the same finding;
	// serve adds what to do.
	unknownTargetAllowLint = "unknown_target: allow lets the rules decide for hosts no inventory resolves; " +
		"upstreams such as eos-mcp and netdev-ssh-mcp then send device credentials " +
		"to any host the agent names (ADR 0032)"
	unknownTargetAllowWarning = unknownTargetAllowLint + "; set unknown_target: deny and list the hosts in --inventory"
	noInventoryValue          = "none (every target is unknown)"
	noInventoryWarning        = "no --inventory: every target is unknown, so this policy denies every call that names a device (rule default:unknown_target); add --inventory <file>"
	noProfileValue            = "none (every call with arguments is denied)"
	noProfileWarning          = "no profile for this server: every call that carries arguments is denied (rule default:bad_arguments); use a --server key that fathomgate version lists, or add a profile with --profiles <dir>"
	cannotMeetWarning         = "obligation cannot be met until M3: a call these rules allow cannot run, and the agent is told why; remove the obligation from these rules to run such calls now"
	carriedWarning            = "obligation not enforced yet: a call these rules allow is forwarded without it"
	holdWarning               = `calls these rules hold are not run yet: approvals arrive in M3; until then the agent gets "fathomgate held …: needs approval"`
)

// carriedUntil names the milestone that enforces each obligation M1
// carries on a forwarded call without enforcing it (ADR 0026 decision 1;
// internal/gate forwardable). cannotMeet are the obligations whose allow
// is not run in M1. Every policy.KnownObligations entry is in exactly one
// (TestObligationsPartitioned).
var (
	carriedUntil = map[string]string{"redact": "M2", "canary_first": "M4", "require_ticket": "M4", "notify": "M4"}
	cannotMeet   = []string{"dry_run", "diff", "timed_rollback"}
)

// loadPipeline loads and checks everything the flags name, before anything
// is bound or spawned (ADR 0027). Any error is a usage error: serve exits 2
// and starts no upstream. server is the --server name.
func loadPipeline(pf pipelineFlags, server string) (*pipeline, error) {
	if pf.noPolicy {
		return &pipeline{
			attrs: []any{"policy", noPolicyValue},
			warns: []warnLine{{msg: noPolicyWarning}},
		}, nil
	}
	b, err := configfile.Read(pf.policy, "the policy file "+pf.policy, maxConfigFile)
	if err != nil {
		return nil, fmt.Errorf("--policy: %w", err)
	}
	pol, err := policy.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("--policy: %s: %w", pf.policy, err)
	}
	pl := &pipeline{attrs: []any{"policy", pf.policy, "rules", len(pol.Rules)}}

	var resolver inventory.Resolver
	if pf.inventory == "" {
		pl.attrs = append(pl.attrs, "inventory", noInventoryValue)
		if pol.Defaults.UnknownTarget != policy.Allow {
			pl.warns = append(pl.warns, warnLine{msg: noInventoryWarning, attrs: []any{"policy", pf.policy}})
		}
	} else {
		if strings.EqualFold(filepath.Ext(pf.inventory), ".csv") {
			return nil, errors.New("--inventory takes an inventory.yaml; convert a CSV first with fathomgate inventory import --csv <file> --out inventory.yaml")
		}
		b, err := configfile.Read(pf.inventory, "the inventory file "+pf.inventory, maxConfigFile)
		if err != nil {
			return nil, fmt.Errorf("--inventory: %w", err)
		}
		f, err := inventory.ParseFile(b)
		if err != nil {
			return nil, fmt.Errorf("--inventory: %s: %w", pf.inventory, err)
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
	byServer := make(map[string]*classify.Profile, len(set)+1)
	keys := make([]string, 0, len(set))
	for _, p := range set {
		byServer[p.profile.Server] = p.profile
		keys = append(keys, p.profile.Server)
	}
	if _, ok := byServer[server]; ok {
		pl.attrs = append(pl.attrs, "profiles", source, "profile", server+".yaml")
	} else {
		// A server with no profile gets an empty one, so every tool is a
		// tool the profile does not list: a call that carries any argument
		// is default:bad_arguments, and one without is EXEC_ARBITRARY for
		// the rules (ADR 0027 note of 2026-09-25, fail closed as ADR 0032
		// and ADR 0033 do). Without this, the fallback classifier would
		// find no target and skip the unknown-target default.
		byServer[server] = &classify.Profile{Server: server, Tools: map[string]classify.ToolSpec{}}
		pl.attrs = append(pl.attrs, "profiles", source, "profile", noProfileValue)
		pl.warns = append(pl.warns, warnLine{
			msg:   noProfileWarning,
			attrs: []any{"server", server, "profiles", source, "servers_with_a_profile", strings.Join(keys, ",")},
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

// policyWarnings are the start-up Warn lines a loaded policy earns: an
// explicit unknown_target: allow (ADR 0032 point 7), each obligation on an
// allow rule that M1 does not enforce or cannot meet, with the rules that
// use it (ADR 0027), and the hold rules, which are not run before
// approvals exist (ADR 0026 decision 3). Policy.Parse fills an unset
// unknown_target in as deny, so allow here was written by the operator.
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
	for _, o := range policy.KnownObligations {
		rules := rulesUsing[o]
		if len(rules) == 0 {
			continue
		}
		if until, ok := carriedUntil[o]; ok {
			out = append(out, warnLine{
				msg:   carriedWarning,
				attrs: []any{"obligation", o, "rules", strings.Join(rules, ","), "enforced_from", until},
			})
			continue
		}
		out = append(out, warnLine{msg: cannotMeetWarning, attrs: []any{"obligation", o, "rules", strings.Join(rules, ",")}})
	}
	if len(holds) > 0 {
		out = append(out, warnLine{msg: holdWarning, attrs: []any{"rules", strings.Join(holds, ",")}})
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
	name    string // file name, without a directory: <server>.yaml
	sum     [sha256.Size]byte
	profile *classify.Profile
}

// embeddedProfiles parses the profiles built into the binary.
func embeddedProfiles() ([]profileFile, error) {
	fsys := profiles.FS()
	return loadProfiles(fsys, "", func(name string) ([]byte, error) { return fs.ReadFile(fsys, name) })
}

// loadProfileDir parses the --profiles set: every *.yaml file at the top
// of dir. The directory and every profile file pass the configfile
// integrity checks. A subdirectory or a *.yml file is refused rather than
// skipped (it would look loaded), and a directory with no profile is an
// error: an empty set would deny every call that carries arguments.
func loadProfileDir(dir string) ([]profileFile, error) {
	if err := configfile.CheckDir(dir, "the profiles directory "+dir); err != nil {
		return nil, err
	}
	set, err := loadProfiles(os.DirFS(dir), dir, func(name string) ([]byte, error) {
		p := filepath.Join(dir, name)
		return configfile.Read(p, "the profile "+p, maxConfigFile)
	})
	if err != nil {
		return nil, err
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("%s holds no *.yaml profile", dir)
	}
	return set, nil
}

// loadProfiles parses every *.yaml file at the top of fsys, in name order:
// strict decoding and Validate (classify.ParseProfile). Each file must be
// named after its server key (<server>.yaml), so the file that classified
// a tool is never in doubt. dir prefixes file names in errors; read reads
// one file by name.
func loadProfiles(fsys fs.FS, dir string, read func(name string) ([]byte, error)) ([]profileFile, error) {
	shown := func(name string) string {
		if dir == "" {
			return name
		}
		return filepath.Join(dir, name)
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", shown("."), err)
	}
	out := make([]profileFile, 0, len(entries))
	seen := map[string]string{}
	for _, e := range entries { // ReadDir sorts by name
		name := e.Name()
		switch {
		case e.IsDir():
			return nil, fmt.Errorf("%s is a directory; profiles are read from the top level only, so move it out", shown(name))
		case strings.HasSuffix(name, ".yml"):
			return nil, fmt.Errorf("%s: profiles are named <server>.yaml; rename it", shown(name))
		case !strings.HasSuffix(name, ".yaml"):
			continue // LICENSE, README and the like
		}
		b, err := read(name)
		if err != nil {
			return nil, err
		}
		p, err := classify.ParseProfile(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", shown(name), err)
		}
		if want := p.Server + ".yaml"; name != want {
			return nil, fmt.Errorf("%s defines server %q; a profile file is named after its server key, %s", shown(name), p.Server, want)
		}
		if first, dup := seen[p.Server]; dup {
			return nil, fmt.Errorf("%s and %s both define server %q", shown(first), shown(name), p.Server)
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
		tools := "tools"
		if len(p.profile.Tools) == 1 {
			tools = "tool "
		}
		lines = append(lines, fmt.Sprintf("  %-*s  %2d %s  sha256:%s  %s", width, p.profile.Server, len(p.profile.Tools), tools, hex.EncodeToString(p.sum[:6]), p.name))
	}
	return lines, nil
}
