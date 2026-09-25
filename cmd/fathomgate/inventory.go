// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/fathomgate/fathomgate/internal/configfile"
	"github.com/fathomgate/fathomgate/internal/gate"
	"github.com/fathomgate/fathomgate/internal/inventory"
)

const inventoryUsage = `usage:
  fathomgate inventory import --csv devices.csv --out inventory.yaml
  fathomgate inventory lint <inventory.yaml>
  fathomgate inventory resolve [--inventory inventory.yaml] [--json] <name>...`

func cmdInventory(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, inventoryUsage)
		return exitUsage
	}
	switch args[0] {
	case "import":
		return cmdInventoryImport(args[1:])
	case "lint":
		return inventoryLint(args[1:], os.Stdout, os.Stderr)
	case "resolve":
		return inventoryResolve(args[1:], os.Stdout, os.Stderr)
	default:
		fmt.Fprintf(os.Stderr, "fathomgate inventory: unknown subcommand %q\n%s\n", args[0], inventoryUsage)
		return exitUsage
	}
}

// cmdInventoryImport converts a CSV export into inventory.yaml.
func cmdInventoryImport(args []string) int {
	fs := flag.NewFlagSet("inventory import", flag.ContinueOnError)
	csvPath := fs.String("csv", "", "CSV with columns name,role,site,tags,status (required; - for stdin)")
	outPath := fs.String("out", "inventory.yaml", "output path (- for stdout)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *csvPath == "" {
		return fail(fmt.Errorf("--csv is required"))
	}
	var in io.Reader = os.Stdin
	if *csvPath != "-" {
		f, err := os.Open(*csvPath)
		if err != nil {
			return fail(err)
		}
		defer func() { _ = f.Close() }()
		in = f
	}
	targets, err := inventory.ImportCSV(in)
	if err != nil {
		return fail(err)
	}
	if _, err := inventory.NewStatic(targets); err != nil {
		return fail(err)
	}
	var out io.Writer = os.Stdout
	if *outPath != "-" {
		f, err := os.OpenFile(*outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return fail(err)
		}
		defer func() { _ = f.Close() }()
		out = f
	}
	if err := inventory.WriteFile(out, &inventory.File{Devices: targets}); err != nil {
		return fail(err)
	}
	if *outPath != "-" {
		fmt.Fprintf(os.Stderr, "wrote %d devices to %s\n", len(targets), *outPath)
	}
	return exitOK
}

// readInventory reads an inventory file the way fathomgate serve --inventory
// does (security review of PR #184, L4): a CSV is refused with the import
// hint, and the file goes through configfile.Read, with its owner and
// write-permission checks and the same size limit.
func readInventory(path string) ([]byte, error) {
	if strings.EqualFold(filepath.Ext(path), ".csv") {
		return nil, errors.New("takes an inventory.yaml; convert a CSV first with fathomgate inventory import --csv <file> --out inventory.yaml")
	}
	return configfile.Read(path, "the inventory file "+path, maxConfigFile)
}

// inventoryLint checks an inventory file (inventory-schema section 9). It
// fails on anything that stops the file loading; on a hostname pattern that
// matches no listed device (ADR 0031 decision 5), which fathomgate serve only
// warns about; and on a listed device whose name the gate refuses as a
// target, which no call can ever reach. It warns, without failing, for each
// role, site or tag a pattern adds to a listed device, since those count for
// write rules. Exit 0 clean (warnings allowed), 1 with problems, 2 when the
// file cannot be read.
func inventoryLint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inventory lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "usage: fathomgate inventory lint <inventory.yaml>")
		return exitUsage
	}
	path := fs.Arg(0)
	b, err := readInventory(path)
	if err != nil {
		return failTo(stderr, fmt.Errorf("inventory lint: %w", err))
	}
	f, err := inventory.ParseFile(b)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "fathomgate: inventory lint: %s: %v\n", path, err)
		return exitFail
	}
	if _, err := f.Chain(); err != nil {
		_, _ = fmt.Fprintf(stderr, "fathomgate: inventory lint: %s: %v\n", path, err)
		return exitFail
	}
	var problems []string
	for i, d := range f.Devices {
		if !gate.ValidTargetName(d.Name) {
			problems = append(problems, fmt.Sprintf("inventory: devices[%d] %s is not a name the gate accepts as a target (a hostname or IP address), so no call can reach it", i, strconv.QuoteToASCII(d.Name)))
		}
	}
	problems = append(problems, f.PatternWarnings()...)
	for _, w := range f.PatternEffects() {
		_, _ = fmt.Fprintf(stderr, "fathomgate: inventory lint: %s: warning: %s\n", path, w)
	}
	for _, p := range problems {
		_, _ = fmt.Fprintf(stderr, "fathomgate: inventory lint: %s: %s\n", path, p)
	}
	if len(problems) > 0 {
		return exitFail
	}
	_, _ = fmt.Fprintf(stdout, "%s: ok (%d devices, %d patterns)\n", path, len(f.Devices), len(f.Roles))
	return exitOK
}

// resolveResult is one name's answer from fathomgate inventory resolve.
type resolveResult struct {
	Name  string `json:"name"`
	Known bool   `json:"known"`
	// Reason says why a name is unknown.
	Reason string            `json:"reason,omitempty"`
	Target *inventory.Target `json:"target,omitempty"`
	// Patterns lists the roles: patterns an unknown name matches; they
	// never make it known (ADR 0031).
	Patterns []string `json:"patterns_matched,omitempty"`
}

// inventoryResolve prints what the inventory says about each name, and
// which provider supplied each field (ADR 0031 decision 3). A name is known
// exactly as fathomgate serve counts it (inventory.Known: a name authority
// lists it, spelled as sent, inventory-schema section 7). Exit 0 when every
// name is known, 1 when any is unknown, 2 on a usage or load error.
func inventoryResolve(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inventory resolve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	invPath := fs.String("inventory", "inventory.yaml", "inventory.yaml to resolve against")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: fathomgate inventory resolve [--inventory inventory.yaml] [--json] <name>...")
		return exitUsage
	}
	b, err := readInventory(*invPath)
	if err != nil {
		return failTo(stderr, fmt.Errorf("--inventory: %w", err))
	}
	f, err := inventory.ParseFile(b)
	if err != nil {
		return failTo(stderr, fmt.Errorf("--inventory: %s: %w", *invPath, err))
	}
	chain, err := f.Chain()
	if err != nil {
		return failTo(stderr, fmt.Errorf("--inventory: %s: %w", *invPath, err))
	}
	patterns, err := inventory.NewPatterns(f.Roles)
	if err != nil {
		return failTo(stderr, fmt.Errorf("--inventory: %s: %w", *invPath, err))
	}
	results := make([]resolveResult, 0, fs.NArg())
	code := exitOK
	for _, name := range fs.Args() {
		r := resolveResult{Name: name}
		if t, ok := inventory.Known(chain, name); ok {
			r.Known, r.Target = true, &t
		} else if lt, listed := chain.Resolve(name); listed {
			r.Reason = "listed as " + printable(lt.Name) + "; a name is known only spelled exactly as listed (inventory-schema section 7)"
		} else {
			r.Reason = "no name authority lists it"
			for _, i := range patterns.Matching(name) {
				r.Patterns = append(r.Patterns, fmt.Sprintf("roles[%d] %s", i, strconv.QuoteToASCII(f.Roles[i].Match)))
			}
		}
		if !r.Known {
			code = exitFail
		}
		results = append(results, r)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return failTo(stderr, err)
		}
		return code
	}
	for _, r := range results {
		printResolved(stdout, r)
	}
	return code
}

// printable returns s as is when it is plain printable ASCII, and quoted
// with Go escapes otherwise, so a stored or typed value cannot carry a
// terminal escape sequence, a control or bidi character, or a homoglyph that
// reads as another name onto the operator's screen (review of PR #184, N2).
func printable(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return strconv.QuoteToASCII(s)
		}
	}
	return s
}

func printResolved(w io.Writer, r resolveResult) {
	if !r.Known {
		_, _ = fmt.Fprintf(w, "%s: unknown (%s)\n", printable(r.Name), r.Reason)
		for _, p := range r.Patterns {
			_, _ = fmt.Fprintf(w, "  matches %s, which never makes a name known (ADR 0031)\n", p)
		}
		return
	}
	t, src := r.Target, r.Target.Sources
	if src == nil {
		src = &inventory.Sources{}
	}
	stale := ""
	if t.Stale {
		stale = ", stale"
	}
	_, _ = fmt.Fprintf(w, "%s: known (listed by %s%s)\n", printable(r.Name), printable(t.Source), stale)
	row := func(field, value, source string) {
		if value == "" {
			value, source = "-", ""
		}
		line := fmt.Sprintf("  %-7s %-24s %s", field, printable(value), printable(source))
		_, _ = fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
	row("name", t.Name, src.Name)
	row("role", t.Role, src.Role)
	row("site", t.Site, src.Site)
	row("status", t.Status, src.Status)
	if len(t.Tags) == 0 {
		row("tags", "", "")
		return
	}
	tags := append([]string(nil), t.Tags...)
	sort.Strings(tags)
	for i, tag := range tags {
		field := ""
		if i == 0 {
			field = "tags"
		}
		row(field, tag, src.Tags[tag])
	}
}

// failTo prints an error in the CLI's voice to w and returns the usage exit
// code, as fail does for os.Stderr.
func failTo(w io.Writer, err error) int {
	_, _ = fmt.Fprintf(w, "fathomgate: %v\n", err)
	return exitUsage
}
