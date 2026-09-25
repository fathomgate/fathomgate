// SPDX-License-Identifier: Apache-2.0

// Command fathomgate is the Fathomgate CLI and (from M0 onward) the proxy itself.
//
// Subcommands:
//
//	fathomgate version
//	fathomgate serve --server S --upstream PATH [--upstream-env K=V]... [--upstream-env-pass NAME]... [-- ARGS...]
//	fathomgate serve --server S --upstream PATH --listen ADDR:PORT (--listen-token-file NAME=PATH... | env FATHOMGATE_LISTEN_TOKEN) [-- ARGS...]
//	fathomgate policy test <file.test.yaml>...
//	fathomgate policy eval --policy p.yaml [--inventory inv.yaml] --server S --tool T --class C --target D...
//	fathomgate audit verify <audit.jsonl> [--key audit.pub]
//	fathomgate audit keygen --out audit.key [--pub audit.pub]
//	fathomgate redact --key-file k [file]
//	fathomgate inventory import --csv devices.csv --out inventory.yaml
//
// Exit codes: 0 success (or allow), 1 failure (or deny, or a failing test),
// 2 usage or internal error, 3 hold.
package main

import (
	"flag"
	"fmt"
	"os"
)

// Build information, set by GoReleaser through -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
	exitHold  = 3
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Printf("fathomgate %s (commit %s, built %s)\n", version, commit, date)
		return exitOK
	case "serve":
		return cmdServe(args[1:])
	case "policy":
		return cmdPolicy(args[1:])
	case "audit":
		return cmdAudit(args[1:])
	case "redact":
		return cmdRedact(args[1:])
	case "inventory":
		return cmdInventory(args[1:])
	case "help", "-h", "--help":
		usage()
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "fathomgate: unknown command %q\n\n", args[0])
		usage()
		return exitUsage
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `fathomgate: a policy-enforcing MCP proxy for network-device MCP servers

Usage:
  fathomgate version
  fathomgate serve --server S --upstream PATH [--upstream-env K=V]... [--upstream-env-pass NAME]... [-- upstream args...]
  fathomgate serve --server S --upstream PATH --listen 127.0.0.1:PORT --listen-token-file NAME=PATH [-- upstream args...]
  fathomgate policy test <file.test.yaml>...
  fathomgate policy eval --policy p.yaml [--inventory inv.yaml] --server S --tool T --class C --target D [--target D2] [--json]
  fathomgate policy eval --policy p.yaml --profile profiles/S.yaml --tool T --arg k=v [--arg k=v] ...
  fathomgate audit verify <audit.jsonl> [--key audit.pub] [--json]
  fathomgate audit keygen --out audit.key [--pub audit.pub]
  fathomgate redact --key-file <file> [input-file]
  fathomgate inventory import --csv devices.csv --out inventory.yaml

Run "fathomgate <command> -h" for flags.
`)
}

// fail prints an error in the CLI's voice and returns the usage exit code.
func fail(err error) int {
	fmt.Fprintf(os.Stderr, "fathomgate: %v\n", err)
	return exitUsage
}

// stringList is a repeatable string flag.
type stringList []string

// String implements flag.Value.
func (s *stringList) String() string { return fmt.Sprint([]string(*s)) }

// Set implements flag.Value.
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// parseInterspersed parses flags that may appear before or after positional
// arguments, which the standard flag package does not do on its own. It
// returns the positional arguments in order.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}
