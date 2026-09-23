// Command netguard is the NetGuard CLI and (from M0 onward) the proxy itself.
//
// Subcommands:
//
//	netguard version
//	netguard serve                                   M0: not implemented yet
//	netguard policy test <file.test.yaml>...
//	netguard policy eval --policy p.yaml [--inventory inv.yaml] --server S --tool T --class C --target D...
//	netguard audit verify <audit.jsonl> [--key audit.pub]
//	netguard audit keygen --out audit.key [--pub audit.pub]
//	netguard redact --key-file k [file]
//	netguard inventory import --csv devices.csv --out inventory.yaml
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
		fmt.Printf("netguard %s (commit %s, built %s)\n", version, commit, date)
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
		fmt.Fprintf(os.Stderr, "netguard: unknown command %q\n\n", args[0])
		usage()
		return exitUsage
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `netguard: a policy-enforcing MCP proxy for network-device MCP servers

Usage:
  netguard version
  netguard serve
  netguard policy test <file.test.yaml>...
  netguard policy eval --policy p.yaml [--inventory inv.yaml] --server S --tool T --class C --target D [--target D2] [--json]
  netguard policy eval --policy p.yaml --profile profiles/S.yaml --tool T --arg k=v [--arg k=v] ...
  netguard audit verify <audit.jsonl> [--key audit.pub] [--json]
  netguard audit keygen --out audit.key [--pub audit.pub]
  netguard redact --key-file <file> [input-file]
  netguard inventory import --csv devices.csv --out inventory.yaml

Run "netguard <command> -h" for flags.
`)
}

// fail prints an error in the CLI's voice and returns the usage exit code.
func fail(err error) int {
	fmt.Fprintf(os.Stderr, "netguard: %v\n", err)
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
