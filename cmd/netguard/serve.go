package main

import (
	"flag"
	"fmt"
	"os"
)

// cmdServe is the proxy entry point. The transport depends on the official
// MCP go-sdk v1.7, which needs Go 1.25; this tree builds with Go 1.24, so the
// transport is a documented stub until the toolchain moves.
func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.String("policy", "policy.yaml", "policy file")
	fs.String("inventory", "inventory.yaml", "static inventory file")
	fs.String("profiles", "profiles", "directory of upstream server profiles")
	fs.String("audit", "audit.jsonl", "audit log path")
	fs.String("upstream", "", "upstream MCP server command (stdio)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	fmt.Fprintln(os.Stderr, "M0: proxy transport not implemented yet — requires Go 1.25 + go-sdk v1.7; see ROADMAP.md")
	return exitUsage
}
