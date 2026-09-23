package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/joshscott13/netguard/internal/proxy"
)

// startupTimeout bounds spawning the upstream, its handshake and tools/list.
const startupTimeout = 30 * time.Second

// reservedServeFlags are accepted by the flag parser but refused in M0: the
// pipeline they configure is not wired into the proxy until M1 (policy,
// inventory, profiles) and M4 (audit). Refusing them keeps an operator from
// believing a policy is enforced when M0 forwards every call.
var reservedServeFlags = []string{"policy", "inventory", "profiles", "audit"}

// cmdServe runs the proxy: an MCP server on stdio toward the agent and an
// MCP client toward one upstream spawned over stdio.
//
//	netguard serve --server <name> --upstream <path> [--upstream-env K=V]... [-- <upstream args>...]
func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	server := fs.String("server", "", "tool prefix `name` for the upstream: the server key of its profile in profiles/ (required)")
	upstream := fs.String("upstream", "", "upstream MCP server executable `path`, spawned over stdio (required); its arguments follow --")
	var env stringList
	fs.Var(&env, "upstream-env", "`KEY=VALUE` added to the upstream's environment (repeatable)")
	for _, name := range reservedServeFlags {
		fs.String(name, "", "not enforced in M0; refused until the pipeline is wired (M1)")
	}
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: netguard serve --server <name> --upstream <path> [--upstream-env K=V]... [-- <upstream args>...]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	var refused []string
	fs.Visit(func(f *flag.Flag) {
		for _, name := range reservedServeFlags {
			if f.Name == name {
				refused = append(refused, "--"+name)
			}
		}
	})
	if len(refused) > 0 {
		return fail(fmt.Errorf("serve: %s not enforced in M0; netguard serve is pass-through only and forwards every call", strings.Join(refused, ", ")))
	}
	if *server == "" || *upstream == "" {
		fs.Usage()
		return fail(errors.New("serve: --server and --upstream are required"))
	}
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); !ok || k == "" {
			return fail(fmt.Errorf("serve: --upstream-env %q is not KEY=VALUE", kv))
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	up := proxy.Upstream{
		Server: *server,
		Transport: proxy.Command{
			Path:   *upstream,
			Args:   fs.Args(),
			Env:    env,
			Stderr: os.Stderr,
		}.Transport(),
	}
	startCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	p, err := proxy.New(startCtx, []proxy.Upstream{up}, proxy.Options{Version: version, Logger: logger})
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "netguard: %v\n", err)
		return exitFail
	}
	logger.Info("serving on stdio; M0 pass-through, no policy enforced", "server", *server, "tools", len(p.Tools()))

	runErr := p.Run(ctx, &mcp.StdioTransport{})
	if err := p.Close(); err != nil {
		logger.Warn("closing upstream", "error", err)
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		fmt.Fprintf(os.Stderr, "netguard: serve: %v\n", runErr)
		return exitFail
	}
	return exitOK
}
