package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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

// reservedServeFlags are refused in M0: the pipeline they configure is not
// wired into the proxy until M1 (policy, inventory, profiles) and M4
// (audit). Refusing them keeps an operator from believing a policy is
// enforced when M0 forwards every call.
var reservedServeFlags = []string{"policy", "inventory", "profiles", "audit"}

const serveUsage = "Usage: netguard serve --server <name> --upstream <path> [--upstream-env K=V]... [-- <upstream args>...]"

// serveConfig is the parsed `netguard serve` command line.
type serveConfig struct {
	server       string
	upstream     string
	upstreamArgs []string
	upstreamEnv  []string
}

// parseServe parses the serve flags. Upstream arguments are accepted only
// after "--": the flag package stops at the first positional argument, so
// without that rule `--upstream x extra --policy p.yaml` would slip a
// reserved flag past the check. Leftover arguments are scanned for reserved
// flag names whether or not "--" came first.
func parseServe(args []string, usageOut io.Writer) (serveConfig, error) {
	var cfg serveConfig
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(usageOut)
	fs.StringVar(&cfg.server, "server", "", "tool prefix `name` for the upstream: the server key of its profile in profiles/ (required)")
	fs.StringVar(&cfg.upstream, "upstream", "", "upstream MCP server executable `path`, spawned over stdio (required); its arguments follow --")
	var env stringList
	fs.Var(&env, "upstream-env", "`KEY=VALUE` added to the upstream's environment (repeatable)")
	for _, name := range reservedServeFlags {
		fs.String(name, "", "not enforced in M0; refused until the pipeline is wired (M1)")
	}
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), serveUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	var refused []string
	fs.Visit(func(f *flag.Flag) {
		if isReservedServeFlag(f.Name) {
			refused = append(refused, "--"+f.Name)
		}
	})
	rest := fs.Args()
	for _, a := range rest {
		if name, ok := flagName(a); ok && isReservedServeFlag(name) {
			refused = append(refused, a)
		}
	}
	if len(refused) > 0 {
		return cfg, fmt.Errorf("%s not enforced in M0; netguard serve is pass-through only and forwards every call", strings.Join(refused, ", "))
	}
	consumed := len(args) - len(rest)
	sawDashDash := consumed > 0 && args[consumed-1] == "--"
	if len(rest) > 0 && !sawDashDash {
		return cfg, fmt.Errorf("unexpected argument %q; arguments for the upstream go after --", rest[0])
	}
	if cfg.server == "" || cfg.upstream == "" {
		return cfg, errors.New("--server and --upstream are required")
	}
	if cfg.upstream == "--" || strings.TrimSpace(cfg.upstream) == "" {
		return cfg, fmt.Errorf("--upstream %q is not an executable path", cfg.upstream)
	}
	if err := proxy.ValidateServerName(cfg.server); err != nil {
		return cfg, fmt.Errorf("--server: %w", err)
	}
	for _, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || !validEnvName(k) {
			return cfg, fmt.Errorf("--upstream-env %q is not KEY=VALUE with KEY matching [A-Za-z_][A-Za-z0-9_]*", kv)
		}
	}
	cfg.upstreamArgs = rest
	cfg.upstreamEnv = env
	return cfg, nil
}

// validEnvName reports whether k matches [A-Za-z_][A-Za-z0-9_]*.
func validEnvName(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		letter := c == '_' || ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z')
		if !letter && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// flagName returns the name in "-name", "--name" or "--name=value".
func flagName(a string) (string, bool) {
	if len(a) < 2 || a[0] != '-' {
		return "", false
	}
	name := strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-")
	name, _, _ = strings.Cut(name, "=")
	return name, name != ""
}

func isReservedServeFlag(name string) bool {
	for _, r := range reservedServeFlags {
		if name == r {
			return true
		}
	}
	return false
}

// cmdServe runs the proxy: an MCP server on stdio toward the agent and an
// MCP client toward one upstream spawned over stdio.
func cmdServe(args []string) int {
	cfg, err := parseServe(args, os.Stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return fail(fmt.Errorf("serve: %w", err))
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	up := proxy.Upstream{
		Server: cfg.server,
		Transport: proxy.Command{
			Path:         cfg.upstream,
			Args:         cfg.upstreamArgs,
			Env:          cfg.upstreamEnv,
			Stderr:       os.Stderr,
			StderrPrefix: "upstream " + cfg.server + ": ",
		}.Transport(),
	}
	startCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	p, err := proxy.New(startCtx, []proxy.Upstream{up}, proxy.Options{Version: version, Logger: logger})
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "netguard: %v\n", err)
		return exitFail
	}
	logger.Info("serving on stdio; M0 pass-through, no policy enforced", "server", cfg.server)

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
