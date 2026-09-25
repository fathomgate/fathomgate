// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fathomgate/fathomgate/internal/proxy"
)

// startupTimeout bounds spawning the upstream, its handshake and tools/list,
// including the restart after an unanswered server/discover (ADR 0018).
const startupTimeout = 30 * time.Second

// reservedServeFlags are refused in M0: the pipeline they configure is not
// wired into the proxy until M1 (policy, inventory, profiles) and M4
// (audit). Refusing them keeps an operator from believing a policy is
// enforced when M0 forwards every call.
var reservedServeFlags = []string{"policy", "inventory", "profiles", "audit"}

// reservedListenFlags are refused in M0: they take the listener off
// loopback, which waits for the policy pipeline and built-in TLS (M1, ADR
// 0016). Unlike reservedServeFlags they are not looked for among the
// upstream's arguments after "--": an upstream flag of that name is the
// upstream's.
var reservedListenFlags = []string{"listen-remote", "listen-host"}

const serveUsage = `Usage:
  fathomgate serve --server <name> --upstream <path> [--upstream-env K=V]... [--upstream-env-pass NAME]...
                   [--listen <addr>:<port> (--listen-token-file NAME=PATH... | env FATHOMGATE_LISTEN_TOKEN)]
                   [-- <upstream args>...]

The agent side is stdio, or with --listen Streamable HTTP at http://<addr>:<port>/mcp
(loopback only, a bearer token on every request) instead of stdio.

Flags:`

// envNamePattern is the rule for upstream environment variable names, as
// printed in errors.
const envNamePattern = "[A-Za-z_][A-Za-z0-9_]*"

// serveConfig is the parsed `fathomgate serve` command line.
type serveConfig struct {
	server       string
	upstream     string
	upstreamArgs []string
	// upstreamEnv is the --upstream-env entries (not secret).
	upstreamEnv []string
	// passNames are the --upstream-env-pass names, deduplicated, in order.
	passNames []string
	// secrets are the --upstream-env-pass variables, read from fathomgate's
	// environment. proxy.Command adds them to the child environment after
	// the allow-list and before upstreamEnv, and scrubs them from the
	// upstream's stderr and relayed errors; serve also scrubs them from
	// everything it writes to stderr. A proxy.Secret never formats its
	// value.
	secrets []proxy.Secret

	// listen is the --listen address (parseListenAddr), or nil to serve
	// the agent on stdio. The two agent sides are exclusive (ADR 0016).
	listen *listenAddr
	// tokens are the listener's bearer tokens by principal, read from the
	// --listen-token-file files or FATHOMGATE_LISTEN_TOKEN. They are never
	// passed to the upstream, and serve scrubs them from its stderr.
	tokens listenTokens
}

// lookupEnvFunc reads a variable from fathomgate's own environment
// (os.LookupEnv outside tests).
type lookupEnvFunc func(name string) (string, bool)

// parseServe parses the serve flags. Upstream arguments are accepted only
// after "--": the flag package stops at the first positional argument, so
// without that rule `--upstream x extra --policy p.yaml` would slip a
// reserved flag past the check. Leftover arguments are scanned for reserved
// flag names whether or not "--" came first.
//
// Values for --upstream-env-pass are read with lookup. goos decides how
// variable names compare: ASCII case-insensitively on Windows, exactly
// elsewhere. No error parseServe returns quotes a command-line argument
// that could be a value, or an environment value: a password typed as its
// own argument, a stray positional or an unknown flag is reported by its
// position. Errors name flags and environment variable names only.
func parseServe(args []string, usageOut io.Writer, lookup lookupEnvFunc, goos string) (serveConfig, error) {
	var cfg serveConfig
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	// The flag package's own messages quote the offending argument
	// ("flag provided but not defined: -FAKEhunter2"), so they are
	// discarded; parseFlagError reports the position instead.
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.server, "server", "", "tool prefix `name` for the upstream: the server key of its profile in profiles/ (required)")
	fs.StringVar(&cfg.upstream, "upstream", "", "upstream MCP server executable `path`, spawned over stdio (required); its arguments follow --")
	var env, pass stringList
	fs.Var(&env, "upstream-env", "`KEY=VALUE` added to the upstream's environment, for non-secrets: the value is on fathomgate's command line (repeatable)")
	fs.Var(&pass, "upstream-env-pass", "variable `NAME` copied from fathomgate's own environment to the upstream's, for secrets: no value on the command line (repeatable)")
	for _, name := range reservedServeFlags {
		fs.String(name, "", "not enforced in M0; refused until the pipeline is wired (M1)")
	}
	var listen string
	var tokenFiles, listenHosts stringList
	fs.StringVar(&listen, "listen", "", "serve Streamable HTTP at http://`addr:port`/mcp instead of stdio: localhost, 127.0.0.1 or [::1] (loopback only); 127.0.0.1 and [::1] are both bound on the port, whichever is given; port 0 picks a free port")
	fs.Var(&tokenFiles, "listen-token-file", "`NAME=PATH` of an owner-only file holding the bearer token of principal NAME (repeatable); or set FATHOMGATE_LISTEN_TOKEN instead (principal env)")
	fs.Bool("listen-remote", false, "reserved for M1; refused: the listener is loopback-only until the policy pipeline is wired")
	fs.Var(&listenHosts, "listen-host", "allowed `host` name: reserved for M1; refused: the listener is loopback-only until the policy pipeline is wired")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(usageOut, serveUsage)
		fs.SetOutput(usageOut)
		fs.PrintDefaults()
		fs.SetOutput(io.Discard)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cfg, err
		}
		return cfg, parseFlagError(fs, args)
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
			refused = append(refused, "--"+name) // the name, not "=value"
		}
	}
	if len(refused) > 0 {
		return cfg, fmt.Errorf("%s not enforced in M0; fathomgate serve is pass-through only and forwards every call", strings.Join(refused, ", "))
	}
	fs.Visit(func(f *flag.Flag) {
		if slices.Contains(reservedListenFlags, f.Name) {
			refused = append(refused, "--"+f.Name)
		}
	})
	if len(refused) > 0 {
		return cfg, fmt.Errorf("%s reserved for M1: the listener is loopback-only until the policy pipeline is wired, and then needs TLS", strings.Join(refused, ", "))
	}
	consumed := len(args) - len(rest)
	sawDashDash := consumed > 0 && args[consumed-1] == "--"
	if len(rest) > 0 && !sawDashDash {
		// Position only: this is where a password typed as its own
		// argument (--upstream-env DEVICE_PASSWORD FAKE-hunter2) lands.
		return cfg, fmt.Errorf("unexpected argument %d; arguments for the upstream go after --", consumed+1)
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

	// --upstream-env: an argument may carry a secret, and a malformed one
	// may be a value typed in the wrong place, so a malformed argument is
	// reported by its position only.
	envKeys := make([]string, 0, len(env))
	for i, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			return cfg, fmt.Errorf("--upstream-env argument %d is not KEY=VALUE", i+1)
		}
		if !validEnvName(k) {
			return cfg, fmt.Errorf("--upstream-env argument %d: key must match %s", i+1, envNamePattern)
		}
		if isFathomgateEnvName(k, goos) {
			return cfg, fmt.Errorf("--upstream-env %s: FATHOMGATE_* variables are fathomgate's own settings and are never passed to an upstream", k)
		}
		envKeys = append(envKeys, k)
	}

	// --upstream-env-pass: a name, never a value. An argument that is not
	// a valid name may be a value typed by mistake, so it is named by its
	// position only.
	for i, name := range pass {
		if strings.Contains(name, "=") {
			return cfg, fmt.Errorf("--upstream-env-pass argument %d is not a variable name; it takes NAME only and reads the value from fathomgate's environment", i+1)
		}
		if !validEnvName(name) {
			return cfg, fmt.Errorf("--upstream-env-pass argument %d: name must match %s", i+1, envNamePattern)
		}
		if isFathomgateEnvName(name, goos) {
			return cfg, fmt.Errorf("--upstream-env-pass %s: FATHOMGATE_* variables are fathomgate's own settings and are never passed to an upstream", name)
		}
		if !slices.ContainsFunc(cfg.passNames, func(n string) bool { return sameEnvName(n, name, goos) }) {
			cfg.passNames = append(cfg.passNames, name)
		}
	}
	for _, name := range cfg.passNames {
		for _, k := range envKeys {
			if sameEnvName(name, k, goos) {
				return cfg, fmt.Errorf("%s is given with both --upstream-env and --upstream-env-pass; use one", name)
			}
		}
	}

	// Read the values last, once every argument is known to be valid, and
	// before anything is spawned. An empty value counts as unset. The
	// "not set" error names the variable (ADR 0017); a value typed as a
	// name would be echoed here, an accepted residual.
	for _, name := range cfg.passNames {
		v, ok := lookup(name)
		if !ok {
			return cfg, fmt.Errorf("--upstream-env-pass %s: not set in fathomgate's environment", name)
		}
		if v == "" {
			return cfg, fmt.Errorf("--upstream-env-pass %s: set but empty in fathomgate's environment", name)
		}
		cfg.secrets = append(cfg.secrets, proxy.NewSecret(name, v))
	}

	// --listen: the address first, then the tokens, which may read files.
	// A token file named without --listen is refused rather than ignored.
	switch {
	case listen != "":
		addr, err := parseListenAddr(listen)
		if err != nil {
			return cfg, err
		}
		tokens, err := loadListenTokens(tokenFiles, lookup)
		if err != nil {
			return cfg, err
		}
		cfg.listen, cfg.tokens = &addr, tokens
	case len(tokenFiles) > 0:
		return cfg, errors.New("--listen-token-file is only used with --listen")
	}
	cfg.upstreamEnv = env
	cfg.upstreamArgs = rest
	return cfg, nil
}

// parseFlagError replaces a flag package error, which quotes the argument,
// with one that names only its position: the first argument that is an
// unknown flag, bad flag syntax, or a flag missing its value. Every serve
// flag takes a value but --listen-remote, a boolean. -h and -help are
// handled by the flag package (flag.ErrHelp) before this is reached.
func parseFlagError(fs *flag.FlagSet, args []string) error {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" || len(a) < 2 || a[0] != '-' {
			break // the flag package stops here too
		}
		name := strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-")
		name, _, hasValue := strings.Cut(name, "=")
		if name == "" || name[0] == '-' || name[0] == '=' {
			return fmt.Errorf("bad flag syntax at argument %d; run fathomgate serve -h for the flags", i+1)
		}
		f := fs.Lookup(name)
		if f == nil {
			return fmt.Errorf("unknown flag at argument %d; run fathomgate serve -h for the flags", i+1)
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			if hasValue {
				return fmt.Errorf("flag at argument %d takes no value", i+1)
			}
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				return fmt.Errorf("flag at argument %d needs a value", i+1)
			}
			i++
		}
	}
	return errors.New("invalid flags; run fathomgate serve -h for the flags")
}

// isFathomgateEnvName reports whether k starts with FATHOMGATE_, ASCII
// case-insensitively on Windows, where environment names are.
func isFathomgateEnvName(k, goos string) bool {
	const p = "FATHOMGATE_"
	return len(k) >= len(p) && sameEnvName(k[:len(p)], p, goos)
}

// sameEnvName compares two variable names already checked by validEnvName
// (so ASCII only): case-insensitively on Windows, exactly elsewhere.
func sameEnvName(a, b, goos string) bool {
	if goos == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
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

// cmdServe runs the proxy: an MCP server toward the agent, on stdio or
// with --listen over Streamable HTTP, and an MCP client toward one upstream
// spawned over stdio.
func cmdServe(args []string) int {
	return serve(args, os.Stderr, os.LookupEnv)
}

// serve is cmdServe with its stderr and environment lookup injected. It
// runs until SIGINT or SIGTERM, or until the agent side ends.
func serve(args []string, stderr io.Writer, lookup lookupEnvFunc) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The first signal starts the shutdown; stopping the notification then
	// gives a second signal its default action, so it ends fathomgate at
	// once instead of being ignored while the shutdown runs (N2 in the
	// security review of PR #109). Nothing is cleaned up after that second
	// signal: the upstream is not stopped (threat-model row on orphaned
	// upstream processes).
	context.AfterFunc(ctx, stop)
	return serveContext(ctx, args, stderr, lookup)
}

// serveContext is serve with the end of ctx standing in for a signal.
// Everything it writes to stderr (errors, the slog log, relayed upstream
// stderr) goes through a redactingWriter, so no --upstream-env-pass value
// and no listen token reaches it, even inside an upstream's own error
// message.
func serveContext(ctx context.Context, args []string, stderr io.Writer, lookup lookupEnvFunc) int {
	cfg, err := parseServe(args, stderr, lookup, runtime.GOOS)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		_, _ = fmt.Fprintf(stderr, "fathomgate: serve: %v\n", err)
		return exitUsage
	}
	// The listener's tokens are scrubbed from stderr too. They are kept out
	// of cfg.secrets, which proxy.Command passes to the upstream.
	scrub := slices.Clone(cfg.secrets)
	for _, name := range cfg.tokens.names {
		scrub = append(scrub, proxy.NewSecret("listen-token:"+name, string(cfg.tokens.byName[name])))
	}
	out := &redactingWriter{w: stderr, red: proxy.NewRedactor(scrub)}
	logger := slog.New(slog.NewTextHandler(out, nil))

	// The listener's pre-flight, before anything is bound or spawned: the
	// MCPGODEBUG refusal (S6 in the security review of T0.40), then the
	// bind of both loopback families, so a port in use on either fails
	// before the upstream starts.
	var lns []net.Listener
	if cfg.listen != nil {
		if err := checkListenEnvironment(lookup); err != nil {
			_, _ = fmt.Fprintf(out, "fathomgate: serve: --listen: %v\n", err)
			return exitUsage
		}
		lns, err = bindLoopback(*cfg.listen, listenTCP, logger)
		if err != nil {
			_, _ = fmt.Fprintf(out, "fathomgate: serve: --listen: %v\n", err)
			return exitFail
		}
	}

	cmd := proxy.Command{
		Path:         cfg.upstream,
		Args:         cfg.upstreamArgs,
		Env:          cfg.upstreamEnv,
		Stderr:       out,
		StderrPrefix: "upstream " + cfg.server + ": ",
		Secrets:      cfg.secrets,
	}
	// A new process per call: New restarts an upstream that does not answer
	// server/discover (ADR 0018).
	up := proxy.Upstream{
		Server:       cfg.server,
		NewTransport: func() mcp.Transport { return cmd.Transport() },
	}
	startCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	p, err := proxy.New(startCtx, []proxy.Upstream{up}, proxy.Options{Version: version, Logger: logger})
	cancel()
	if err != nil {
		for _, ln := range lns {
			_ = ln.Close()
		}
		_, _ = fmt.Fprintf(out, "fathomgate: %v\n", err)
		return exitFail
	}
	attrs := []any{"server", cfg.server}
	if len(cfg.passNames) > 0 {
		attrs = append(attrs, "upstream_env_pass", strings.Join(cfg.passNames, ","))
	}
	if cfg.listen != nil {
		// Neither stdin nor stdout is touched from here on (ADR 0016).
		return runListener(ctx, p, lns, listenRun{tokens: cfg.tokens, server: cfg.server, passNames: cfg.passNames}, logger, out)
	}
	logger.Info("serving on stdio; M0 pass-through, no policy enforced", attrs...)

	runErr := p.Run(ctx, &mcp.StdioTransport{})
	if err := p.Close(); err != nil {
		logger.Warn("closing upstream", "error", err)
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		_, _ = fmt.Fprintf(out, "fathomgate: serve: %v\n", runErr)
		return exitFail
	}
	return exitOK
}

// redactingWriter is the last guard on fathomgate's stderr: every Write has
// the --upstream-env-pass values replaced by "[redacted:NAME]"
// (proxy.Redactor.Redact, built once), in raw, encoded and escaped form.
// Each Write is redacted on its own, which holds because every writer
// behind it (fmt, slog, the upstream stderr line writer) writes whole
// lines. It keeps no state between writes, so concurrent writers are as
// safe as with w alone.
type redactingWriter struct {
	w   io.Writer
	red *proxy.Redactor // nil: pass through
}

func (r *redactingWriter) Write(p []byte) (int, error) {
	if r.red == nil {
		return r.w.Write(p)
	}
	if _, err := io.WriteString(r.w, r.red.Redact(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}
