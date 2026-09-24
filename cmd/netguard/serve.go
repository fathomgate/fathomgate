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
	"runtime"
	"slices"
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

const serveUsage = "Usage: netguard serve --server <name> --upstream <path> [--upstream-env K=V]... [--upstream-env-pass NAME]... [-- <upstream args>...]"

// envNamePattern is the rule for upstream environment variable names, as
// printed in errors.
const envNamePattern = "[A-Za-z_][A-Za-z0-9_]*"

// serveConfig is the parsed `netguard serve` command line.
type serveConfig struct {
	server       string
	upstream     string
	upstreamArgs []string
	// upstreamEnv is the --upstream-env entries (not secret).
	upstreamEnv []string
	// passNames are the --upstream-env-pass names, deduplicated, in order.
	passNames []string
	// secrets are the --upstream-env-pass variables, read from netguard's
	// environment. proxy.Command adds them to the child environment after
	// the allow-list and before upstreamEnv, and scrubs them from the
	// upstream's stderr and relayed errors; serve also scrubs them from
	// everything it writes to stderr. A proxy.Secret never formats its
	// value.
	secrets []proxy.Secret
}

// lookupEnvFunc reads a variable from netguard's own environment
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
	fs.Var(&env, "upstream-env", "`KEY=VALUE` added to the upstream's environment, for non-secrets: the value is on netguard's command line (repeatable)")
	fs.Var(&pass, "upstream-env-pass", "variable `NAME` copied from netguard's own environment to the upstream's, for secrets: no value on the command line (repeatable)")
	for _, name := range reservedServeFlags {
		fs.String(name, "", "not enforced in M0; refused until the pipeline is wired (M1)")
	}
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
		return cfg, fmt.Errorf("%s not enforced in M0; netguard serve is pass-through only and forwards every call", strings.Join(refused, ", "))
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
		if isNetguardEnvName(k, goos) {
			return cfg, fmt.Errorf("--upstream-env %s: NETGUARD_* variables are netguard's own settings and are never passed to an upstream", k)
		}
		envKeys = append(envKeys, k)
	}

	// --upstream-env-pass: a name, never a value. An argument that is not
	// a valid name may be a value typed by mistake, so it is named by its
	// position only.
	for i, name := range pass {
		if strings.Contains(name, "=") {
			return cfg, fmt.Errorf("--upstream-env-pass argument %d is not a variable name; it takes NAME only and reads the value from netguard's environment", i+1)
		}
		if !validEnvName(name) {
			return cfg, fmt.Errorf("--upstream-env-pass argument %d: name must match %s", i+1, envNamePattern)
		}
		if isNetguardEnvName(name, goos) {
			return cfg, fmt.Errorf("--upstream-env-pass %s: NETGUARD_* variables are netguard's own settings and are never passed to an upstream", name)
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
			return cfg, fmt.Errorf("--upstream-env-pass %s: not set in netguard's environment", name)
		}
		if v == "" {
			return cfg, fmt.Errorf("--upstream-env-pass %s: set but empty in netguard's environment", name)
		}
		cfg.secrets = append(cfg.secrets, proxy.NewSecret(name, v))
	}
	cfg.upstreamEnv = env
	cfg.upstreamArgs = rest
	return cfg, nil
}

// parseFlagError replaces a flag package error, which quotes the argument,
// with one that names only its position: the first argument that is an
// unknown flag, bad flag syntax, or a flag missing its value. Every serve
// flag takes a value. -h and -help are handled by the flag package
// (flag.ErrHelp) before this is reached.
func parseFlagError(fs *flag.FlagSet, args []string) error {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" || len(a) < 2 || a[0] != '-' {
			break // the flag package stops here too
		}
		name := strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-")
		name, _, hasValue := strings.Cut(name, "=")
		if name == "" || name[0] == '-' || name[0] == '=' {
			return fmt.Errorf("bad flag syntax at argument %d; run netguard serve -h for the flags", i+1)
		}
		if fs.Lookup(name) == nil {
			return fmt.Errorf("unknown flag at argument %d; run netguard serve -h for the flags", i+1)
		}
		if !hasValue {
			if i+1 >= len(args) {
				return fmt.Errorf("flag at argument %d needs a value", i+1)
			}
			i++
		}
	}
	return errors.New("invalid flags; run netguard serve -h for the flags")
}

// isNetguardEnvName reports whether k starts with NETGUARD_, ASCII
// case-insensitively on Windows, where environment names are.
func isNetguardEnvName(k, goos string) bool {
	const p = "NETGUARD_"
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

// cmdServe runs the proxy: an MCP server on stdio toward the agent and an
// MCP client toward one upstream spawned over stdio.
func cmdServe(args []string) int {
	return serve(args, os.Stderr, os.LookupEnv)
}

// serve is cmdServe with its stderr and environment lookup injected.
// Everything it writes to stderr (errors, the slog log, relayed upstream
// stderr) goes through a redactingWriter, so no --upstream-env-pass value
// reaches it, even inside an upstream's own error message.
func serve(args []string, stderr io.Writer, lookup lookupEnvFunc) int {
	cfg, err := parseServe(args, stderr, lookup, runtime.GOOS)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		_, _ = fmt.Fprintf(stderr, "netguard: serve: %v\n", err)
		return exitUsage
	}
	out := &redactingWriter{w: stderr, red: proxy.NewRedactor(cfg.secrets)}

	logger := slog.New(slog.NewTextHandler(out, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	up := proxy.Upstream{
		Server: cfg.server,
		Transport: proxy.Command{
			Path:         cfg.upstream,
			Args:         cfg.upstreamArgs,
			Env:          cfg.upstreamEnv,
			Stderr:       out,
			StderrPrefix: "upstream " + cfg.server + ": ",
			Secrets:      cfg.secrets,
		}.Transport(),
	}
	startCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	p, err := proxy.New(startCtx, []proxy.Upstream{up}, proxy.Options{Version: version, Logger: logger})
	cancel()
	if err != nil {
		_, _ = fmt.Fprintf(out, "netguard: %v\n", err)
		return exitFail
	}
	attrs := []any{"server", cfg.server}
	if len(cfg.passNames) > 0 {
		attrs = append(attrs, "upstream_env_pass", strings.Join(cfg.passNames, ","))
	}
	logger.Info("serving on stdio; M0 pass-through, no policy enforced", attrs...)

	runErr := p.Run(ctx, &mcp.StdioTransport{})
	if err := p.Close(); err != nil {
		logger.Warn("closing upstream", "error", err)
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		_, _ = fmt.Fprintf(out, "netguard: serve: %v\n", runErr)
		return exitFail
	}
	return exitOK
}

// redactingWriter is the last guard on netguard's stderr: every Write has
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
