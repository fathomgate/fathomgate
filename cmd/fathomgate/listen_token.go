// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Bearer tokens for `fathomgate serve --listen` (ADR 0016): from owner-only
// files named on the command line (--listen-token-file name=path,
// repeatable) or from FATHOMGATE_LISTEN_TOKEN, never from a flag value. No
// error here quotes a token, a path (which may be a token typed in the
// wrong place) or an argument; errors name the flag, the argument's
// position, the principal or the variable.

const (
	// listenTokenEnv carries one token from the environment, for MCP hosts
	// and containers that inject secrets there. It is a FATHOMGATE_*
	// variable, so it never reaches an upstream (ADR 0017).
	listenTokenEnv = "FATHOMGATE_LISTEN_TOKEN" //nolint:gosec // a variable name, not a credential
	// envPrincipal is the principal name of the FATHOMGATE_LISTEN_TOKEN
	// token: attribution only, like every principal.
	envPrincipal = "env"
	// minListenTokenBytes is the shortest token accepted. proxy.HTTPHandler
	// checks the same rule again (minTokenBytes there).
	minListenTokenBytes = 32
	// maxTokenFileBytes caps what is read from a token file.
	maxTokenFileBytes = 4096
	// principalPattern is the rule for principal names, as printed.
	principalPattern = "[A-Za-z0-9_.:-]"
)

// listenTokens is the token of each principal, and the principals in
// order.
type listenTokens struct {
	byName map[string][]byte
	names  []string // sorted
}

// loadListenTokens reads the tokens for --listen: each --listen-token-file
// entry (name=path) or FATHOMGATE_LISTEN_TOKEN, not both, and at least one.
// Token files are read with readTokenFile, which refuses any file another
// user could read or replace.
func loadListenTokens(files []string, lookup lookupEnvFunc) (listenTokens, error) {
	out := listenTokens{byName: make(map[string][]byte)}
	envTok, envSet := lookup(listenTokenEnv)
	switch {
	case envSet && len(files) > 0:
		return out, fmt.Errorf("%s and --listen-token-file are both set; use one", listenTokenEnv)
	case envSet:
		if envTok == "" {
			return out, fmt.Errorf("%s is set but empty", listenTokenEnv)
		}
		if err := checkListenToken([]byte(envTok)); err != nil {
			return out, fmt.Errorf("%s: the token %w", listenTokenEnv, err)
		}
		out.byName[envPrincipal] = []byte(envTok)
		out.names = []string{envPrincipal}
		return out, nil
	case len(files) == 0:
		return out, fmt.Errorf("--listen needs a bearer token: --listen-token-file NAME=PATH (repeatable) or %s", listenTokenEnv)
	}

	for i, entry := range files {
		name, path, ok := strings.Cut(entry, "=")
		if !ok || name == "" || path == "" {
			return out, fmt.Errorf("--listen-token-file argument %d is not NAME=PATH", i+1)
		}
		if !validPrincipalName(name) {
			return out, fmt.Errorf("--listen-token-file argument %d: the name must be 1 to 64 characters of %s", i+1, principalPattern)
		}
		if _, dup := out.byName[name]; dup {
			return out, fmt.Errorf("--listen-token-file %s is given twice; each principal has one token", name)
		}
		raw, err := readTokenFile(path)
		if err != nil {
			return out, fmt.Errorf("--listen-token-file %s: %w", name, err)
		}
		tok := trimOneNewline(raw)
		if err := checkListenToken(tok); err != nil {
			return out, fmt.Errorf("--listen-token-file %s: the token %w", name, err)
		}
		for other, t := range out.byName {
			if bytes.Equal(t, tok) {
				return out, fmt.Errorf("--listen-token-file %s and %s have the same token; give each principal its own", min(name, other), max(name, other))
			}
		}
		out.byName[name] = tok
		out.names = append(out.names, name)
	}
	slices.Sort(out.names)
	return out, nil
}

// checkListenToken checks a token's shape: at least 32 bytes of printable
// ASCII without spaces. It cannot check that the token is random. The
// error completes "the token ...".
func checkListenToken(tok []byte) error {
	if len(tok) < minListenTokenBytes {
		return fmt.Errorf("is %d bytes; at least %d are required (generate one with: openssl rand -hex 32)", len(tok), minListenTokenBytes)
	}
	for _, b := range tok {
		if b <= ' ' || b >= 0x7f {
			return errors.New("contains white space, a control character or a non-ASCII byte")
		}
	}
	return nil
}

// validPrincipalName checks a principal name: 1 to 64 of [A-Za-z0-9_.:-],
// the rule proxy.HTTPHandler applies too.
func validPrincipalName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("_.:-", c) >= 0
		if !ok {
			return false
		}
	}
	return true
}

// trimOneNewline removes one trailing newline, "\n" or "\r\n", as editors
// and `openssl rand -hex 32 > file` leave it. Anything else stays and is
// refused by checkListenToken.
func trimOneNewline(b []byte) []byte {
	if b, ok := bytes.CutSuffix(b, []byte("\r\n")); ok {
		return b
	}
	b, _ = bytes.CutSuffix(b, []byte("\n"))
	return b
}
