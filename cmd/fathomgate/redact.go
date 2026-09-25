// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/fathomgate/fathomgate/internal/redact"
)

// cmdRedact reads device output from a file or stdin, redacts it with the
// deployment's HMAC key and writes the result to stdout. A summary of which
// rules fired goes to stderr so stdout stays pipeable.
func cmdRedact(args []string) int {
	fs := flag.NewFlagSet("redact", flag.ContinueOnError)
	keyFile := fs.String("key-file", "", "file holding the HMAC key (or set FATHOMGATE_REDACT_KEY)")
	quiet := fs.Bool("q", false, "do not print the hit summary")
	files, err := parseInterspersed(fs, args)
	if err != nil {
		return exitUsage
	}
	key, err := loadRedactKey(*keyFile)
	if err != nil {
		return fail(err)
	}
	in := os.Stdin
	if len(files) == 1 {
		f, err := os.Open(files[0])
		if err != nil {
			return fail(err)
		}
		defer func() { _ = f.Close() }()
		in = f
	} else if len(files) > 1 {
		fmt.Fprintln(os.Stderr, "usage: fathomgate redact --key-file <file> [input-file]")
		return exitUsage
	}
	data, err := io.ReadAll(in)
	if err != nil {
		return fail(err)
	}
	out, hits := redact.New(key).Redact(string(data))
	if _, err := io.WriteString(os.Stdout, out); err != nil {
		return fail(err)
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "redacted %d secrets", redact.Count(hits))
		for _, h := range hits {
			fmt.Fprintf(os.Stderr, " %s=%d", h.RuleID, h.Count)
		}
		fmt.Fprintln(os.Stderr)
	}
	return exitOK
}

func loadRedactKey(path string) ([]byte, error) {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			return nil, fmt.Errorf("key file %s is empty", path)
		}
		return b, nil
	}
	if env := os.Getenv("FATHOMGATE_REDACT_KEY"); env != "" {
		return []byte(env), nil
	}
	return nil, fmt.Errorf("--key-file is required (or set FATHOMGATE_REDACT_KEY)")
}
