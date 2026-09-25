// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/fathomgate/fathomgate/internal/audit"
)

func cmdAudit(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fathomgate audit <verify|keygen> ...")
		return exitUsage
	}
	switch args[0] {
	case "verify":
		return cmdAuditVerify(args[1:])
	case "keygen":
		return cmdAuditKeygen(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "fathomgate audit: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

// cmdAuditVerify replays the chain and exits 1 on the first break.
func cmdAuditVerify(args []string) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	keyPath := fs.String("key", "", "Ed25519 public (or private) key PEM to verify checkpoint signatures")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	files, err := parseInterspersed(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(files) != 1 {
		fmt.Fprintln(os.Stderr, "usage: fathomgate audit verify <audit.jsonl> [--key audit.pub]")
		return exitUsage
	}
	var pub ed25519.PublicKey
	if *keyPath != "" {
		k, err := audit.LoadPublicKey(*keyPath)
		if err != nil {
			return fail(err)
		}
		pub = k
	}
	rep, err := audit.VerifyWithKey(files[0], pub)
	if err != nil {
		return fail(err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		status := "OK"
		if !rep.OK {
			status = "BROKEN"
		}
		fmt.Printf("chain:       %s\n", status)
		fmt.Printf("events:      %d\n", rep.Events)
		fmt.Printf("checkpoints: %d (signatures checked: %v)\n", rep.Checkpoints, rep.SignaturesChecked)
		fmt.Printf("last seq:    %d\n", rep.LastSeq)
		fmt.Printf("last hash:   %s\n", rep.LastHash)
		if !rep.OK {
			fmt.Printf("broken seq:  %d\n", rep.BrokenSeq)
			fmt.Printf("problem:     %s\n", rep.Problem)
		}
	}
	if !rep.OK {
		return exitFail
	}
	return exitOK
}

// cmdAuditKeygen creates a checkpoint signing key pair.
func cmdAuditKeygen(args []string) int {
	fs := flag.NewFlagSet("audit keygen", flag.ContinueOnError)
	out := fs.String("out", "audit.key", "private key output path; created owner-only and never overwritten")
	pubOut := fs.String("pub", "", "public key output path (default: <out>.pub)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *pubOut == "" {
		*pubOut = *out + ".pub"
	}
	// Friendly early errors; WriteKeyPair enforces the same with O_EXCL.
	if _, err := os.Lstat(*out); err == nil {
		return fail(fmt.Errorf("%s already exists; refusing to overwrite a signing key", *out))
	}
	if _, err := os.Lstat(*pubOut); err == nil {
		return fail(fmt.Errorf("%s already exists; refusing to overwrite a verification key", *pubOut))
	}
	pub, priv, err := audit.NewKey()
	if err != nil {
		return fail(err)
	}
	if err := audit.WriteKeyPair(*out, *pubOut, pub, priv); err != nil {
		return fail(err)
	}
	fmt.Printf("private key: %s\npublic key:  %s\n", *out, *pubOut)
	return exitOK
}
