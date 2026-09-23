package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/joshscott13/netguard/internal/inventory"
)

func cmdInventory(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: netguard inventory import --csv devices.csv --out inventory.yaml")
		return exitUsage
	}
	switch args[0] {
	case "import":
		return cmdInventoryImport(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "netguard inventory: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

// cmdInventoryImport converts a CSV export into inventory.yaml.
func cmdInventoryImport(args []string) int {
	fs := flag.NewFlagSet("inventory import", flag.ContinueOnError)
	csvPath := fs.String("csv", "", "CSV with columns name,role,site,tags,status (required; - for stdin)")
	outPath := fs.String("out", "inventory.yaml", "output path (- for stdout)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *csvPath == "" {
		return fail(fmt.Errorf("--csv is required"))
	}
	var in io.Reader = os.Stdin
	if *csvPath != "-" {
		f, err := os.Open(*csvPath)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		in = f
	}
	targets, err := inventory.ImportCSV(in)
	if err != nil {
		return fail(err)
	}
	if _, err := inventory.NewStatic(targets); err != nil {
		return fail(err)
	}
	var out io.Writer = os.Stdout
	if *outPath != "-" {
		f, err := os.OpenFile(*outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		out = f
	}
	if err := inventory.WriteFile(out, &inventory.File{Devices: targets}); err != nil {
		return fail(err)
	}
	if *outPath != "-" {
		fmt.Fprintf(os.Stderr, "wrote %d devices to %s\n", len(targets), *outPath)
	}
	return exitOK
}
