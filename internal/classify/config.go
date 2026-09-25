// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"fmt"
	"strings"
)

// Config payload checks (docs/specs/classification.md section 11, M1-36).
//
// A config payload is sent to the device in configuration mode, and on most
// upstreams nothing stops it from leaving that mode: eos-mcp push_config puts
// every config_lines element into the same eAPI call as "configure session
// <name>", and netmiko send_config_set (upa, ntunes) writes each line to the
// CLI. A line such as "end", followed by "reload now" or by "configure" and
// "hostname x", runs outside the configuration session, so the call is no
// longer the write the class says: it is an exec command, or a write with no
// commit timer. EOS also runs exec commands from configuration mode without
// any exit. Such a payload makes the call EXEC_ARBITRARY.

// configDialect selects which line rules apply to a tool's config payload.
type configDialect int

const (
	// dialectCLI is the union list for vendor CLIs (EOS, IOS, NX-OS,
	// IOS-XR, and any platform behind netmiko). It is the default: a
	// profile the table below does not list gets the strictest rules.
	dialectCLI configDialect = iota
	// dialectJunosLoad is junos-mcp-server load_and_commit_config, which
	// hands config_text to PyEZ Config.load in the format given by
	// config_format (default "set").
	dialectJunosLoad
)

// configDialects maps server and bare tool name to a dialect other than
// dialectCLI. The server key is the profile's server, which the gate checks
// against the --server name, so an operator profile under another name gets
// dialectCLI, the stricter rules.
var configDialects = map[[2]string]configDialect{
	{"junos-mcp-server", "load_and_commit_config"}: dialectJunosLoad,
}

// cliEscapeWords are the first words that leave configuration mode, re-enter
// it outside the session, commit or abort the session, or run an exec
// command (EOS runs exec commands from configuration mode, and netmiko and
// eAPI run anything once the mode is left). A line's first word matches when
// it is a non-empty prefix of one of these, since vendor CLIs accept
// abbreviations ("conf", "wr", "rel", "e"). The match is one-way: a longer
// word such as "exit-address-family" or "load-interval" is not a prefix of
// any of them and passes.
var cliEscapeWords = []string{
	// leave or re-enter configuration mode, or end the session
	"end", "exit", "quit", "abort", "configure", "commit", "rollback",
	// exec from configuration mode, shells and interpreters
	"do", "run", "exec", "execute", "enable", "disable",
	"bash", "shell", "start", "tclsh", "python", "python3", "guestshell", "op",
	// device state, files and reboots
	"reload", "reboot", "halt", "reset", "restart", "zeroize", "zerotouch",
	"copy", "write", "delete", "erase", "format", "rename", "mkdir", "rmdir",
	"clear", "request", "load", "save", "install", "diagnose", "debug", "undebug", "test",
	"tcpdump",
	// reads: a config payload needs none, and their output (or a redirect
	// of it to a file) would ride on a write's result
	"show", "more",
	// sessions to other hosts: the lines after it go to that host
	"ssh", "telnet", "connect",
}

// junosSetVerbs are the configuration statements a Junos "load set" payload
// may start a line with. Anything else, including run, commit, rollback,
// load, save, exit and quit, fails: whether the load-configuration RPC acts
// on them is not established, so the default is conservative.
var junosSetVerbs = []string{
	"set", "delete", "activate", "deactivate", "annotate", "insert", "rename",
	"copy", "protect", "unprotect", "edit", "top", "up",
}

// Check identifiers for config payload lines, in Result.Reason. The
// control-character and non-ascii identifiers are shared with the command
// checks.
const (
	checkEscapeWord    = "escape-word"
	checkLeadingSymbol = "leading-symbol"
	checkSetVerb       = "set-verb"
)

// configFailure names the first config payload line that failed, by its
// 1-based element and line number, and the check.
type configFailure struct {
	element, line int
	check         string
}

func (f configFailure) reason() string {
	return fmt.Sprintf("config element %d line %d failed the config payload check (%s)", f.element, f.line, f.check)
}

// checkConfigPayload applies the dialect's rules to every element of every
// config argument of the tool, in profile order. Each element is split into
// lines on CR, LF and CRLF; every line is checked. It returns nil when every
// line passes.
func checkConfigPayload(profile *Profile, tool string, spec ToolSpec, args map[string]any) *configFailure {
	dialect := configDialects[[2]string{profile.Server, bareToolName(profile, tool)}]
	junosData := false
	if dialect == dialectJunosLoad {
		junosData = junosLoadIsData(args["config_format"])
	}
	element := 0
	for _, p := range spec.ConfigParams {
		for _, v := range rawValues(args[p]) {
			element++
			for i, line := range splitLines(v) {
				var check string
				switch {
				case dialect == dialectCLI:
					check = checkCLIConfigLine(line)
				case junosData:
					check = checkBytes(line)
				default:
					check = checkJunosSetLine(line)
				}
				if check != "" {
					return &configFailure{element: element, line: i + 1, check: check}
				}
			}
		}
	}
	return nil
}

// bareToolName strips the "<server>." prefix Lookup accepts.
func bareToolName(profile *Profile, tool string) string {
	if _, ok := profile.Tools[tool]; ok {
		return tool
	}
	return strings.TrimPrefix(tool, profile.Server+".")
}

// splitLines splits on CRLF, CR and LF. Any other line separator (vertical
// tab, form feed, NEL, U+2028) stays in the line and fails checkBytes.
// Empty lines are kept so line numbers match the payload.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(strings.ReplaceAll(s, "\r", "\n"), "\n")
}

// checkBytes fails a line holding a control character other than tab, or a
// byte of 0x80 or above.
func checkBytes(line string) string {
	for i := 0; i < len(line); i++ {
		b := line[i]
		switch {
		case b == '\t':
		case b < 0x20 || b == 0x7f:
			return checkControl
		case b >= 0x80:
			return checkNonASCII
		}
	}
	return ""
}

// checkCLIConfigLine applies dialectCLI to one line. Blank lines and "!"
// comments pass. Any other line must start with a letter or digit, and its
// first word (letters, digits, "-" and "_") must not abbreviate an escape
// word.
func checkCLIConfigLine(line string) string {
	if c := checkBytes(line); c != "" {
		return c
	}
	t := strings.ToLower(strings.Trim(line, " \t"))
	if t == "" || t[0] == '!' {
		return ""
	}
	if !isLowerAlnum(t[0]) {
		return checkLeadingSymbol
	}
	end := 1
	for end < len(t) && (isLowerAlnum(t[end]) || t[end] == '-' || t[end] == '_') {
		end++
	}
	word := t[:end]
	for _, v := range cliEscapeWords {
		if strings.HasPrefix(v, word) {
			return checkEscapeWord
		}
	}
	return ""
}

// checkJunosSetLine applies the Junos "load set" rules to one line. Blank
// lines and "#" comments pass; any other line's first word, up to a space
// or tab, must be one of junosSetVerbs exactly.
func checkJunosSetLine(line string) string {
	if c := checkBytes(line); c != "" {
		return c
	}
	t := strings.ToLower(strings.Trim(line, " \t"))
	if t == "" || t[0] == '#' {
		return ""
	}
	word := t
	if i := strings.IndexAny(t, " \t"); i >= 0 {
		word = t[:i]
	}
	for _, v := range junosSetVerbs {
		if word == v {
			return ""
		}
	}
	return checkSetVerb
}

// junosLoadIsData reports whether junos-mcp-server loads config_text as
// configuration data rather than as "load set" statements. The handler
// lower-cases config_format and loads "text" and "xml" as data (the
// load-configuration RPC parses a hierarchy or an XML tree, and no statement
// in either runs a command); "set" and the default are statements. Only an
// ASCII string that lower-cases to "text" or "xml" counts, so no Unicode
// case folding can disagree with Python's str.lower(); anything else gets
// the stricter set rules.
func junosLoadIsData(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	switch strings.ToLower(s) {
	case "text", "xml":
		return true
	}
	return false
}

func isLowerAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}
