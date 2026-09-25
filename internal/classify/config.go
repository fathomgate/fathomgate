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
// any exit, and some configuration schedules execution itself. Such a
// payload makes the call EXEC_ARBITRARY.

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
// it outside the session, commit or abort the session, run an exec command
// (EOS runs exec commands from configuration mode, and netmiko and eAPI run
// anything once the mode is left), define an alias for one, or schedule
// execution. A line's first word matches when it is a non-empty prefix of one
// of these, since vendor CLIs accept abbreviations ("conf", "wr", "rel",
// "e"). The match is one-way: a longer word such as "exit-address-family",
// "load-interval" or "event-monitor" is not a prefix of any of them and
// passes.
//
// The list is a denylist, and EOS configuration mode accepts every exec
// command, so it cannot be complete for eos-mcp; an allow-list of top-level
// configuration words for push_config is the long-term fix
// (classification.md section 11.5).
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
	// aliases define a new exec word for a later call (IOS "alias
	// configure hn do reload", EOS "alias hn reload now", NX-OS "cli alias
	// name hn reload")
	"alias", "cli",
	// configuration that schedules execution: IOS EEM ("event manager") and
	// kron, EOS event-handler, schedule and daemon, NX-OS scheduler, and the
	// "command" lines inside them
	"event", "event-handler", "schedule", "scheduler", "kron", "daemon", "command",
	// other exec verbs EOS runs from configuration mode, and mode changes on
	// IOS-XR (admin) and Huawei VRP (return, system-view)
	"ping", "traceroute", "clock", "send", "watch", "logout", "terminal",
	"agent", "return", "system-view", "admin",
}

// junosSetVerbs are the configuration statements a Junos "load set" payload
// may start a line with. Anything else, including run, commit, rollback,
// load, save, exit and quit, fails: whether the load-configuration RPC acts
// on them is not established, so the default is conservative.
var junosSetVerbs = []string{
	"set", "delete", "activate", "deactivate", "annotate", "insert", "rename",
	"copy", "protect", "unprotect", "edit", "top", "up",
}

// junosExecConfigWords are the Junos hierarchies that make configuration
// run something: event policies (event-options, execute-commands), commit,
// op and event scripts (scripts), and on-box extensions (extensions). In a
// set payload a line fails when any word after the first abbreviates one of
// them (Junos accepts unique abbreviations, and "edit system" then "set
// scripts ..." names the hierarchy relative to the current level); in text
// and xml payloads when one appears anywhere, case-insensitively.
var junosExecConfigWords = []string{"event-options", "scripts", "extensions", "execute-commands"}

// Size caps for config payloads. A line in the CLI and Junos set dialects
// may be at most maxConfigLineLen bytes, the command cap: no configuration
// statement needs more. The whole payload, every element of every config
// argument together, may be at most maxConfigPayloadLen bytes, the gate's
// cap on a call's arguments. Junos text and xml lines have no line cap, as
// an xml document can be one line.
const (
	maxConfigLineLen    = maxCommandLen
	maxConfigPayloadLen = 64 << 10
)

// Check identifiers for config payload lines, in Result.Reason. The
// control-character, non-ascii and too-long identifiers are shared with the
// command checks.
const (
	checkEscapeWord    = "escape-word"
	checkLeadingSymbol = "leading-symbol"
	checkSetVerb       = "set-verb"
	checkSeparator     = "separator"
	checkExecConfig    = "exec-config"
	checkDTD           = "dtd"
)

// configFailure names the first config payload line that failed, by its
// 1-based element and line number, and the check. Element 0 means the
// payload as a whole (too-long).
type configFailure struct {
	element, line int
	check         string
}

func (f configFailure) reason() string {
	if f.element == 0 {
		return fmt.Sprintf("config payload failed the config payload check (%s)", f.check)
	}
	return fmt.Sprintf("config element %d line %d failed the config payload check (%s)", f.element, f.line, f.check)
}

// checkConfigPayload applies the dialect's rules to every element of every
// config argument of the tool, in profile order. Each element is split into
// lines on CR, LF and CRLF; every line is checked. It returns nil when every
// line passes.
func checkConfigPayload(profile *Profile, tool string, spec ToolSpec, args map[string]any) *configFailure {
	dialect := configDialects[[2]string{profile.Server, bareToolName(profile, tool)}]
	format := ""
	if dialect == dialectJunosLoad {
		format = junosLoadFormat(args["config_format"])
	}
	var values []string
	total := 0
	for _, p := range spec.ConfigParams {
		for _, v := range rawValues(args[p]) {
			values = append(values, v)
			total += len(v)
		}
	}
	if total > maxConfigPayloadLen {
		return &configFailure{check: checkTooLong}
	}
	for e, v := range values {
		for i, line := range splitLines(v) {
			var check string
			switch {
			case dialect == dialectCLI:
				check = checkCLIConfigLine(line)
			case format == "set":
				check = checkJunosSetLine(line)
			default:
				check = checkJunosDataLine(line, format)
			}
			if check != "" {
				return &configFailure{element: e + 1, line: i + 1, check: check}
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
// comments pass. Any other line must be at most maxConfigLineLen bytes, hold
// no ";" (NX-OS runs "hostname x ; end ; reload" as three commands), start
// with a letter or digit, and its first word (letters, digits, "-" and "_")
// must not abbreviate an escape word.
func checkCLIConfigLine(line string) string {
	if len(line) > maxConfigLineLen {
		return checkTooLong
	}
	if c := checkBytes(line); c != "" {
		return c
	}
	t := strings.ToLower(strings.Trim(line, " \t"))
	if t == "" || t[0] == '!' {
		return ""
	}
	if strings.Contains(t, ";") {
		return checkSeparator
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
// lines and "#" comments pass. Any other line must be at most
// maxConfigLineLen bytes; its first word, up to a space or tab, must be one
// of junosSetVerbs exactly; "top" and "up" take nothing but an optional
// count after "up" (Junos runs "top <command>" and "up <n> <command>" as
// <command> at that level); and no later word may abbreviate one of
// junosExecConfigWords.
func checkJunosSetLine(line string) string {
	if len(line) > maxConfigLineLen {
		return checkTooLong
	}
	if c := checkBytes(line); c != "" {
		return c
	}
	t := strings.ToLower(strings.Trim(line, " \t"))
	if t == "" || t[0] == '#' {
		return ""
	}
	words := strings.Fields(t) // only spaces and tabs are left after checkBytes
	known := false
	for _, v := range junosSetVerbs {
		if words[0] == v {
			known = true
			break
		}
	}
	if !known {
		return checkSetVerb
	}
	switch words[0] {
	case "top":
		if len(words) != 1 {
			return checkSetVerb
		}
	case "up":
		if len(words) > 2 || (len(words) == 2 && !allDigits(words[1])) {
			return checkSetVerb
		}
	}
	for _, w := range words[1:] {
		w = strings.Trim(w, `"'`)
		if w == "" {
			continue
		}
		for _, x := range junosExecConfigWords {
			if strings.HasPrefix(x, w) {
				return checkExecConfig
			}
		}
	}
	return ""
}

// checkJunosDataLine applies the Junos text and xml rules to one line: the
// byte checks, no hierarchy from junosExecConfigWords anywhere in the line
// (case-insensitive), and for xml no "<!" (a DOCTYPE or entity declaration).
func checkJunosDataLine(line, format string) string {
	if c := checkBytes(line); c != "" {
		return c
	}
	t := strings.ToLower(line)
	for _, x := range junosExecConfigWords {
		if strings.Contains(t, x) {
			return checkExecConfig
		}
	}
	if format == "xml" && strings.Contains(t, "<!") {
		return checkDTD
	}
	return ""
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// junosLoadFormat returns "text" or "xml" when junos-mcp-server loads
// config_text as configuration data, and "set" when it loads it as "load
// set" statements. The handler lower-cases config_format and loads "text"
// and "xml" as data (the load-configuration RPC parses a hierarchy or an
// XML tree, and no statement in either runs a command); "set" and the
// default are statements. Only an ASCII string that lower-cases to "text"
// or "xml" counts, so no Unicode case folding can disagree with Python's
// str.lower(); anything else gets the stricter set rules.
func junosLoadFormat(v any) string {
	s, ok := v.(string)
	if !ok {
		return "set"
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return "set"
		}
	}
	switch f := strings.ToLower(s); f {
	case "text", "xml":
		return f
	}
	return "set"
}

func isLowerAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}
