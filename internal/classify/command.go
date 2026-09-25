// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"regexp"
	"strconv"
	"strings"
)

// The fallback command classifier is the union of the strongest filters the
// surveyed servers already ship: mcp-telecom's allow-prefix list and regex
// blocklist, pyATS's pipe and redirect ban, and netdev-ssh-mcp's redirection
// of config reads to READ_CONFIG. It is deliberately conservative: anything
// it cannot prove to be a read is EXEC_ARBITRARY. It is vendor-agnostic
// because the device vendor is not known when a call is classified; see
// docs/specs/classification.md section 5.
var (
	// allowPrefix lists the verbs a read-only command may start with.
	// monitor is limited to Junos "monitor traffic", which must also carry
	// a bounded count (monitorCountOK). Junos "monitor interface" takes no
	// count and runs until interrupted, so it is not on the list; IOS-XE
	// "monitor capture" defines capture points and exports files.
	allowPrefix = regexp.MustCompile(`^(?:show|get|display|monitor\s+traffic|ping|traceroute|tracepath)(?:\s|$)`)

	// blocklistStart is classification.md section 5.3: the verbs that
	// change state when they start a line (bl-config-mode and the vendor
	// rows). None of them is on the allow-prefix list, so today they fail
	// there too; this keeps them failing if that list ever grows.
	blocklistStart = regexp.MustCompile(`^(?:configure|config|conf|edit|set|delete|no|commit|rollback|load|save|write|wr|copy|erase|format|reload|rel|relo|request|restart|shutdown|clear|reset|debug|undebug|monitor\s+start|install|boot|zeroize|reboot|halt|power|activate|deactivate|license|crypto|archive|exec|start|bash|python|guestshell|tclsh|run|enable|feature|dockerd|scp|tftp|ssh|ftp|telnet|execute|diagnose|file|test)(?:\s|$)`)
)

// blockedWords are the state-changing verbs refused as any word of a
// command, so "reset-reason" or "no-shutdown" inside a hyphenated keyword
// does not trip them. They include the abbreviations vendor CLIs accept
// (wr, rel, relo). write-file and read-file are the Junos "monitor traffic"
// options that write a capture to disk and read one back from a file on
// the device. Words that are also common show arguments (boot, install,
// enable, no) are only in blocklistStart.
//
// This and blockedPair replace one regular expression matched anywhere in
// the command (M1-39: it cost about 60 us per KiB of command); the test
// keeps that expression and checks the two agree (FuzzBlocklistWords).
var blockedWords = map[string]struct{}{
	"configure": {}, "edit": {}, "set": {}, "delete": {}, "rollback": {}, "commit": {},
	"wr": {}, "wri": {}, "writ": {}, "write": {}, "write-file": {}, "read-file": {},
	"copy": {}, "rel": {}, "relo": {}, "reloa": {}, "reload": {}, "reboot": {},
	"shutdown": {}, "clear": {}, "reset": {}, "format": {}, "erase": {}, "debug": {},
	"undebug": {}, "zeroize": {}, "tclsh": {}, "bash": {}, "python": {},
	"guestshell": {},
}

// blockedPair reports whether two consecutive words are a refused two-word
// verb: any abbreviation of "configure terminal" down to "conf t",
// "request system", "admin save", "admin reboot" and "start shell".
func blockedPair(a, b string) bool {
	switch a {
	case "request":
		return b == "system"
	case "admin":
		return b == "save" || b == "reboot"
	case "start":
		return b == "shell"
	}
	return len(a) >= len("conf") && isAbbrevOf(a, "configure") && isAbbrevOf(b, "terminal")
}

// blocked reports whether any word, or any two consecutive words, of
// fields is on the blocklist.
func blocked(fields []string) bool {
	for i, f := range fields {
		if _, ok := blockedWords[f]; ok {
			return true
		}
		if i+1 < len(fields) && blockedPair(f, fields[i+1]) {
			return true
		}
	}
	return false
}

// hasShellMeta rejects pipes, redirects, chaining, substitution, quoting
// and escapes. A pipe on a network CLI is usually harmless, but it is also
// how "show | ..." smuggles unexpected output filters, and on Linux-backed
// servers the line reaches a shell. Quotes, backslashes, braces, globs,
// tilde and $ are refused because a shell turns them into something the
// checks below never saw ("-f" and a backslash-escaped -f become -f,
// {-f,1.1.1.1} and [-]f expand, * and ? glob, ~root is a home directory,
// $'...' and ${IFS} are rewritten). A $ is allowed only at the end of a
// word (a regex anchor, as in "show ip bgp regexp _65000$"), where no shell
// expands it: before a space, tab, CR, LF or form feed, or at the end.
//
// It is the byte loop of the regular expression [|<>;&"'{}*?\[\]~`\\]|\$\S,
// which the test keeps and checks it against (FuzzShellMeta).
func hasShellMeta(c string) bool {
	for i := 0; i < len(c); i++ {
		switch c[i] {
		case '|', '<', '>', ';', '&', '"', '\'', '{', '}', '*', '?', '[', ']', '~', '`', '\\':
			return true
		case '$':
			if i+1 < len(c) {
				switch c[i+1] {
				case ' ', '\t', '\n', '\r', '\f':
				default:
					return true
				}
			}
		}
	}
	return false
}

// configKeywords are the second words of show, display and get that dump
// configuration. A second word is a config read when it is a prefix of one
// of these (vendor CLIs accept any unambiguous abbreviation: "show ru",
// "show tec") or one of these is a prefix of it ("show running-config-x",
// "show config-sessions"). Matching too much only makes a call
// READ_CONFIG, the stricter read class.
var configKeywords = []string{
	"running-config", "startup-config", "configuration", "config",
	"tech-support", "derived-config", "archive", "full-configuration",
	"current-configuration", "saved-configuration", "session-config",
	"checkpoint", "candidate",
	// NX-OS: "show file bootflash:backup.cfg" prints a file (saved configs
	// live on bootflash) and "show diff rollback-patch ..." prints config
	// diff lines with password hashes. Accepted cost: "show file systems"
	// and "show d" are READ_CONFIG too.
	"file", "diff",
}

// systemConfigKeywords are the third words after "system" (or any prefix of
// it, "show sys rol 1") that dump configuration: Junos show system rollback
// and show system configuration, FortiOS get system admin, interface, ha.
//
// The two-way prefix test over-matches here on purpose: "ha" is a prefix of
// "hardware", so "get system hardware" is READ_CONFIG, and "a" or "i" alone
// match too. Over-matching only makes a read READ_CONFIG, the stricter read
// class.
var systemConfigKeywords = []string{
	"rollback", "configuration", "admin", "interface", "ha",
}

// prefixRelated reports whether w is a prefix of k or k is a prefix of w.
func prefixRelated(w, k string) bool {
	return strings.HasPrefix(k, w) || strings.HasPrefix(w, k)
}

func matchesAny(w string, keywords []string) bool {
	for _, k := range keywords {
		if prefixRelated(w, k) {
			return true
		}
	}
	return false
}

// isConfigRead reports whether normalised fields dump configuration. A bare
// show, display or get is a config read: FortiOS "show" with no argument
// prints the whole configuration.
func isConfigRead(fields []string) bool {
	switch fields[0] {
	case "show", "display", "get":
	default:
		return false
	}
	if len(fields) == 1 {
		return true
	}
	if matchesAny(fields[1], configKeywords) {
		return true
	}
	return len(fields) > 2 && isAbbrevOf(fields[1], "system") && matchesAny(fields[2], systemConfigKeywords)
}

// isAbbrevOf reports whether w is an abbreviation of keyword k: a non-empty
// prefix of it, as a vendor CLI would accept.
func isAbbrevOf(w, k string) bool {
	return w != "" && strings.HasPrefix(k, w)
}

// maxMonitorCount bounds the packets a "monitor traffic" may capture.
const maxMonitorCount = 1000

// monitorCountOK reports whether the words carry at least one "count"
// and every "count" is followed by n with 1 <= n <= maxMonitorCount, n
// plain decimal digits. Requiring every value to be in range means neither
// "count 5 count 999999" nor "count 999999 count 5" passes, whichever one
// the device honours.
func monitorCountOK(fields []string) bool {
	seen := false
	for i, f := range fields {
		if f != "count" {
			continue
		}
		seen = true
		if i+1 >= len(fields) {
			return false
		}
		n := fields[i+1]
		if n == "" || len(n) > 4 || strings.Trim(n, "0123456789") != "" {
			return false
		}
		v, err := strconv.Atoi(n)
		if err != nil || v < 1 || v > maxMonitorCount {
			return false
		}
	}
	return seen
}

// maxCommandLen caps the command the downgrade will inspect. Longer
// commands stay EXEC_ARBITRARY; no read needs more.
const maxCommandLen = 1024

// Check identifiers name the first check a command failed. They appear in
// Result.Reason and are stable so audit consumers can match on them.
const (
	checkEmpty       = "empty"
	checkControl     = "control-character"
	checkNonASCII    = "non-ascii"
	checkShellMeta   = "shell-meta"
	checkLeadingDash = "leading-dash"
	checkBlocklist   = "blocklist"
	checkAllowPrefix = "allow-prefix"
	checkTooLong     = "too-long"
	checkNoCount     = "monitor-no-count"
)

// ClassifyCommand classifies a single free-form CLI command. It returns
// READ_OPERATIONAL for commands that pass the allow-list, READ_CONFIG for
// configuration dumps, and EXEC_ARBITRARY for everything else including an
// empty command.
func ClassifyCommand(cmd string) Class {
	c, _ := classifyCommand(cmd)
	return c
}

// classifyCommand is ClassifyCommand plus the id of the check that failed,
// empty when the command passed.
//
// The raw command is inspected before whitespace is collapsed: a newline,
// carriage return or other control character would otherwise vanish into a
// space while the device still receives two lines ("show version\ncopy
// tftp: flash:"). Only space and tab count as whitespace, and a command
// must be printable ASCII, so a look-alike character cannot hide a verb.
func classifyCommand(cmd string) (Class, string) {
	if len(cmd) > maxCommandLen {
		return ExecArbitrary, checkTooLong
	}
	raw := strings.Trim(cmd, " \t")
	if check := checkBytes(raw); check != "" {
		return ExecArbitrary, check
	}
	fields := strings.Fields(strings.ToLower(raw))
	if len(fields) == 0 {
		return ExecArbitrary, checkEmpty
	}
	c := strings.Join(fields, " ")
	if hasShellMeta(c) {
		return ExecArbitrary, checkShellMeta
	}
	// A leading-dash argument is an option to whatever parses the line.
	// Network CLIs take none on read commands; on a server that runs ping
	// or traceroute on its own host it is option injection.
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "-") {
			return ExecArbitrary, checkLeadingDash
		}
	}
	if blocklistStart.MatchString(c) || blocked(fields) {
		return ExecArbitrary, checkBlocklist
	}
	if isConfigRead(fields) {
		return ReadConfig, ""
	}
	// Junos "monitor traffic" runs until interrupted unless it carries
	// "count <n>"; n must be 1 to 1000.
	if fields[0] == "monitor" && len(fields) > 1 && fields[1] == "traffic" && !monitorCountOK(fields) {
		return ExecArbitrary, checkNoCount
	}
	if allowPrefix.MatchString(c) {
		return ReadOperational, ""
	}
	return ExecArbitrary, checkAllowPrefix
}

// ClassifyCommands classifies a batch of commands with the downgrade rule:
// the result is EXEC_ARBITRARY if any command fails, READ_CONFIG if any
// command is a configuration read, and READ_OPERATIONAL only if every
// command passes. An empty batch is EXEC_ARBITRARY because there is nothing
// to prove safe.
func ClassifyCommands(cmds []string) Class {
	c, _, _ := classifyCommands(cmds)
	return c
}

// classifyCommands is ClassifyCommands plus the index of the first failing
// command and the check it failed (-1 and "" when every command passed, and
// -1 and checkEmpty for an empty batch).
func classifyCommands(cmds []string) (Class, int, string) {
	if len(cmds) == 0 {
		return ExecArbitrary, -1, checkEmpty
	}
	out := ReadOperational
	for i, c := range cmds {
		switch class, check := classifyCommand(c); class {
		case ExecArbitrary:
			return ExecArbitrary, i, check
		case ReadConfig:
			out = ReadConfig
		}
	}
	return out, -1, ""
}
