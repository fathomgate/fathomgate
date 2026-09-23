package classify

import (
	"regexp"
	"strings"
)

// The fallback command classifier is the union of the strongest filters the
// surveyed servers already ship: mcp-telecom's allow-prefix list and regex
// blocklist, pyATS's pipe and redirect ban, and netdev-ssh-mcp's redirection
// of config reads to READ_CONFIG. It is deliberately conservative: anything
// it cannot prove to be a read is EXEC_ARBITRARY.
var (
	// allowPrefix lists the verbs a read-only command may start with.
	allowPrefix = regexp.MustCompile(`^(?:show|get|display|monitor|ping|traceroute|tracepath)(?:\s|$)`)

	// configRead matches commands that dump configuration and therefore
	// belong to READ_CONFIG even though they start with an allowed verb.
	configRead = regexp.MustCompile(`^(?:show|display|get)\s+(?:running-config|running|startup-config|startup|configuration|config|full-configuration|current-configuration|saved-configuration|system\s+config)(?:\s|$)`)

	// blocklist matches state-changing verbs anywhere in the command,
	// bounded by whitespace so "reset-reason" or "no-shutdown" inside a
	// hyphenated keyword does not trip it.
	blocklist = regexp.MustCompile(`(?:^|\s)(?:configure|config\s+t(?:erminal)?|edit|set|delete|rollback|commit|write(?:\s+(?:mem(?:ory)?|erase))?|copy\s+running|reload|reboot|shutdown|clear|reset|format|erase|debug|request\s+system|zeroize|admin\s+(?:save|reboot))(?:\s|$)`)

	// shellMeta rejects pipes, redirects, chaining and substitution. A pipe
	// on a network CLI is usually harmless, but it is also how "show | ..."
	// smuggles unexpected output filters and on Linux-backed servers it is
	// a shell. The fallback refuses it; profiles for servers that filter
	// commands themselves can classify those tools as READ_OPERATIONAL.
	shellMeta = regexp.MustCompile("[|<>;&`]|\\$\\(")
)

// ClassifyCommand classifies a single free-form CLI command. It returns
// READ_OPERATIONAL for commands that pass the allow-list, READ_CONFIG for
// configuration dumps, and EXEC_ARBITRARY for everything else including an
// empty command.
func ClassifyCommand(cmd string) Class {
	c := strings.ToLower(strings.Join(strings.Fields(cmd), " "))
	if c == "" {
		return ExecArbitrary
	}
	if shellMeta.MatchString(c) {
		return ExecArbitrary
	}
	if blocklist.MatchString(c) {
		return ExecArbitrary
	}
	if configRead.MatchString(c) {
		return ReadConfig
	}
	if allowPrefix.MatchString(c) {
		return ReadOperational
	}
	return ExecArbitrary
}

// ClassifyCommands classifies a batch of commands with the downgrade rule:
// the result is EXEC_ARBITRARY if any command fails, READ_CONFIG if any
// command is a configuration read, and READ_OPERATIONAL only if every
// command passes. An empty batch is EXEC_ARBITRARY because there is nothing
// to prove safe.
func ClassifyCommands(cmds []string) Class {
	if len(cmds) == 0 {
		return ExecArbitrary
	}
	out := ReadOperational
	for _, c := range cmds {
		switch ClassifyCommand(c) {
		case ExecArbitrary:
			return ExecArbitrary
		case ReadConfig:
			out = ReadConfig
		}
	}
	return out
}
