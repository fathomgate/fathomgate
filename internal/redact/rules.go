package redact

import "regexp"

// Rule is one redaction pattern. Capture groups whose name begins with "s"
// are secrets and get replaced; everything else in the match is kept.
type Rule struct {
	// ID is the stable identifier written to Hit and to fixture expect files.
	ID string
	// Vendor groups the rule for humans: cisco, junos, eos, panos, fortios,
	// generic.
	Vendor string
	// Pattern must contain at least one capture group named s, s2, ...
	Pattern *regexp.Regexp
}

// DefaultRules is the ordered pattern list. Specific vendor rules come first
// so a line is attributed to the most precise rule; generic rules are last.
// Order matters within a family too: "neighbor X password 7 Y" must be
// claimed by the BGP rule before the bare password-type rule sees it.
var DefaultRules = []Rule{
	// Cisco IOS, IOS-XE, NX-OS (and EOS, which shares the grammar).
	{"cisco-bgp-neighbor-password", "cisco", regexp.MustCompile(`(?i)\bneighbor\s+\S+\s+password\s+(?:\d\s+)?(?P<s>\S+)`)},
	{"cisco-ospf-md5", "cisco", regexp.MustCompile(`(?i)\bmessage-digest-key\s+\d+\s+md5\s+(?:\d\s+)?(?P<s>\S+)`)},
	{"cisco-ospf-auth-key", "cisco", regexp.MustCompile(`(?i)\bospf\s+authentication-key\s+(?:\d\s+)?(?P<s>\S+)`)},
	{"cisco-key-string", "cisco", regexp.MustCompile(`(?i)\bkey-string\s+(?:\d\s+)?(?P<s>\S+)`)},
	{"cisco-aaa-server-key", "cisco", regexp.MustCompile(`(?i)\b(?:tacacs-server|radius-server)\s+(?:host\s+\S+\s+)?key\s+(?:\d\s+)?"?(?P<s>[^"\s]+)"?`)},
	{"cisco-server-key", "cisco", regexp.MustCompile(`(?i)^\s*key\s+\d\s+"?(?P<s>[^"\s]+)"?`)},
	// Known limitation: an NX-OS "snmp-server host X use-vrf management" line
	// with no community redacts the literal "use-vrf". Harmless and rare.
	{"cisco-snmp-community", "cisco", regexp.MustCompile(`(?i)\bsnmp-server\s+community\s+(?P<s>\S+)`)},
	{"cisco-snmp-host", "cisco", regexp.MustCompile(`(?i)\bsnmp-server\s+host\s+\S+(?:\s+(?:traps|informs|version\s+\S+|vrf\s+\S+|udp-port\s+\d+|use-vrf\s+\S+))*\s+(?P<s>\S+)`)},
	{"cisco-snmp-user", "cisco", regexp.MustCompile(`(?i)\bsnmp-server\s+user\s+.*?\bauth\s+(?:md5|sha|sha-256)\s+(?P<s>\S+)(?:\s+priv\s+(?:aes-128\s+)?(?P<s2>\S+))?`)},
	{"cisco-isakmp-key", "cisco", regexp.MustCompile(`(?i)\bcrypto\s+isakmp\s+key\s+(?:\d\s+)?(?P<s>\S+)`)},
	{"ntp-authentication-key", "cisco", regexp.MustCompile(`(?i)\bntp\s+authentication-key\s+\d+\s+(?:md5|sha1|sha2)\s+(?:\d\s+)?(?P<s>\S+)`)},
	{"cisco-password-type", "cisco", regexp.MustCompile(`(?i)\b(?:password|secret)\s+\d{1,2}\s+(?P<s>\S+)`)},

	// Arista EOS.
	{"eos-secret-sha512", "eos", regexp.MustCompile(`(?i)\b(?:secret|password)\s+(?:sha512|md5)\s+(?P<s>\S+)`)},

	// IKE pre-shared keys, shared grammar across Cisco, Junos and PAN-OS.
	{"ike-pre-shared-key", "generic", regexp.MustCompile(`(?i)\bpre-shared-key(?:\s+(?:local|remote|key|ascii-text|hexadecimal|\d))*\s+"?(?P<s>[^"\s;]+)"?`)},

	// Juniper Junos.
	{"junos-encrypted-password", "junos", regexp.MustCompile(`(?i)\bencrypted-password\s+"?(?P<s>[^"\s;]+)"?`)},
	{"junos-secret-data", "junos", regexp.MustCompile(`"(?P<s>[^"]+)"\s*;?\s*##\s*SECRET-DATA`)},
	{"junos-9-hash", "junos", regexp.MustCompile(`(?P<s>\$9\$[A-Za-z0-9./\-]+)`)},

	// Palo Alto PAN-OS.
	{"panos-phash", "panos", regexp.MustCompile(`(?i)\bphash\s+(?P<s>\S+)`)},
	{"panos-snmp-community", "panos", regexp.MustCompile(`(?i)\bsnmp-community-string\s+(?P<s>\S+)`)},
	{"panos-encrypted-value", "panos", regexp.MustCompile(`(?P<s>-AQ==[A-Za-z0-9+/=]+)`)},

	// Fortinet FortiOS.
	// The token alternative lets a second pass re-claim the line instead of
	// leaving "password ENC <token>" to the generic rule, which would redact
	// the literal "ENC".
	{"fortios-enc", "fortios", regexp.MustCompile(`\bENC\s+(?P<s>[A-Za-z0-9+/=]{16,}|<redacted:hmac:[0-9a-f]{12}>)`)},

	// Generic, last.
	{"unix-crypt-hash", "generic", regexp.MustCompile(`(?P<s>\$(?:1|5|6|2[aby]?|8|14)\$[A-Za-z0-9./$]+)`)},
	{"generic-keyword", "generic", regexp.MustCompile(`(?i)\b(?:password|passwd|secret|community|psk|passphrase|shared-secret|auth-key|api-key|token)(?:\s*[:=]\s*|\s+)"?(?P<s>[^"\s;]+)"?`)},
}

// RuleIDs returns the ids of the given rules in order.
func RuleIDs(rules []Rule) []string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}
