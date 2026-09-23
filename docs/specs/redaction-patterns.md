# Redaction patterns

Normative specification for `internal/redact`. An ordered regex list runs at the response serialiser over every tool result. Vendor patterns run first, generic patterns last. Each match is replaced by a keyed, truncated HMAC-SHA256 token. Counts and pattern ids, never values, go to the audit event.

Decision record: [ADR 0006](../adr/0006-keyed-hmac-redaction.md). Fixture corpus: `tests/fixtures/configs/`.

## 1. Token format

```
<redacted:hmac:3f9a1b2c4d5e>
```

- `hmac` is `HMAC-SHA256(key, secret_bytes)` truncated to the first 12 lower-case hex characters.
- `key` is the per-deployment redaction key (32 random bytes) read from `redact.key_file` or the environment variable named by `redact.key_env`. Startup fails without one; there is no unkeyed mode.
- `secret_bytes` is the matched secret group only, not the whole line, so `password 7 0822455D0A16` on two devices yields the same token.
- The console renders the token as `hmac:3f9a1b2c4d5e` in the `ng-redacted` style. The CLI and audit blobs keep the angle-bracket form.

An operator who needs to compare a value against a known secret runs `netguard redact token <secret>` locally to get the token. There is no reverse operation.

## 2. Pattern table

Patterns are RE2. `S` marks the capture group that is replaced. Patterns are applied line by line to text content and to string values inside `structuredContent`. Example lines are sanitised fixtures, not real secrets.

### 2.1 Cisco IOS, IOS-XE

| Id | Regex | Example line | Notes |
| --- | --- | --- | --- |
| `cisco-enable-secret` | `(enable\s+(secret|password)(\s+\d+)?\s+)(?P<S>\S+)` | `enable secret 9 $9$abc...` | Types 0, 4, 5, 7, 8, 9 |
| `cisco-username-secret` | `(username\s+\S+(\s+privilege\s+\d+)?\s+(secret|password)(\s+\d+)?\s+)(?P<S>\S+)` | `username admin privilege 15 secret 5 $1$...` | |
| `cisco-type7` | `(\s(password|key|key-string)\s+7\s+)(?P<S>[0-9A-Fa-f]{4,})` | `key-string 7 0822455D0A16` | Type 7 is cleartext-equivalent |
| `cisco-hash-generic` | `(?P<S>\$(1|4|5|6|8|9|14)\$[A-Za-z0-9./$]+)` | `$14$xyz...` | Catches hashes on any line |
| `cisco-snmp-community` | `(snmp-server\s+community\s+)(?P<S>\S+)` | `snmp-server community s3cr3t RO` | |
| `cisco-snmp-user` | `(snmp-server\s+user\s+\S+\s+\S+\s+v3\s+(encrypted\s+)?auth\s+(md5|sha|sha-2\s+\d+)\s+)(?P<S>\S+)(\s+priv\s+\S+(\s+\d+)?\s+)(?P<S2>\S+)?` | `snmp-server user ops group v3 auth sha X priv aes 128 Y` | Two groups |
| `cisco-tacacs-radius-key` | `((tacacs|radius)(-server)?\s+(host\s+\S+\s+)?key(\s+\d+)?\s+)(?P<S>\S+)` | `tacacs-server key 7 ...` | Also `tacacs server X` / `key 7` sub-mode |
| `cisco-key-sub` | `(^\s*key(\s+\d+)?\s+)(?P<S>\S+)$` | ` key 7 ...` inside `tacacs server` block | Anchored to sub-mode indentation |
| `cisco-bgp-password` | `(neighbor\s+\S+\s+password(\s+\d+)?\s+)(?P<S>\S+)` | `neighbor 10.0.0.1 password 7 ...` | |
| `cisco-ospf-md5` | `(ip\s+ospf\s+message-digest-key\s+\d+\s+md5(\s+\d+)?\s+)(?P<S>\S+)` | | |
| `cisco-isakmp-key` | `(crypto\s+isakmp\s+key(\s+\d+)?\s+)(?P<S>\S+)` | | |
| `cisco-ikev2-psk` | `((local|remote)\s+)?(pre-shared-key(\s+(local|remote))?(\s+\d+)?\s+)(?P<S>\S+)` | | |
| `cisco-ntp-key` | `(ntp\s+authentication-key\s+\d+\s+md5\s+)(?P<S>\S+)` | | |
| `cisco-hsrp-vrrp-auth` | `((standby|vrrp)\s+\d+\s+authentication(\s+(md5\s+key-string|text))?(\s+\d+)?\s+)(?P<S>\S+)` | | |
| `cisco-wpa-psk` | `(wpa-psk\s+(ascii|hex)(\s+\d+)?\s+)(?P<S>\S+)` | | |

### 2.2 Cisco NX-OS

| Id | Regex | Example line |
| --- | --- | --- |
| `nxos-username-password` | `(username\s+\S+\s+password\s+\d+\s+)(?P<S>\S+)` | `username admin password 5 $5$...` |
| `nxos-snmp-user` | `(snmp-server\s+user\s+\S+\s+\S+\s+auth\s+(md5|sha)\s+)(?P<S>\S+)(\s+priv(\s+aes-128)?\s+)(?P<S2>\S+)` | `snmp-server user ops network-admin auth md5 0x... priv 0x...` |
| `nxos-key-chain` | `(key-string(\s+\d+)?\s+)(?P<S>\S+)` | ` key-string 7 ...` |
| `nxos-feature-keys` | `((tacacs-server|radius-server)\s+(host\s+\S+\s+)?key(\s+\d+)?\s+)(?P<S>\S+)` | |

`cisco-hash-generic` and `cisco-bgp-password` also apply to NX-OS.

### 2.3 Junos

| Id | Regex | Example line | Notes |
| --- | --- | --- | --- |
| `junos-secret-data` | `(\S+\s+)(?P<S>"?\$(1|5|6|8|9)\$[^"\s;]+"?)(;\s*##\s*SECRET-DATA)` | `encrypted-password "$6$..."; ## SECRET-DATA` | The marker is the anchor |
| `junos-encrypted-password` | `(encrypted-password\s+)(?P<S>"[^"]+")` | | Without marker, `display set` form |
| `junos-type9` | `(?P<S>"?\$9\$[A-Za-z0-9./-]+"?)` | `authentication-key "$9$..."` | Reversible; covers protocol keys, RADIUS, TACACS, SNMP |
| `junos-hash-generic` | `(?P<S>\$(1|5|6|8)\$[A-Za-z0-9./$]+)` | | |
| `junos-set-form` | `(set\s+.*(authentication-key|pre-shared-key|secret|community|key|encrypted-password|password)\s+)(?P<S>"[^"]+"|\S+)` | `set snmp community public authorization read-only` | `display set` output |
| `junos-community` | `(^\s*community\s+)(?P<S>\S+)(\s*\{)` | `community public {` | Braced form |

### 2.4 Arista EOS

| Id | Regex | Example line |
| --- | --- | --- |
| `eos-username-secret` | `(username\s+\S+(\s+privilege\s+\d+)?(\s+role\s+\S+)?\s+secret\s+(sha512|5|0|7)?\s*)(?P<S>\S+)` | `username admin privilege 15 role network-admin secret sha512 $6$...` |
| `eos-enable-password` | `(enable\s+password\s+(sha512|5|0|7)?\s*)(?P<S>\S+)` | |
| `eos-type7` | `(\s(password|key)\s+7\s+)(?P<S>\S+)` | `neighbor 10.0.0.1 password 7 ...` |
| `eos-server-key` | `((tacacs-server|radius-server)\s+(host\s+\S+\s+)?key\s+(7\s+)?)(?P<S>\S+)` | |
| `eos-ospf-md5` | `(ip\s+ospf\s+message-digest-key\s+\d+\s+md5\s+(7\s+)?)(?P<S>\S+)` | |
| `eos-snmp-community` | `(snmp-server\s+community\s+)(?P<S>\S+)` | |
| `eos-ssl-key` | `(?P<S>-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)` | Multi-line; applied to whole content |

`cisco-hash-generic` also applies to EOS.

### 2.5 PAN-OS

| Id | Regex | Example line |
| --- | --- | --- |
| `panos-phash` | `(<phash>|phash\s+)(?P<S>[^<\s]+)` | `<phash>$1$...</phash>` |
| `panos-psk` | `(pre-shared-key\s+(key\s+)?|<key>)(?P<S>[^<\s]+)` | `pre-shared-key key -AQ==...` |
| `panos-secret-element` | `(<(secret|password|api-key|bind-password|private-key)>)(?P<S>[^<]+)` | XML form |
| `panos-secret-set` | `(set\s+.*\s(secret|password|api-key|bind-password|community)\s+)(?P<S>\S+)` | Set form |
| `panos-aq-blob` | `(?P<S>-AQ==[A-Za-z0-9+/=]{16,})` | Encrypted blob marker |

### 2.6 FortiOS

| Id | Regex | Example line |
| --- | --- | --- |
| `fortios-enc` | `(\bENC\s+)(?P<S>[A-Za-z0-9+/=]{16,})` | `set password ENC AbC...==` |
| `fortios-plain-secret` | `(set\s+(password|passwd|psksecret|secret|community|key|auth-password|priv-password)\s+)(?P<S>"[^"]+"|\S+)` | `set community "public"` |
| `fortios-private-key` | Same as `eos-ssl-key` | |

### 2.7 Nokia SR Linux, Cisco IOS-XR

| Id | Regex | Notes |
| --- | --- | --- |
| `srlinux-password` | `(password\s+)(?P<S>\$\d\$\S+|"[^"]+")` | |
| `srlinux-community` | `(community\s+)(?P<S>\S+)` | |
| `iosxr-secret` | `((secret|password)(\s+\d+)?\s+)(?P<S>\S+)` | Plus `cisco-hash-generic`, `cisco-tacacs-radius-key` |

### 2.8 Generic, last

| Id | Regex | Notes |
| --- | --- | --- |
| `generic-keyword` | `(?i)((password|passwd|secret|token|api[_-]?key|community|psk|pre-shared-key)\s*[:=]\s*)(?P<S>"[^"]+"|\S{6,})` | Key-value forms in any output |
| `generic-private-key` | PEM block, as `eos-ssl-key` | |
| `generic-jwt` | `(?P<S>eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})` | |
| `generic-entropy` | Tokens of 24 or more `[A-Za-z0-9+/=_-]` characters with Shannon entropy above 4.0 bits per character, on a line that also matches `(?i)(key|secret|token|password|hash)` | Guarded to limit false positives on hashes and MAC tables |

## 3. Ordering and overlap

Patterns run in the order listed: vendor-specific tables for the resolved `vendor` first, then every other vendor table, then generic. A match consumes its span; later patterns do not re-match inside a token. Ordering matters where a specific pattern preserves more context than a generic one (`cisco-type7` keeps `password 7` visible while `generic-keyword` would not).

When `vendor` is unknown, all vendor tables run in the order of section 2.

## 4. Where redaction runs

- In `internal/proxy`'s response serialiser, on every `tools/call` result: `content[].text`, string leaves of `structuredContent`, and `isError` messages.
- On elicitation and `input_required` text forwarded from upstreams.
- On the diff before it enters the pending record or blob store, after `DiffHash` is computed.
- On `args_redacted` in the audit event.

Redaction does not run on `tools/list` descriptions; those are pinned and quarantined instead ([ADR 0008](../adr/0008-dual-era-mcp-support.md)).

## 5. Allow-list mode

`redact.mode: allowlist` forwards output only from `READ_OPERATIONAL` calls whose command matches `redact.allowlist_commands` (default: the `show` families for interfaces, bgp, ospf, route, version, lldp, arp, mac, log). Any other output is replaced by `<redacted:output-withheld rule=allowlist>` and the full redacted output is stored in the blob store for an operator to release. This mode is off by default and exists for shops that consider regex redaction insufficient.

## 6. Fixture corpus

`tests/fixtures/configs/<vendor>.cfg` holds one sanitised configuration per platform. Every secret-bearing line carries a trailing comment with the pattern id expected to catch it, in the vendor's comment syntax:

```
username admin privilege 15 secret 9 $9$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa   ! ng:cisco-username-secret
snmp-server community s3cr3t RO   ! ng:cisco-snmp-community
```

Tier 1 tests load every fixture, run the redactor, and assert that every annotated line was changed by exactly the named pattern, that no unannotated line was changed, and that the count matches. A new pattern requires a new annotated fixture line. A redaction gap report ([issue template](../../.github/ISSUE_TEMPLATE/redaction_gap.yml)) supplies the line shape with the secret replaced, never the secret itself.

Gitleaks runs in CI over a sample of blob-store outputs from tier 2 as a canary; a finding there is a test failure.
