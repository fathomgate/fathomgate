# Draft upstream issue: keyed hash for netdev-ssh-mcp obfuscation

Status: **draft, not filed** (T0.29, 2026-09-23). A maintainer decides
whether and when to file it at https://github.com/krisiasty/netdev-ssh-mcp/issues.
Everything below the rule is the proposed issue text. It uses only `FAKE`
values and placeholder names.

---

**Title:** Obfuscation hash is unkeyed, and some patterns hash a keyword instead of the secret

**Version:** v1.6.6 (`be3e36342b0c71007ce416a435dfdfecc966ea13`), `internal/netdev/obfuscate.go`

Thanks for obfuscating secrets by default. It is the only SSH MCP server we
surveyed that does. We found two things while testing it behind a proxy.

### 1. The hash can be reversed for short values

`hashSecret` returns `[h:` + hex(`sha256(value)[:6]`) + `]` with no key. Anyone
who has the tool output can hash a word list and compare. Common SNMP
communities and type-7 strings fall at once:

```
$ printf public  | shasum -a 256 | cut -c1-12   # efa1f375d761
$ printf private | shasum -a 256 | cut -c1-12   # 715dc8493c36
```

**Suggestion:** use HMAC-SHA256 with a key, and keep the `[h:<12 hex>]` shape:

- read the key from a file or an env var (for example `--obfuscate-key-file`
  or `OBFUSCATE_KEY`), so tokens stay stable across runs and devices for
  anyone who shares the key;
- if no key is set, generate a random one at startup. Tokens then still
  compare equal within one process, which is the diffing use case, but they
  cannot be looked up offline.

This is a small change in `hashSecret` (`crypto/hmac` is in the standard library).

### 2. Some lines keep the secret in clear

The optional type group in some patterns accepts only a digit, or appears
before the algorithm keyword. So the regex captures a keyword and the real
value is left in the suffix:

| Input line (FAKE values) | Output today |
|---|---|
| `username admin role network-admin secret sha512 $6$FAKEsalt$FAKEhash` | `... secret [h:a396244643b5] $6$FAKEsalt$FAKEhash` |
| `ntp authentication-key 1 md5 7 FAKEntpKey` | `... md5 [h:7902699be42c] FAKEntpKey` |
| `ip ospf message-digest-key 1 md5 7 FAKEospfKey` | `... md5 [h:7902699be42c] FAKEospfKey` |
| `key-string 7 FAKEkeyString` | `key-string [h:7902699be42c] FAKEkeyString` |
| `pre-shared-key ascii-text "$9$FAKEpsk"; ## SECRET-DATA` (Junos) | `pre-shared-key [h:cddba75c4762] "$9$FAKEpsk"; ...` (the IOS IKEv2 pattern matches before the Junos one) |

These lines are not matched at all:

- `snmp-server host 192.0.2.50 version 2c FAKEcommunity`
- NX-OS `radius-server host 192.0.2.41 key 7 "FAKEkey" authentication accounting`
- NX-OS `snmp-server user admin network-admin auth md5 0xFAKEauth priv 0xFAKEpriv localizedkey`: the `priv` value
- Junos `secret "$9$FAKE..."; ## SECRET-DATA` under `tacplus-server` / `radius-server`
- Junos `authentication-key 1 type md5 value "$9$FAKE..."` (NTP)
- Junos `set`-format output, for example `set system radius-server 192.0.2.42 secret "$9$FAKE..."`

**Suggestions:**

- allow `(?:\s+(?:\d+|sha\d+|md5))?` before the value where a type or
  algorithm token can appear;
- put the Junos `pre-shared-key ascii-text` pattern before the IOS one, or
  exclude `ascii-text|hexadecimal` from the IOS capture;
- add a catch-all for Junos `## SECRET-DATA` lines (a quoted string followed by
  `## SECRET-DATA`) and for `$9$` values, which covers both formats;
- add a table-driven `obfuscate_test.go`. There is none at this tag. We are
  happy to contribute our FAKE fixture configs for EOS, IOS-XE, NX-OS and Junos.
