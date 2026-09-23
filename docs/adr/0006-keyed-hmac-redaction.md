# ADR 0006: Keyed HMAC redaction

- Status: accepted
- Date: 2026-09-23
- Deciders: Josh Scott

## Context

Device configs carry `enable secret`, SNMP communities, BGP and OSPF keys, TACACS and RADIUS keys, IKE pre-shared keys and VPN credentials. Of 25 surveyed network MCP servers, only netdev-ssh-mcp redacts secrets ([research brief 02](../research/02-network-mcp-servers.md)). Juniper's own Mist MCP docs warn that PSKs and RADIUS secrets can reach the assistant. Generic gateway redaction (Docker `--block-secrets`, Lasso Presidio) knows cloud tokens and PII, not `password 7` or `## SECRET-DATA`.

netdev-ssh-mcp replaces secrets with deterministic unsalted SHA-256 so the same secret compares equal across devices. That is useful for an operator checking consistency, but a type 7 string or a short SNMP community can be brute-forced from an unsalted hash.

A community post argues regex redaction fails open on unseen formats. That is true, and cannot be fully fixed by more regexes.

## Decision

We will run an ordered in-process regex list at the response serialiser, vendor patterns first and generic keyword and entropy patterns last, and replace each match with a keyed truncated HMAC-SHA256 token of the form `<redacted:hmac:3f9a…>` (12 hex characters).

- The key is per deployment and lives outside the log directory.
- The same secret yields the same token across devices in one deployment, so consistency checks still work.
- Redaction count and pattern ids, never values, go in the audit event.
- The vendor fixture corpus in `tests/fixtures/configs/` grows with every reported gap; gitleaks runs in CI over sampled stored outputs as a canary.
- Redaction runs on every tool result, including errors and elicitation text, because it sits in the serialiser and not in a per-tool handler.

Patterns are listed in [redaction-patterns.md](../specs/redaction-patterns.md).

## Consequences

### Positive

- Equality across devices without offline guessing.
- No path bypasses the redactor.
- A missed pattern is a bug report with a fixture, not a design change.

### Negative

- Regex fails open on an unseen format. Mitigated by the corpus, the CI canary, and an optional allow-list mode that only forwards output from known-safe show commands.
- The HMAC key is a secret the operator must keep. Key custody is an open question.
- Over-redaction can mask legitimate output (an interface description containing the word `password`). Accepted; false positives are visible, false negatives are not.

### Neutral

- `--no-redact` does not exist. Redaction is not optional.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Unsalted SHA-256 (netdev-ssh-mcp) | Brute-forceable for low-entropy secrets. |
| Random tokens per match | Loses cross-device equality that operators use to spot inconsistent keys. |
| Fixed mask (`********`) | Same loss, and hides whether two values differed. |
| gitleaks inline | Process per call; cloud-token-centric rules; no vendor grammar. Kept as the CI canary. |
| detect-secrets in-process | Python-only; would need the vendor patterns written anyway. |

## References

- [Research brief 02, redaction findings](../research/02-network-mcp-servers.md)
- [Research brief 03, section 4](../research/03-policy-and-approval-patterns.md)
- [netdev-ssh-mcp](https://github.com/krisiasty/netdev-ssh-mcp)
- [Cisco password types](https://community.cisco.com/t5/networking-knowledge-base/understanding-the-differences-between-the-cisco-password-secret/ta-p/3163238)
- [Junos passwords in configuration](https://junipertrain.wordpress.com/2016/10/19/junos-passwords-in-configuration/)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [Redaction fails open](https://dev.to/hex_tracker/redaction-fails-open-whitelist-your-mcp-tools-output-instead-3mpn)
