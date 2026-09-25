# ADR 0031: A hostname pattern never makes a target known; it only adds attributes to a device listed elsewhere

- Status: accepted
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer), accepted by the maintainer 2026-09-25 with the answers under *Decisions on the open questions*; proposed by network-safety-engineer (board task M1-34, from the security review of PR #154, findings H1 and H2); reviewers security-reviewer, policy-engineer
- Supersedes in part: [ADR 0007](0007-role-resolver-chain-sot-optional.md), provider row 2 only (dated row in its *Amendments*)
- Related: board task M1-37, its own record: an unset `defaults.unknown_target` denies every class (decision 4 below)

## Context

[ADR 0007](0007-role-resolver-chain-sot-optional.md) resolves a target name through a chain: static file, then hostname patterns, then the upstream's own inventory (M2), then a source of truth (M2). The first provider to hit wins, and a name no provider resolves is `unknown`, which the unknown-target default decides before the rules run.

`internal/inventory/patterns.go` `Resolve` returns `known: true` (with `Status: "pattern"`) for any name that matches any pattern. The name comes from the agent, so a pattern turns off the unknown-target default for every string it matches, not just for devices that exist. The security review of PR #154 showed both halves ([threat model](../security/threat-model.md), row "Pattern-resolved target"):

- **Reads (H1).** With `^core-|^border-` active, `core-x.attacker.example` was a known `core` device and `get_config` was `allow` `reads-anywhere`. A free-form-host upstream (netdev-ssh-mcp) then logs in to that host with the operator's `DEVICE_PASSWORD` or SSH agent: a credential leak to a host the agent chose, plus unredacted config output until M2.
- **Writes (H2).** With `^lab-` adding `tags: [lab]`, `lab-ghost-99`, `LAB-core-rtr-01`, `lab-x@core-rtr-01` and `lab-leaf-01.evil` were known lab devices, and `lab-open`'s `lab-writes-free` allowed a write to each, with no dry run in M1 ([ADR 0026](0026-m1-policy-pipeline-at-dispatch.md) decision 1).

PR #154 mitigated the shipped example (no active pattern; every device listed by name) and rewrote [inventory-schema section 4](../specs/inventory-schema.md#4-hostname-patterns) to warn. The spec's original intent was that a pattern match alone never makes a target known; the code never did that. Two more facts shape the choice:

- Target-name validation (M1-18: `default:bad_arguments` for anything not a hostname or IP literal) rejects `lab-x@core-rtr-01` and names with whitespace or control characters, but `core-x.attacker.example` and `lab-ghost-99` are valid hostnames. Validation narrows the hazard; it cannot close it.
- Naming conventions are the main reason patterns exist ([PLAN.md](../PLAN.md) resolver table): an operator has a list of names (spreadsheet, IPAM export, the upstream's own inventory) with no role column, and the name encodes the role. None of the surveyed upstream inventories carries a role ([inventory-schema section 5](../specs/inventory-schema.md#5-upstream-inventory-provider)), so in M2 patterns are how an upstream-listed device gets one.

Hostname patterns and the unknown-target default are core ("Decides", [ADR 0020](0020-open-core-apache-2.md) M1 row), so whatever rule this record sets is core too.

## Decision

We will make hostname patterns attribute-only: a pattern never makes a target known on its own, and only fills in role, site and tags on a device that a name authority (static file or CSV import in M1; the upstream inventory and the source-of-truth snapshot in M2) has already listed.

1. **Two kinds of provider.** *Name authorities* decide whether a target is known: the static file (including what `fathomgate inventory import` writes), and in M2 the upstream `INVENTORY_READ` provider (its standing for writes is decided in the M2 upstream-provider ADR, decision 3 below) and the NetBox or Nautobot resolver or its snapshot. First authority to list the exact name wins, as in ADR 0007. *Enrichers* run only after an authority has hit: hostname patterns are the only enricher.
2. **Merge.** The authority's record wins every field it sets. Each matching pattern fills a field the record leaves empty (`role`, `site`; the first matching pattern in file order wins each field) and unions its `tags`. This is the merge [inventory-schema section 2](../specs/inventory-schema.md#2-resolver-chain) already describes and the code never implemented. A name no authority lists is `unknown`, whatever patterns it matches.
3. **Provenance.** `inventory.Target` gains a per-field source (spec section 1 already names `source`; values `static`, `pattern`, `upstream:<id>`, `netbox`, `nautobot`, `snapshot`). `Status` goes back to meaning device status and is never `pattern`. `fathomgate inventory resolve` prints which provider supplied each field. The audit event (M4) records the sources.
4. **No policy interface change.** `policy.Request` and `policy.Target` are unchanged; `Known` keeps its meaning (an authority listed the name). `Evaluate` is untouched and stays pure (invariant 1).
5. **A pattern that matches no listed device** is a warning when the inventory loads (`inventory: roles[<i>] "<match>": matches no listed device`) and an error in `fathomgate inventory lint`. It cannot resolve anything, and an operator who wrote it probably expected it to.
6. **The pattern shape does not change.** `roles:` entries keep `match`, `role`, `site`, `tags`. The anchoring advice in inventory-schema section 4 stays as good practice, but the hazard text is rewritten: with this decision a loose pattern can mislabel a listed device (accepted in ADR 0007), not admit a made-up one.
7. **ADR 0007.** This record supersedes ADR 0007's provider row 2 only ("hostname patterns" as a provider that can hit). The rest of ADR 0007 stands. When this record is accepted, ADR 0007 gets a dated pointer row in `Amendments`.

## Consequences

### Positive

- H1 and H2 close in general, not only in the shipped example: an agent cannot make a name known by choosing one that fits a naming convention. Only names an operator (or, from M2, the upstream or the source of truth) listed reach the rules.
- Patterns keep their real job: a CSV of 800 names and five patterns gives every device a role and site without editing 800 lines, and in M2 an upstream-listed device with no role gets one from its name.
- No interface change to `policy`; the fix is inside `internal/inventory` and its spec.
- Spec section 2 (merge, tags union) and the code agree for the first time.

### Negative

- A network that relied on patterns alone must now list its devices. Mitigated: `fathomgate inventory import devices.csv` takes the list from any spreadsheet or IPAM export, `inventory sync` (M2) from a source of truth, and the upstream provider (M2) from the server itself. v0.1.0 enforced nothing (`serve` refused `--inventory`), so nobody relied on it in production.
- Pattern-derived role and tags on a listed device can still unlock writes (for example `^lab-` tagging a listed `lab-core-01` that is really a core router). This is the misclassification ADR 0007 accepted; the operator vouched for the name. The maintainer confirmed this (decision 2 below).
- The chain grows a second pass (enrich after hit). Small, and tested below.

### Neutral

- M1-18 target-name validation remains necessary and complementary: it stops names such as `lab-x@core-rtr-01`, which an upstream's SSH layer may read as `user@host`, before resolution.
- Target alias drift (upa TOML, threat model) is unchanged: Fathomgate resolves names, not the address the upstream connects to. This decision does not make it worse; (b) and (c) would have, by giving roles to TOML names Fathomgate's inventory never listed.
- DNS search suffixes: matching stays exact on the string the upstream receives. `core-rtr-01.corp.example` is not `core-rtr-01` and is `unknown`, which fails closed. Under (b) or (c), `^core-` would have admitted any short name the proxy host's resolver completes through a search domain, including a wildcard record.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| (b) A pattern may make a target known for reads, but pattern-derived tags and roles never satisfy `device_tags` or `device_roles` for `WRITE_CONFIG`, `EXEC_ARBITRARY` or `LAB_LIFECYCLE` (carry `source: pattern` into `policy.Target`) | Closes H2 only. H1, the credential leak to an agent-chosen host on a read, is the more severe finding and stays open. It also changes `policy.Target` and puts a class list inside `Evaluate`'s matcher semantics, so the policy file no longer says everything about what is allowed. |
| (c) Keep today's behaviour behind a required per-pattern opt-in (`known: true`) | A flag that reproduces a documented credential leak, for a need CSV import already meets. Anyone who sets it has H1 and H2 back, and a copied example would carry it. |
| (a) with pattern-derived attributes barred from write rules | Declined by the maintainer (decision 2 below): it removes the main write-side use (tagging a listed lab range) and the name is already operator-vouched. |
| Validation only (M1-18) | `core-x.attacker.example` and `lab-ghost-99` are valid hostnames. |
| Drop hostname patterns | Loses role-by-naming-convention, which is how M2's upstream-listed devices would get a role at all. |

## Migration

- **File format:** none. `roles:` keeps its shape; its meaning narrows.
- **v0.1.0 users:** `fathomgate serve` refused `--inventory`, so no call was ever decided from a pattern. Only `fathomgate policy eval --inventory` and `inventory resolve` output change: a name matched only by a pattern now prints `unknown`. Anyone who copied the v0.1.0 `inventory.example.yaml` (which had `^core-|^border-`, `^lab-`, `^fw-` active) lists those devices by name or imports them from CSV; the load warning in decision 5 points at each pattern that now matches nothing.
- **CHANGELOG:** the implementing PR adds a `Changed` entry with this migration note (a pre-1.0 minor may change the inventory semantics with a note).
- **Docs in the implementing PR:** inventory-schema sections 1, 2 and 4, PLAN.md resolver row 2, the `inventory.example.yaml` comment block, and the threat-model row "Pattern-resolved target" (to mitigated, with the tests below as evidence).

## Tests the implementing task must add

In `internal/inventory` (tier 1, `-race`):

1. **Patterns alone resolve nothing.** An inventory with patterns `^core-|^border-` (role `core`), `^lab-` (tags `[lab]`), `^fw-` (role `firewall`) and no devices: `core-x.attacker.example`, `core-rtr-01.attacker.example`, `fw-evil.example`, `lab-ghost-99`, `LAB-core-rtr-01`, `lab-x@core-rtr-01`, `lab-leaf-01.evil` and `ghost-99` all return `known: false`.
2. **Same names with the shipped devices listed and those patterns active:** every name in test 1 is still unknown; `TestRepoExampleInventory` runs once with the commented-out pattern block enabled.
3. **Enrichment.** Listed `core-rtr-09` with no role gets `role: core`, source `pattern` for `role`, `static` for `name`; listed device with `role: access` matching `^core-` keeps `access`; two matching patterns: first wins `role`, tags union without duplicates; the listed record's tags are kept.
4. **`Status` is never `pattern`,** and `inventory resolve` prints a per-field source.
5. **Warning:** a pattern that matches no listed device logs the decision-5 warning at load and fails `inventory lint`.
6. **Fuzz:** `FuzzPatternsNeverResolveUnlisted`, for any string not in the static list, `Resolve` returns `known: false` whatever patterns are loaded.

In `cmd/fathomgate` and `policies/`:

7. `fathomgate policy eval --policy policies/examples/lab-open.yaml --inventory <testdata with ^lab- tagging lab> --server eos-mcp --tool push_config --class WRITE_CONFIG --target lab-ghost-99` is `deny` `default:unknown_target`; the same with a listed, untagged `lab-sw-09` is `allow` `lab-writes-free`.
8. Under `read-only.yaml` with `^core-` active: `--class READ_CONFIG --target core-x.attacker.example` is `deny` `default:unknown_target`.
9. The "pattern hazard" case in `policies/examples/lab-open.test.yaml` is rewritten: the policy test file cannot express a pattern, so it moves to test 7 and the policy case says what it is (a tagged, known target).
10. The M1-18 gate tests (with M1-33) carry the attacker names of test 1 from arguments to decision with a pattern-bearing inventory.

## Decisions on the open questions

Accepted by the maintainer, Josh Scott, on 2026-09-25, with these answers:

1. **Option (a): accepted.** A hostname pattern never makes a target known; it only adds attributes to a device a name authority lists. This record supersedes [ADR 0007](0007-role-resolver-chain-sot-optional.md) provider row 2 only, and ADR 0007 gets a dated row in its *Amendments*. The rest of ADR 0007 stands.
2. **Pattern-derived role and tags on a listed device: yes, they count for write rules.** A role or tag a pattern gives a device that a name authority lists may satisfy `device_roles` and `device_tags` for `WRITE_CONFIG`, `EXEC_ARBITRARY` and `LAB_LIFECYCLE`, because the operator listed the name. A stricter policy-level option (write-unlocking attributes must come from the authority's own record) may be proposed later in its own record; it would not change this decision.
3. **The upstream inventory listing (M2, provider 3) as a name authority for writes: decided in the M2 upstream-provider ADR,** together with the target alias drift cross-check. What an upstream returns is untrusted data (invariant 7). Until that record, this record's list of name authorities for M1 is the static file and CSV import.
4. **An unset `unknown_target`: decided separately.** The maintainer chose that an unset `defaults.unknown_target` denies every class, so a read to an unknown target no longer reaches the rules by default. That is board task M1-37, with its own record; this record does not change `Evaluate` and relies on M1-37 for the read half of an unknown target under a policy that omits the key.
5. **A pattern that matches no listed device: warning at load, error in `fathomgate inventory lint`** (decision 5), so a stale pattern never stops `serve`.
6. **Aliases: no `aliases:` field until someone asks.** Matching stays exact on the string the upstream receives, which fails closed: an operator who needs both the FQDN and the short name lists both.

## References

- [ADR 0007](0007-role-resolver-chain-sot-optional.md), [ADR 0020](0020-open-core-apache-2.md), [ADR 0026](0026-m1-policy-pipeline-at-dispatch.md)
- [inventory-schema](../specs/inventory-schema.md) sections 1, 2, 4, 5 and 7; [policy-schema section 4](../specs/policy-schema.md#4-evaluation-order)
- [Threat model](../security/threat-model.md), rows "Pattern-resolved target (reads and writes)" and "Target alias drift"
- Security review of PR #154 (H1, H2); [M1 board](../milestones/M1.yaml): M1-34 (this record), M1-18 (target-name validation), M1-33, M1-37 (an unset `unknown_target` denies every class)
- `internal/inventory/patterns.go`, `internal/inventory/resolver.go`
