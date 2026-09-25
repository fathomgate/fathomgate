# ADR 0035: Policy test cases that carry arguments run the gate path

- Status: proposed
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer), to decide; proposed by policy-engineer (board task M1-33, from the security reviews of PR #152 and PR #154); reviewers security-reviewer, go-reviewer
- Amends (when accepted): [policy-schema.md](../specs/policy-schema.md) sections 7 and 9; the `fathomgate policy test` and `fathomgate policy eval` CLI surface

## Context

A `*.test.yaml` case ([policy-schema section 7](../specs/policy-schema.md#7-test-file-format)) gives the class and the resolved targets directly, and `fathomgate policy test` passes them straight to `policy.Evaluate`. The 45 shipped cases therefore prove what the rules do with a class. They do not prove that a real command gets that class, or that a real host name resolves the way the case assumes. The security reviews found two gaps:

- **PR #152 (classification).** The injection inputs it fixed cannot be written as a test case. These are `show clock` followed by a line break and `conf t`, control and look-alike characters, shell-quoted options, and config dumps through short forms. A case can only say `class: READ_OPERATIONAL`, and that is exactly the input the bug got wrong.
- **PR #154 (inventory).** Attacker-chosen names such as `core-x.attacker.example` and `lab-ghost-99`, under an inventory with hostname patterns, cannot be written either. A case sets `known` itself, so ADR 0031's rule that a pattern never makes a name known is proved only in Go.

Test-matrix rows 3, 4 and 6 are M1's exit criteria, and M1 exit criterion 2 is "policy test suite green". Today those rows hold at the policy level only. Their classification half is pinned in `internal/classify` and `internal/gate` Go tests that a contributor who reads only the policy suite never sees. `serve` runs a longer path than `Evaluate`: `internal/gate` `Decide` parses the arguments, applies the per-call caps, normalises, classifies (with the annotation raise), checks the closed argument list, validates and resolves targets, then calls `Evaluate` ([ADR 0026](0026-m1-policy-pipeline-at-dispatch.md) steps 1 to 6). `fathomgate policy eval --profile ... --arg ...` re-implements part of that path in `cmd/fathomgate/policy.go`. It calls `classify.Classify`, `gate.ValidTargetName` and `inventory.Known`, but skips the parse checks, the caps, the group and zero-target refusals and the annotation raise. So it can show a different decision from the one `serve` makes.

The test-file schema is a spec interface, and `policy test` is a CLI surface, so a change to either needs a record (CLAUDE.md, *How work moves*).

## Decision

We will let a `*.test.yaml` case carry a server, tool and raw arguments instead of a class and targets. Such a case runs through `internal/gate` `Decide`, the same method `serve` calls. Its profiles come from the embedded set or `--profiles`, as `serve` loads them. Its inventory comes from the test file. It can assert everything the gate decides before `Evaluate`. Existing cases keep running exactly as today.

### 1. Two kinds of case, told apart by their fields

| Kind | Marked by | Runs | Unchanged? |
| --- | --- | --- | --- |
| **Class-given case** | `request.class` | `policy.Evaluate` on the request as written, as today | Yes. All 45 shipped cases are of this kind |
| **Gate case** | `request.arguments` or `request.arguments_json` (`arguments: {}` for a call with none) | `gate.Decide` on a `seam.CallInfo` built from the case, with the file's inventory and the run's profile set | New |

A case that gives both `class` and an arguments field is a load error, and so is one that gives neither. A gate case may not give `targets`, because the gate derives them from the arguments and resolves them through the inventory. Refusing both fields at load means no case can pass on inputs the gate never sees.

### 2. New fields

File level (both optional):

| Field | Type | Meaning |
| --- | --- | --- |
| `inventory` | string or mapping | A path (relative to the test file, like `policy`) to an inventory in the [inventory-schema section 3](../specs/inventory-schema.md#3-static-file) format, or the same document inline. It is read and parsed exactly as `serve --inventory` reads and parses it: `internal/configfile` checks for the path form, strict decoding, `version: 1` required, and a `.csv` refused with a pointer to `inventory import`. It is then built into the same `inventory.Chain`, so patterns enrich and never make a name known (ADR 0031). Without it, every name a gate case sends is unknown, as under `serve` without `--inventory`. Class-given cases ignore it. |

Gate case, under `request`:

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `server` | string | yes | The profile's server key. It must name a profile in the run's set (section 3). |
| `tool` | string | yes | The upstream's own tool name, without the prefix. It is looked up exactly, as `Decide` looks it up. A tool the profile does not list is allowed, and the case then asserts the refusal. |
| `arguments` | mapping | one of the two | The arguments object. The runner encodes it with `encoding/json`, and those bytes become `CallInfo.Arguments`. Values may be strings, numbers, booleans, null, lists and mappings. A non-string key, a YAML merge key (`<<`), or a value of any other YAML type (timestamp, binary) is a load error. A YAML double-quoted string carries `\n`, `\t`, `​` and other escapes, so the PR #152 inputs can be written here. |
| `arguments_json` | string | one of the two | The arguments exactly as the agent's bytes, passed through unchanged. This is for inputs a YAML mapping cannot hold: a duplicated key, trailing data, a top-level array, invalid JSON. |
| `annotations` | mapping | no | `readOnlyHint` and `destructiveHint`, each a boolean. Absent means nil, as for an upstream that sends none. This lets a case prove the raise to `EXEC_ARBITRARY` (invariant 3). |
| `session` | mapping | no | `devices_touched` and `pending_holds`, as today. `CallInfo.Counted` is nil, so the case's targets count as new devices. |

A gate case whose encoded arguments exceed 64 KiB is a load error. The proxy refuses such a call before the gate runs (ADR 0026, *Argument cap*), so the gate path cannot say what `serve` would do with it.

Under `expect`, beside `effect`, `rule` and `obligations` (unchanged, and still valid for both kinds):

| Field | Kind | Asserts, from the `seam.Verdict` of `Decide` |
| --- | --- | --- |
| `class` | gate | The final class (`Verdict.Class`), after downgrade, reclassify and the annotation raise |
| `class_source` | gate | `profile`, `capability_table`, `fallback`, `annotation_raise`, `downgrade` or `reclassify` |
| `targets` | gate | The target names after validation, exactly as the upstream receives them, in order (`Verdict.Targets`). `[]` asserts none |
| `unknown_target` | gate | The decision log line's `unknown_target` |
| `parse_error` | gate | The log line's fixed code: `invalid_utf8`, `invalid_json`, `not_object`, `duplicate_key`, `trailing_data`, `too_many_commands`, `too_many_targets` |
| `unnamed_args`, `malformed_args` | gate | The log line's lists, compared as sets |
| `forwarded` | gate | `Verdict.Forward`: whether `serve` in this milestone would send the call upstream. For example, `false` for an `allow` that carries `dry_run` in M1 |
| `tool_error` | gate | `Verdict.Error`, the one line the agent sees, compared exactly. `""` asserts that there is none |

`effect` is `Verdict.Effect`, which is what `Evaluate` returned, or `deny` for a refusal before it. A `hold` therefore stays `hold`, as ADR 0026 records it. `obligations` and the three log-line fields come from `Verdict.Record` by attribute name, and the runner reads nothing else from the record. Using a gate-only field on a class-given case is a load error. So is a `parse_error`, `unnamed_args` or `malformed_args` with a `rule` other than `default:bad_arguments`, because such a case could never pass.

A failing case reports the first mismatch in this order: effect, rule, class, class_source, obligations, targets, unknown_target, parse_error, unnamed_args, malformed_args, forwarded, tool_error. It names what the runner got and what the case wanted, as today.

### 3. Profiles: the run's set, as `serve` chooses it

A gate case never names a profile file. By default the run uses the profiles embedded in the binary, the same set `serve` uses without `--profiles`. `fathomgate policy test --profiles <dir> <file>...` replaces that set for the whole run. It never merges with it, as in [ADR 0027](0027-serve-policy-inventory-profiles-flags.md). The set is loaded by the same function `serve` calls: every top-level `*.yaml`, strict, validated, each file named after its server key, and the `configfile` checks for `--profiles`. That function moves out of `cmd/fathomgate/serve_policy.go` so that both commands call it.

This means the shipped suites prove the shipped binary's profiles, and an operator can prove a patched profile set against the shipped suites before running `serve --profiles` with it.

A gate case whose `server` has no profile in the set is a load error that names the server and the set (`embedded` or the directory). `serve` would give that server an empty profile. The call would then be `default:bad_arguments` for any argument, and a case expecting a deny would pass for the wrong reason (open question 3).

### 4. Asserting the refusals before `Evaluate`

| To prove | Write |
| --- | --- |
| Arguments the gate cannot parse | `arguments_json` with the bytes; `expect: {effect: deny, rule: default:bad_arguments, parse_error: duplicate_key}` (or `invalid_json`, `not_object`, `trailing_data`) |
| A per-call cap | An `arguments` list of 65 commands or 257 targets; `parse_error: too_many_commands` or `too_many_targets` |
| An unnamed or refused argument (ADR 0033) | `arguments: {hostname: lab-sw-01, config_path: /proc/self/environ}`; `rule: default:bad_arguments, unnamed_args: [config_path]` |
| A malformed target, command or config argument | `rule: default:bad_arguments, malformed_args: [hostnames]` |
| A bad target name, a group or tag selector, or no target | `rule: default:bad_arguments` and `tool_error` with the fixed text. These three causes have no log-line code (open question 8) |
| An unknown target, for a read or a write | `arguments` naming the host; `expect: {effect: deny, rule: default:unknown_target, unknown_target: true, targets: [core-x.attacker.example]}` |
| `invalid_utf8` | Not in a test file: YAML text is valid UTF-8, and a JSON `\u` escape decodes to valid UTF-8. It stays in the `internal/gate` Go tests (open question 6) |

`default:internal_error` (proxy only) and the 64 KiB `too_large` refusal (proxy only) are outside the gate and are not assertable here. The proxy's own tests pin them.

### 5. Backward compatibility

- Every key a file uses today keeps its meaning, and no key becomes required. The 45 cases run through `Evaluate` exactly as now, with the same output and the same exit status. `policy test` without `--profiles` needs nothing new.
- A file written for this schema fails to load on an older binary. It fails loudly (unknown key), never silently, because the decoder stays strict.
- `tools/policy-lint` (Python) skips `*.test.yaml` today and still does.
- `make policy-test` keeps its glob. `TestRepoExamplePolicies` moves with the runner (section 7), so `go test ./...` still runs every shipped suite, gate cases included.

### 6. `fathomgate policy eval`

`policy eval` has two modes today, and this record keeps them. The class-given mode (`--class`, `--target`) is unchanged. The `--profile` mode moves onto the gate path: the flags build a `seam.CallInfo`, and the same function the runner uses decides it, with the profile file as a set of one keyed by its server. After this change, `eval --profile` and a gate case with the same inputs cannot disagree, and neither can disagree with `serve`. In that mode:

- `--class` and `--target` become usage errors (exit 2), because the gate computes both, as in section 1. Today `--class` silently overrides the profile's class.
- `--server`, if given, must equal the profile's server key.
- A new `--arguments-json '<json>'` gives the arguments as bytes, for the inputs `--arg key=value` cannot express (open question 7). `--arg` and `--arguments-json` are exclusive.
- The output keeps its order (decision, class, target, rule, reason) and exit codes (0 allow, 1 deny, 3 hold). It adds `class_source`, `parse_error` when set, and the tool error line the agent would see.

### 7. Where the code lives

`internal/gate` imports `internal/policy`, so a runner that calls `Decide` cannot live in `internal/policy`. The file format and the runner, for both kinds of case, move to a new package `internal/policytest`, which imports `policy`, `gate`, `classify`, `inventory` and the shared profile-set loader. `internal/policy` keeps `Evaluate`, `Load` and nothing about test files. `Evaluate` does not change and stays pure (invariant 1). `internal/gate` gains no export: the runner calls `gate.New` and `Decide` as the proxy's wiring does.

### 8. Output

`policy test` prints no argument value, and it never prints a case name or an argument name raw. It quotes both with `strconv.QuoteToASCII` when they are not printable ASCII, as `inventory resolve` does. The reason is that a suite carrying the PR #152 inputs is itself the injection text. With `-v`, a failing gate case also prints its class, class_source and the rule trace.

### 9. What the implementing task adds

- The cases M1-33 asks for, in the shipped suites: rows 3, 4 and 6 through each profile they name (netdev-ssh-mcp `run_show_command`; upa `send_command_and_get_output`; eos-mcp `run_command`), the PR #152 injection inputs from the threat-model rows, and the PR #154 names under an inventory with active patterns (ADR 0031 test 10). Also: the `show running-config` reclassify to `READ_CONFIG` through ntunes `send_command`, and `config_path` on eos-mcp.
- Tests of the runner in `internal/policytest`, one per load error in sections 1 to 3, and a test that `policy eval --profile` and a gate case give the same verdict on shared inputs.
- policy-schema sections 7 and 9 rewritten. Section 9's sentence "a case cannot carry arguments or commands" goes. `docs/testing/test-strategy.md` records gate cases as tier 1 evidence. The glossary and the CHANGELOG `Unreleased` entry are updated.

Gate cases are tier 1 evidence. A test-matrix row is marked validated only against the named real upstream (CLAUDE.md), so M1-28 still has to run rows 3, 4 and 6 through `serve` against the real servers.

Example, in `policies/examples/` (the downgrade half of row 3 and row 4 through upa, and row 6 through netdev-ssh-mcp):

```yaml
policy: read-only.yaml
inventory: ../../inventory.example.yaml
cases:
  - name: show ip bgp summary on upa is downgraded to a read
    request:
      server: upa
      tool: send_command_and_get_output
      arguments: {name: lab-sw-01, command: show ip bgp summary}
    expect: {effect: allow, rule: reads-anywhere, class: READ_OPERATIONAL, class_source: downgrade, forwarded: true}

  - name: row 4, reload after a line break is not a read
    request:
      server: upa
      tool: send_command_and_get_output
      arguments: {name: lab-sw-01, command: "show clock\nreload"}
    expect:
      effect: deny
      rule: no-exec
      class: EXEC_ARBITRARY
      tool_error: "fathomgate denied upa.send_command_and_get_output: rule no-exec (class EXEC_ARBITRARY): EXEC_ARBITRARY is denied: the call runs commands outside the read allow-list or outside configuration mode"

  - name: row 6, an attacker-chosen host is unknown even for a read
    request:
      server: netdev-ssh-mcp
      tool: run_show_command
      arguments: {host: core-x.attacker.example, command: show version}
    expect: {effect: deny, rule: default:unknown_target, unknown_target: true, targets: [core-x.attacker.example]}
```

## Consequences

### Positive

- Rows 3, 4 and 6 are proved in the policy suite from the command the agent sends, so M1 exit criterion 2 ("policy test suite green") covers classification and resolution, not only the rules.
- The PR #152 and PR #154 regressions can be written by anyone who can write YAML, and each is visible next to the rule it tests.
- `serve`, `policy test` and `policy eval --profile` decide through one function, so the drift already present in `eval` (no caps, no group or zero-target refusal, no annotation raise) goes away.
- A patched profile set can be checked against the shipped suites before it is deployed.

### Negative

- A profile change can now fail a policy suite. That is intended, but it means a profile PR runs `make policy-test` as well as the classify tests.
- `tool_error` assertions pin the agent-facing text. ADR 0026 already makes the first line an interface, and a copy change then touches the suites too. Cases should use `tool_error` where the text is the point (rows 4 and 6, the three uncoded refusals) and `rule` everywhere else.
- The runner reads `obligations`, `unknown_target`, `parse_error`, `unnamed_args` and `malformed_args` from the decision log line by name, so renaming one breaks the suites. These are the M4 audit event's fields and should not be renamed casually anyway.
- One more package, and the profile-set loader moves out of `cmd/fathomgate`.

### Neutral

- `policy.Decision`, `policy.Request`, `Evaluate`, the class and obligation sets, and the `seam` types do not change.
- `invalid_utf8` and the proxy-only refusals stay in Go tests.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| A `profile: <file>` path on each case (the M1-33 note's sketch) | Lets a suite pass against a profile `serve` would not load (wrong file name, a second profile for the same server). The run's set, chosen as `serve` chooses it, proves what ships. |
| A separate runner that calls `classify` and `inventory` directly, like today's `eval --profile` | That is a second implementation of the gate, and it has already drifted. One function is the only way `test`, `eval` and `serve` stay in agreement. |
| Put the runner in `internal/policy` behind an interface the gate satisfies | Moves gate knowledge into the pure package's API, for no gain over a small package of its own. |
| Assert the rule trace | The trace describes the whole policy, and a rule added above would change every case. `rule` and the gate fields assert the decision without pinning unrelated rules. |
| Assert the three uncoded target refusals by a new log-line code | Changes the ADR 0026 decision line and the future audit event. `tool_error` asserts the same thing with no new field (open question 8). |
| Keep gate-level cases in Go only | Contributors without Go, and reviewers reading `policies/`, then cannot see or add them. The M1-33 finding is exactly that the suite does not show them. |

## Open questions for the maintainer

Each has a recommendation. Accepting the record with no answer means accepting the recommendation.

1. **Profile choice per run, not per case or per file.** Should a test file be able to name a profile directory itself? *Recommendation: no.* The embedded set, or `--profiles` for the whole run, as `serve` works. A third-party profile author runs `policy test --profiles <dir>`.
2. **Inventory in the file, not on the command line.** Should `policy test` also take `--inventory`? *Recommendation: no.* A case's expectation depends on its inventory, so the inventory belongs with the case. A flag would let the same file pass or fail depending on how it was run. Profiles are different: they are the product's shipped data, and `serve` has a default set, while `serve` has no default inventory.
3. **A gate case naming a server with no profile in the set.** Load error, or `serve`'s empty profile? *Recommendation: load error.* The empty profile makes every argument-bearing call `default:bad_arguments`, so a deny case would pass whatever it meant to test. `serve`'s behaviour for an unprofiled server stays pinned in `serve_policy_test.go`.
4. **Require `expect.rule` on gate cases.** *Recommendation: yes.* Because the gate fails closed, `effect: deny` alone passes for any refusal. Class-given cases stay optional for compatibility; `policy-lint` can warn on them later.
5. **Where the new cases go.** Append to the three `*.test.yaml` files, or add sibling files such as `read-only.gate.test.yaml`? *Recommendation: sibling files.* The 45 cases stay byte for byte unchanged, the file-level `inventory` applies only where it is used, and `make policy-test`'s glob already picks the new files up.
6. **`invalid_utf8` in a test file.** Add an `arguments_base64` field for bytes that are not UTF-8? *Recommendation: no.* It is one code, already covered in `internal/gate` tests, and a binary field in a human-read suite hides what it tests.
7. **`policy eval --arguments-json`.** Add it with the gate move in section 6? *Recommendation: yes.* An operator can then reproduce any gate case with one command. The `--class`/`--target` usage errors under `--profile` come with it, since today `--class` silently overrides the profile's class. No annotation flags on `eval` yet; the suites cover the raise.
8. **A code for the three target refusals** (bad name, group selector, no target) in the decision log line. *Recommendation: not now.* `tool_error` asserts them, and a new log field belongs with the M4 audit-event schema, where a `refusal` code for every `default:bad_arguments` cause could be decided at once.
9. **`configfile` checks when `policy test` reads a profile directory or an inventory path.** *Recommendation: yes, as `serve`, `inventory lint` and `inventory resolve` do.* Then a file `serve` would refuse cannot pass a suite. CI checkouts and ordinary working copies meet the checks.

## References

- [ADR 0026](0026-m1-policy-pipeline-at-dispatch.md) (pipeline steps, deny text, decision log line), [ADR 0027](0027-serve-policy-inventory-profiles-flags.md) (profiles embedded or `--profiles`, the empty profile), [ADR 0031](0031-hostname-patterns-never-make-a-target-known.md) (test 10), [ADR 0032](0032-unset-unknown-target-denies-every-class.md), [ADR 0033](0033-closed-argument-list-per-tool.md)
- [policy-schema sections 7 and 9](../specs/policy-schema.md#7-test-file-format), [profile-schema sections 2.2 to 2.4](../specs/profile-schema.md#22-targets-at-the-gate), [inventory-schema sections 3 and 7](../specs/inventory-schema.md#3-static-file), [test-matrix rows 3, 4 and 6](../testing/test-matrix.md)
- [Threat model](../security/threat-model.md): the PR #152 injection rows and "Pattern-resolved target"
- `internal/policy/testfile.go`, `internal/gate/gate.go`, `internal/gate/seam/seam.go`, `cmd/fathomgate/policy.go`, `cmd/fathomgate/serve_policy.go`
- [M1 board](../milestones/M1.yaml): M1-33 (this record), M1-18 (gate), M1-28 (real-server validation)
