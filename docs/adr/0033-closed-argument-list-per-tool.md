# ADR 0033: A closed argument list per tool: an argument the profile does not name is denied

- Status: accepted
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer), who decided on 2026-09-25 for a closed list (any argument the profile does not name is denied, not a per-tool deny-list) and for deny, never strip; written up by policy-engineer (board task M1-35); reviewers security-reviewer, go-reviewer
- Amends: [profile-schema.md](../specs/profile-schema.md) sections 2 and 7 (new section 2.3; numbered 2.2 when accepted, renumbered when the gate added its own 2.2); [ADR 0026](0026-m1-policy-pipeline-at-dispatch.md) step 1 gains a second cause for `default:bad_arguments`

## Context

A profile maps a tool's target, command and config arguments (`target_params`, `targets_params`, `group_params`, `command_params`, `config_params`) and ignores everything else. Every other argument goes to the upstream unread. The security review of PR #158 showed what that costs. Every eos-mcp v1.3.0 tool takes `config_path`, a file path the agent chooses (`eos_mcp/server.py:22-23`, `config.py:20-43`). The upstream parses it with `configparser` and returns the error text to the agent, and `configparser` quotes the offending lines. So:

- a single-line secret file (`~/.git-credentials`, `.pgpass`, the `--listen-token-file` file) comes back whole;
- `/proc/<ppid>/environ` returns fathomgate's whole environment, including `FATHOMGATE_LISTEN_TOKEN` and every `--upstream-env-pass` value;
- the file also replaces the credentials, transport and TLS verification for that call.

The reviewer reproduced `get_version` and `get_router_list` with `config_path` allowed under `read-only.yaml`. It is critical as soon as policy is enforced (M1-19), because an allowed read then carries a file read of the proxy's own secrets.

`config_path` is one instance of a general gap. Any argument the profile does not look at is a channel fathomgate cannot see. The M1-35 audit of the shipped profiles found three more:

- netdev-ssh-mcp `username` picks the device account the server's credentials log in as;
- ntunes `send_config` `enter_config_mode=false` sends a "config" payload in exec mode;
- eos-mcp `session_name` is free text interpolated into `configure session <name>`.

Upstreams also add parameters between versions. junos-mcp-server's v1.1.1 tag has two tools that its main branch has since dropped, one of which (`reload_devices`) reads an agent-chosen file.

The maintainer decided the shape on 2026-09-25: a closed list, where the profile names every argument a tool may carry and anything else is denied. He rejected a per-tool list of forbidden parameters, because it fails open for the next `config_path`. And the call is denied, never forwarded with the argument stripped, because stripping changes what the agent asked for without telling it. This record fixes the schema, where the check runs, and the edge cases.

## Decision

We will make each tool's argument list closed. A profile names every argument a tool accepts. The gate denies a call that carries any other argument, with `default:bad_arguments`, before `policy.Evaluate`.

### 1. Schema: `args` (required) and `refused_args` (optional) on every tool

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `args` | list of string | **yes**, `[]` when empty | Every argument the tool accepts other than those already in the five `*_params` lists. fathomgate does not read their values. |
| `refused_args` | list of string | no | Arguments the upstream accepts that the profile deliberately leaves unnamed. They have no effect at run time: an unnamed argument is denied anyway. The list records a reviewed refusal, so the coverage test can tell it apart from a parameter the upstream added later. |

The named set of a tool is `target_params ∪ targets_params ∪ group_params ∪ command_params ∪ config_params ∪ args`. The strict loader (`ParseProfile`) refuses a profile in any of these cases:

- a tool has no `args` key (or `args:` with no value);
- a name is empty or has surrounding whitespace;
- a name appears twice across the six named lists;
- a `refused_args` entry is also named, or is listed twice.

A tool with no other argument says `args: []`, so a profile author cannot leave the list out by accident.

Optional arguments need nothing extra. Named means allowed whether it is present or absent. Whether an argument is required is the upstream's business, checked by its own schema.

### 2. What is checked, and what counts as "sent"

`classify.CheckArguments(profile, tool, args) (unnamed, malformed []string)` does the check, and `Classify` copies its result into `Result.UnnamedArgs` and `Result.MalformedArgs` (`Result.ArgumentsOK()` is true when both are empty). Both lists are sorted.

- **Unnamed.** Every top-level key of the arguments object that is not in the tool's named set. A key counts as sent whatever its value, so `"config_path": ""` and `"config_path": null` are unnamed like any other: the upstream still receives the key, and an empty value is often the default that selects a file. Matching is exact and case-sensitive, byte for byte: `Config_Path` and `"hostname "` are unnamed.
- **Unknown tool.** When the profile does not list the tool, every key is unnamed. A tool the upstream adds after the profile was written is then denied as soon as it carries an argument. A call with no arguments is still classified `EXEC_ARBITRARY` as today (classification spec section 3).
- **No profile.** When the server has no profile, nothing is checked: [ADR 0027](0027-serve-policy-inventory-profiles-flags.md) starts it with the fallback classifier and a Warn. That Warn must also say the arguments are not checked (M1-20).
- **Empty strings in named arguments.** They are allowed. In a target argument an empty string adds no target, as it does today, and a tool that then has zero targets is M1-18's zero-target rule.
- **Nested objects.** Only top-level keys are checked. A value in `args` may be any JSON value, including an object, and fathomgate does not read inside it. A named target, command or config argument must be a string or an array of strings. `null` counts as absent. A number, a boolean, an object, or an array holding anything other than strings is reported in `MalformedArgs` and denied with the same rule id. So is a string the upstream would parse as JSON itself (see *Notes after acceptance*, H1). Until now `fmt.Sprint` turned such a value into a target or command string that the upstream never sees in that form. A profile author must not put an argument in `args` if its value is an object whose inner keys can change what the upstream does. Leave such an argument unnamed (refused) until the schema can describe it. None of the shipped profiles has one.

### 3. Where the check lives, and who denies

The check is in `internal/classify`, next to the profile that defines the named set. It is pure: no I/O and no clock. `policy.Evaluate` does not change and never sees the argument names (invariant 1). The gate (`internal/gate`, M1-18) denies before step 4 of [ADR 0026](0026-m1-policy-pipeline-at-dispatch.md) when `!Result.ArgumentsOK()`. The effect is `deny`, the rule is `default:bad_arguments` (already reserved for step 1), and the call is never forwarded or stripped.

The agent-facing reason is fixed text that names no argument:

```text
fathomgate denied eos-mcp.get_version: rule default:bad_arguments (class READ_OPERATIONAL): an argument is not named in the server profile for this tool
```

Argument names are agent-chosen text, so they stay out of the tool error, as ADR 0026 requires for argument values. The decision log line carries them as `unnamed_args` and `malformed_args`, escaped by `slog`. M1-18 fixes a cap on how many names and how many bytes are logged. For a malformed argument alone, the reason reads `a target, command or config argument must be a string that does not parse as JSON, or a list of such strings`.

`fathomgate policy eval --profile` shows the same deny. The trace names the arguments, because the operator typed them. It exits 1 without calling `Evaluate`.

### 4. What the agent is shown in `tools/list`

The agent should not be offered an argument that is always denied. When M1-19 wires the gate, the proxy removes each property that is not named from each listed tool's `inputSchema.properties`, and from `required`. That changes only what fathomgate advertises; the call is still checked as above. A tool whose upstream `required` list includes an unnamed property is then unusable through fathomgate, which is the intended fail-closed result: the profile has to decide about that property. This is M1-19's work, not this PR's.

### 5. When an upstream adds a parameter

The list fails closed. A new optional parameter the agent does not send changes nothing. A call that sends one is denied until a profile change names it (in `args` or a `*_params` list) or refuses it (in `refused_args`). Profile changes follow the existing route: read the upstream source at a pinned version, then get a security review for every `args` or `refused_args` change.

The tests carry the upstream's parameter set:

- **Tier 1** (`internal/classify/profiles_repo_test.go`, `TestRepoProfileArguments`). A table of every parameter each shipped upstream accepts per tool, read from source at the commit in each profile's header, must equal the named set plus `refused_args`. A second table pins each `refused_args` list. The test also checks that every tool of every profile reports an unknown probe argument, and that each refused argument is reported with a path, `""` and `null` as its value.
- **Tier 2** (test-engineer, with the M1-28 validation runs). For each upstream the harness runs, fetch `tools/list` and compare each tool's `inputSchema.properties` keys with the profile's named set plus `refused_args`. Any difference fails. This is the check that sees a parameter the Go table has not caught up with. The harness also fails when a property named in `args` has an object schema (`type: object`, `properties` or `additionalProperties`), because fathomgate does not look inside values in `args`.
- **Neither check replaces reading the handlers.** A server whose handlers read the arguments dict directly accepts keys its schema never lists. junos `load_and_commit_config` reads `config` and `timeout`, and a `tools/list` comparison cannot see them. The tier 1 table is filled from the handler code as well as the declared schema.

### 6. The shipped profiles

Each profile's parameters were read from the upstream source (the M1-35 PR lists the commits). Every parameter is named except these, which are refused:

| Profile | Tools | Refused | Why |
| --- | --- | --- | --- |
| `eos-mcp` (v1.3.0, `bffb893`) | all 17 | `config_path` | The local file read and credential swap above. |
| `eos-mcp` | `push_config`, `confirm_config_session`, `abort_config_session` | `session_name` | Free text interpolated into `configure session <name>` (`eapi.py:112-115`, `133-134`). Every session is the default `mcp-push`. |
| `netdev-ssh-mcp` (v1.7.1) | `get_config`, `run_show_command`, `run_ping`, `run_traceroute` | `username` | Picks the device account the server's credentials log in as. The operator sets `DEVICE_USERNAME`, which the server falls back to. |
| `ntunes-netmiko-mcp-server` (unpinned, read at `4cc59d6`) | `send_config` | `enter_config_mode` | With `false`, netmiko sends the "config" lines in exec mode, so `reload` would run under a `WRITE_CONFIG` class. |
| `junos-mcp-server` (unpinned, read at main `75fe90a`) | `load_and_commit_config` | `config` | Not in the schema. The handler reads it as the payload when `config_text` is absent (`jmcp.py:1657`), so the device would get a payload fathomgate never read. Added after the security review of PR #161. |

`upa` (`96e8ff3`) refuses nothing.

## Consequences

### Positive

- The `config_path` class of finding is closed for every argument no one has reviewed yet, not only for the one found. A new upstream parameter is denied until someone decides about it.
- Each profile now records every argument of every tool, with the source commit. A reviewer can see in one file what the agent can send.
- Target, command and config arguments of the wrong type are denied, where before they were turned into strings.
- `Evaluate` does not change, and the check needs no mocks.

### Negative

- Every profile, including third-party profiles written against the M0 schema, must add `args` to every tool or fail to load. No profile outside the repo is known to exist before M1 ships. The CHANGELOG entry carries the migration note (the file format may change before 1.0.0).
- An agent that fills in every parameter with its default, sending `config_path: ""` or `username: ""`, is denied until it stops. Item 4 keeps well-behaved agents from being offered those parameters. The deny text names the rule, so the agent can retry without them.
- Refusing `username` means a netdev-ssh-mcp operator must set `DEVICE_USERNAME`. Refusing `session_name` means one eos-mcp session name. Refusing `enter_config_mode` means ntunes config pushes always enter config mode.
- Keeping the parameter table in the Go test means someone has to update it from source for every new upstream version. Tier 2 catches it when they forget.

### Neutral

- `refused_args` is documentation plus test data. Deleting an entry changes no run-time decision. It only makes the coverage tests fail.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Per-tool `forbidden_params` deny-list | Rejected by the maintainer. It fails open: a parameter nobody has reviewed, or one added in the next upstream version, goes through. |
| Strip unnamed arguments and forward the rest | Rejected by the maintainer. The upstream would run a different call from the one the agent asked for and the log records, with no signal to the agent. For `config_path` it happens to be safe; for an argument that narrows a command's scope it would not be. |
| `args` optional, where absent means "only the `*_params` arguments" | Equally closed at run time. But a profile written before this record would load and then deny every call that uses a benign argument, and nobody could tell whether the author meant "none" or forgot. Requiring `args: []` makes the author say which. |
| No `refused_args`; keep refusals in comments or in the tier 2 harness | The coverage test could not tell a reviewed refusal from a new parameter without a second list somewhere. Keeping that list in the profile puts the decision next to the argument it concerns, where the security reviewer reads it. |
| Per-argument value types or patterns (`port: int`, `destination: ^[^-]`) | Richer and eventually useful (the netdev-ssh-mcp leading `-` finding, M2), but not needed to close this finding. This record keeps the list to names. The only type check is for the five mapped kinds, which fathomgate itself reads. |
| Check inside `policy.Evaluate` | Would put profile knowledge and argument names into the pure evaluator, and give policy authors a way to allow an unnamed argument. The profile defines the set, so the check sits next to it. |

## Notes after acceptance

**2026-09-25, security review of PR #161.** The reviewer found no name trick that gets past the closed list: case, padding, zero-width characters, look-alike letters, `_meta`, NUL, and prefixed names of tools the profile does not list. The maintainer upheld the three extra refusals (`username`, `session_name`, `enter_config_mode`). The same PR recorded the following:

- **H1, fixed here: a JSON string in a list parameter.** Python FastMCP (`mcp` 1.x, `func_metadata.pre_parse_json`) runs `json.loads` on any string sent for a parameter not annotated plain `str`. So `hostnames: "[\"core-rtr-01\"]"` reaches eos-mcp as a list, while fathomgate saw one target literally named `["core-rtr-01"]`. `hostnames: "null"` reaches it as `None`, and `daily_brief` then runs on every device. A `config_lines` sent as a JSON string would be read as one payload line. `CheckArguments` now reports a mapped argument as malformed in two cases:
  - its string value, after trimming, is valid JSON that starts with `[`, `n`, `t` or `f`;
  - it is a target, group or command argument that starts with `[` or `{`, whether or not the JSON is valid.

  Config arguments keep Junos `[edit ...]` text and JSON-object payloads.
- **H2, fixed here: junos `render_and_apply_j2_template` runs agent code.** It renders `template_content` in a plain Jinja2 `Environment` (`jmcp.py:1369-1375`), so a template runs Python on the upstream host. The tool is now `EXEC_ARBITRARY` with `never-downgrade`. The closed list cannot help here, because the dangerous input is a named config argument; the class has to carry it.
- **N1, not covered: answers to elicitation.** An upstream that asks the agent for input mid-call (junos v1.1.1 `add_device` elicits `ssh_key_path`) gets a second argument channel. The closed list does not see it, because it checks only `tools/call` arguments. Relayed input requests are ADR 0014's territory. Until a record covers checking their answers against the profile, operators should not run upstreams whose tools elicit paths or credentials (the junos profile header says so for v1.1.1).
- **2026-09-25, M1-17: meta-tools.** A tool's `capability_param` (profile-schema section 2.5) joins its named set, like the five `*_params` lists, and its value must be one string under the target rule (a list is malformed there). The Meraki `execute_api` `parameters` argument is refused under section 2: its value is an object whose keys the upstream passes to the Meraki SDK as keyword arguments (the organisation, network or serial a read reaches, and query options). That leaves 4 of the table's 493 capabilities callable through fathomgate. Naming `parameters` would need this record amended, or a new one, to say how an object argument is checked; the maintainer moved that to M2 on 2026-09-25 (threat model, "Meraki `parameters` scope and JSON-keyed secret redaction").
- **2026-09-25, M1-17 (security review of PR #196, F4): a reason for the capability argument.** Section 3's malformed text allows "a list of such strings", which is wrong for a `capability_param`: it takes one string, never a list. When the only malformed argument is the tool's capability argument, the gate now gives `the capability argument must be one string that does not parse as JSON` instead (`reasonMalformedCapability` in `internal/gate/text.go`). Like the others it is fixed text and names no argument value. Every other malformed case keeps section 3's text.
- **N2, for M1-18: duplicate keys.** Go's `encoding/json` keeps the last of two duplicate keys, and the upstream's parser may not. The gate's decoder must refuse an arguments object with a duplicate key. Otherwise it must forward the re-encoded map it checked, never the raw bytes.

## References

- Security review of PR #158 (M1-14), reproduced `config_path` reads; [M1 board](../milestones/M1.yaml) M1-35 (this record), M1-18 (gate), M1-19 (wiring), M1-20 (`serve` Warn), M1-28 (validation)
- [ADR 0010](0010-classify-by-payload-not-annotations.md), [ADR 0026](0026-m1-policy-pipeline-at-dispatch.md), [ADR 0027](0027-serve-policy-inventory-profiles-flags.md)
- [profile-schema.md](../specs/profile-schema.md) section 2.3; [threat-model.md](../security/threat-model.md) (the eos-mcp `config_path` row)
- `internal/classify/profile.go` (`ToolSpec.Args`, `RefusedArgs`, `validateArgs`, `Named`), `normalize.go` (`CheckArguments`, `Result.UnnamedArgs`, `MalformedArgs`)
