# Research Brief 03: Policy Engine, Approval, Audit, Redaction, Blast-Radius and Testing Patterns

**Context:** open-source guardrail proxy sitting between AI agents and network-device MCP servers. Must allow/deny by device role + command class, force dry-run/diff before writes, hold writes for human approval, redact secrets, enforce blast-radius limits, and keep a tamper-evident audit log.
**Date:** 2026-09-22. Research method: ~20 web searches and page fetches. Sources cited inline.
**Legend:** **[F]** = verified against a fetched source. **[I]** = inference / recommendation / from prior knowledge, not verified in this pass.

---

## 1. Policy engine options for a Python project

### 1.1 Open Policy Agent (OPA) / Rego

- **Maturity [F]:** CNCF-graduated, general-purpose engine; OPA documents three integration modes: REST API (a sidecar/daemon queried over HTTP), the Go library (Go-only), and Wasm-compiled policies (language-agnostic, needs a Wasm runtime and a per-language SDK for management features). OPA itself says REST is the most common integration at the time of writing. https://www.openpolicyagent.org/docs/integration
- **Python integration story:**
  - HTTP sidecar: any HTTP client; adds a second process and a network hop, but gives you bundles, decision logs, and hot reload for free. **[F]** per the integration page above.
  - Subprocess: shell out to `opa eval` per decision, or keep `opa run --server` as a child process managed by the proxy. **[I]** Simple and dependency-free but adds process management; latency of a per-call `opa eval` fork is probably tens of ms, fine for a proxy that is already doing SSH.
  - Wasm: the `opa-wasm` PyPI package wraps wasmer-python, but its latest release is 0.3.2 from Feb 2022 and it lists Python 3.8-3.10 support. **[F]** https://pypi.org/project/opa-wasm/ **[I]** Treat as effectively unmaintained for a 2026 project; you would likely have to write your own thin wasmtime-py loader against OPA's Wasm ABI (https://www.openpolicyagent.org/docs/wasm).
- **Expressiveness for "device tags + command class + session counters" [I]:** Rego handles set membership (`input.device.tags[_] == "prod-core"`), lookups against external data (NetBox exports loaded as `data.devices`), and arithmetic comparisons on counters, so long as the *proxy* supplies the counters in `input` (e.g. `input.session.devices_touched`). OPA is stateless per query; it does not maintain session counters itself.
- **Testability [F]:** first-class. Tests are Rego rules prefixed `test_`, run with `opa test`, with `with input as {...}` to mock input and `with data.x as ...` to mock data; `--coverage` and `--format=json` exist for CI. https://www.openpolicyagent.org/docs/policy-testing
- **Community familiarity [I]:** High among platform/DevOps engineers (Gatekeeper, Conftest, Terraform/Sentinel-adjacent). Lower among traditional network engineers, who tend to know YAML/Ansible more than Rego. Rego's learning curve (unification, partial rules) is a real onboarding cost.

### 1.2 Cedar (AWS)

- **Maturity [F]:** Rust implementation, open source under cedar-policy org; a CLI exists for `validate` and `authorize` and AWS publishes a CI pipeline sample using them. https://github.com/cedar-policy/cedar , https://github.com/aws-samples/cedar-policy-validation-pipeline
- **Python bindings [F]:** `cedarpy` on PyPI is a wrapper over the Rust engine, version 4.12.0 released 2026-09-12, tracking Cedar 4.12.0, Python 3.10-3.14, with `is_authorized`, `is_authorized_batch`, `validate_policies`, `format_policies`, template linking and partial evaluation. https://pypi.org/project/cedarpy . Other, older attempts exist (`cedar-py` from k9security, `cedarling-python` from Gluu) but `cedarpy` looks like the live one. **[I]** on "live".
- **Expressiveness [I, from prior knowledge of the Cedar language; verify at https://docs.cedarpolicy.com]:** Cedar is deliberately not Turing-complete: no loops, recursion or user-defined functions; evaluation is bounded and policies are statically validated against a schema. It has entities with attributes and parent hierarchies (good fit for "device is member of group prod-core"), sets, records, and a `context` record per request. Counters like "devices touched this session" must be computed by the proxy and passed in `context`, then compared with `<`/`>=`. That is workable but you cannot aggregate over a set inside the policy.
- **Testability [F]:** the AWS sample keeps `ALLOW/` and `DENY/` directories of request JSON files evaluated by `cedar authorize` against the policy set plus an entities file, and a schema `validate` step. https://github.com/aws-samples/cedar-policy-validation-pipeline . With `cedarpy` you can do the same inside pytest with no external binary. **[I]** on the pytest point.
- **Community familiarity [I]:** Low outside AWS (Verified Permissions). Syntax is readable (`permit(principal, action, resource) when {...};`) so the reading curve is shallow even if nobody has written it before.

### 1.3 Kyverno-style declarative YAML matching

- **Maturity [I]:** Kyverno itself is a Kubernetes admission controller; there is no standalone Python evaluator of Kyverno policies. What is reusable is the *shape*: `match`/`exclude` selectors on labels and names, plus `validate`/`mutate` blocks, with pattern operators and optional CEL expressions.
- **Python story [I]:** you would re-implement the matcher yourself; realistically it becomes a custom YAML DSL (1.5) with Kyverno-flavoured field names. CEL is available in Python via `cel-python` if you want expression snippets. Not verified in this pass.
- **Familiarity [I]:** Kubernetes-heavy teams know it; network engineers mostly do not. Not a strong differentiator for this audience.

### 1.4 Casbin (pycasbin)

- **Maturity [F]:** `pycasbin` is under the Apache incubator as `apache/casbin-pycasbin`, ~1.8k stars, supports ACL/RBAC/ABAC/RESTful/deny-override/priority models defined in a PERM-style `model.conf` and CSV policy rows, with custom Python matcher functions and async support since 1.23. https://github.com/apache/casbin-pycasbin , https://pypi.org/project/pycasbin/
- **Expressiveness [I]:** the matcher is a single expression per model (`r.sub == p.sub && keyMatch(r.obj, p.obj)`); you can call registered Python functions, so "device has tag X and command class Y and counter < N" is expressible by passing objects (ABAC: `r.obj.tags`). It gets awkward once rules need per-rule reasons, multi-clause obligations (e.g. "allow but require dry-run first"), or structured outputs. Casbin returns a boolean, not a decision object.
- **Testability [I]:** ordinary pytest against `Enforcer.enforce()`; no policy-native test DSL.
- **Familiarity [I]:** popular in web-app RBAC; not part of the netdevops vocabulary.

### 1.5 Custom YAML DSL evaluated in Python

- **Maturity [I]:** whatever you build. Zero external dependencies; the schema can be validated with pydantic/JSON Schema and unit-tested like any Python code.
- **Expressiveness [I]:** you control it. A rule shape that covers the stated requirements:
  ```yaml
  rules:
    - id: no-writes-to-prod-core-without-approval
      match: {device_tags: [prod-core], command_class: [config-write]}
      effect: require_approval
      obligations: [dry_run, diff]
    - id: session-device-cap
      match: {command_class: [config-write]}
      when: {session.devices_touched: {gte: 5}}
      effect: deny
      reason: "session blast-radius limit"
  ```
  Decisions carry `effect ∈ {allow, deny, require_approval}` plus obligations, which is exactly the vocabulary a proxy needs and which none of the general engines return natively.
- **Testability [I]:** pytest table tests over (request, expected decision); trivially fast, no binaries.
- **Familiarity [I]:** highest. Every network engineer reads YAML (Ansible, NetBox exports, containerlab topologies).
- **Risk [I]:** feature creep turns it into a bad Rego. Mitigate by keeping the matcher to equality/set/range operators and pushing anything richer to an "advanced" engine later.

### 1.6 Recommendation

- **MVP: custom YAML DSL, with the decision object designed so it can be produced by another engine later.** Reasons: (a) the proxy's decisions are not pure allow/deny; they carry obligations (dry-run, diff, hold-for-approval) and reasons, which general engines don't model; (b) the target users read YAML, not Rego or Cedar; (c) no sidecar, no unmaintained Wasm shim, no Rust wheel; (d) counters and NetBox lookups are trivially available in-process. Keep the evaluator as a pure function `evaluate(policy, request) -> Decision` so it is easy to unit-test and easy to swap. **[I]**
- **Later: OPA/Rego as an optional backend** for organisations that already run OPA (bundles, decision logs, central policy distribution), integrated via HTTP to a sidecar or a managed child process. Map the Rego result object `{effect, reason, obligations}` onto the same `Decision` type. Cedar is the runner-up: `cedarpy` gives a clean in-process story and schema validation, and its bounded semantics are attractive for a safety product, but its lack of community mindshare among network teams and its inability to express obligations directly keep it second. **[I]**

---

## 2. Human-in-the-loop approval patterns

### 2.1 MCP elicitation (spec status as of the draft spec, Sept 2026)

- **[F]** Elicitation lets a server ask the user for input mid-request. Two modes: **form** (flat JSON-Schema of primitives: string, number/integer, boolean, single/multi-select enums, with defaults; no nested objects) and **url** (server hands the client a URL for an out-of-band interaction; client shows the full URL and must get explicit consent before opening). https://modelcontextprotocol.io/specification/draft/client/elicitation
- **[F]** Response is a three-action model: `accept` (with `content` for form mode), `decline`, `cancel`. Servers must handle all three.
- **[F]** In the 2026-07-28 spec, elicitation is delivered via **Multi Round-Trip Requests (MRTR)**: the server returns an `InputRequiredResult` (`resultType: "input_required"`) carrying `elicitation/create` requests; the client answers and *retries the original call* with `inputResponses` attached, optionally echoing a server-provided `requestState`. This is designed to work over stateless HTTP. Sessions were removed from the protocol; each request is self-describing. https://blog.modelcontextprotocol.io/posts/2026-07-28/
- **[F]** Clients declare `elicitation` capability per request in `_meta.io.modelcontextprotocol/clientCapabilities` with `form` and/or `url`; an empty object means form-only. Servers must not use form mode for credentials.
- **[F]** Client support: Claude Code exposes an `Elicitation` hook event so MCP input requests can be answered programmatically (https://code.claude.com/docs/en/agent-sdk/hooks); LangChain's MCP adapters announced elicitation support (https://www.langchain.com/blog/mcp-in-langchain-stateless-protocol-elicitation-and-more); GitHub's MCP server supports the new spec (https://github.blog/changelog/2026-07-23-github-mcp-server-supports-the-next-mcp-specification/). **[I]** Support is still uneven across desktop clients; the proxy cannot assume every upstream client renders forms, so elicitation should be one approval channel, not the only one.
- **Fit for the proxy [I]:** a form-mode elicitation with a boolean "approve this diff?" plus an enum reason is a natural *in-band* approval for the operator who is driving the agent. It is the wrong tool for *separation of duties* (a different human approving) because the answer comes from the same client session. Use url mode or an out-of-band channel for that.

### 2.2 How agent frameworks do approval

- **Claude Code / Agent SDK hooks [F]:** `PreToolUse` hooks receive the tool name and input and return `hookSpecificOutput.permissionDecision` of `allow`, `deny`, `ask` or `defer`, with `permissionDecisionReason` and optional `updatedInput` (rewrite arguments before execution). Precedence: deny > defer > ask > allow. `defer` ends the query so it can be resumed later, which is effectively a first-party "hold for approval" primitive. `PostToolUse` can replace tool output (`updatedToolOutput`), which is where output redaction would hook in if the proxy were implemented as hooks rather than as a network proxy. https://code.claude.com/docs/en/agent-sdk/hooks
- **OpenAI Agents SDK [F]:** tools declare `needs_approval` (bool or async callable); a run halts with `RunResult.interruptions` containing `ToolApprovalItem`s; the run is serialized via `result.to_state()` / `RunState.to_json()`, later `state.approve(item)` or `state.reject(item)`, then `Runner.run(agent, state)` resumes. Docs warn to verify reviewer identity server-side and to version agent definitions alongside stored state; there is no built-in TTL. https://openai.github.io/openai-agents-python/human_in_the_loop/
- **LangGraph [F]:** `interrupt(payload)` inside a node pauses and persists state through a checkpointer keyed by `thread_id`; resume with `Command(resume=value)` on the same thread. The whole node re-runs from the top on resume, so pre-interrupt side effects must be idempotent. https://docs.langchain.com/oss/python/langgraph/interrupts
- **Common thread [I]:** all three externalize a *serializable pending state* keyed by an id, and resume by re-invoking with the decision attached. None of them own TTL, notification or approver identity; those are left to the host application. That is the gap the proxy fills.

### 2.3 Ops-tooling approval patterns

- **HCP Terraform / Terraform Enterprise [F]:** runs pass through a `Needs Confirmation` state where the run pauses until a user with apply permission confirms or discards; `Policy Override` is a separate state where mandatory (soft-mandatory) policy failures can be overridden by users with override permission; auto-apply skips confirmation for VCS-triggered runs. Terminal states include Applied, Discarded, Canceled, Errored. https://developer.hashicorp.com/terraform/cloud-docs/workspaces/run/states . Runs and approvals are exposed via the `/runs` API (actions `apply`, `discard`, `cancel`). https://developer.hashicorp.com/terraform/cloud-docs/api-docs/run
- **Ansible Automation Platform / AWX [F]:** workflow *approval nodes* pause a workflow with a configurable timeout; an approval that times out enters a `timed out` state and can no longer be acted on (an AWX bug report exists precisely because the UI still showed the buttons). https://github.com/ansible/awx/issues/13465 . Approvals can be performed via API/Ansible module `awx.awx.workflow_approval`. https://docs.ansible.com/projects/ansible/latest/collections/awx/awx/workflow_approval_module.html . Red Hat's original write-up describes approvers, notifications and timeout semantics. https://www.redhat.com/en/blog/how-to-add-approval-steps-to-ansible-tower-workflows
- **Rundeck, Spacelift, Argo CD [I, not fetched this pass]:** Rundeck has no native approval step; the common pattern is a job that posts to Slack and polls/waits for a webhook. Spacelift has explicit `approval` policies (OPA/Rego!) that gate runs on N approvals and expose approve/reject in UI/API. Argo CD does not do per-change approval; its `syncWindows` deny/allow syncs by time window and `manual` sync policy holds until a human clicks. Verify before quoting.

### 2.4 Extracted pattern: the approval-hold

Combine the above into one state machine the proxy owns. **[I]** unless marked.

```
tools/call (write) --policy--> require_approval
   |
   v
PENDING(id, ttl, created_at, requester, device_set, diff_sha256, dry_run_output_ref)
   |-- approve(id, approver, comment)  --> APPROVED --> execute --> EXECUTED / FAILED
   |-- deny(id, approver, reason)      --> DENIED
   |-- ttl elapsed                     --> EXPIRED   (terminal; approve/deny rejected, as AWX does [F])
   |-- requester cancels / diff drift  --> CANCELLED
```

Design points:
1. **Pending record is the source of truth**, persisted (SQLite is fine for MVP) and serializable, like OpenAI `RunState` and LangGraph checkpoints **[F]**. Store the *exact* rendered change and the diff hash; on resume, re-run dry-run and refuse if the diff hash changed (drift guard).
2. **TTL is mandatory** and expiry is terminal, mirroring AWX approval-node timeouts **[F]**. Suggested defaults: 15 min for a single device, shorter for larger sets.
3. **Out-of-band approve/deny**: (a) CLI `proxy approve <id> --comment ...` that writes to the same store; (b) signed webhook endpoint (`POST /approvals/{id}` with HMAC, used by Slack interactive buttons or a ticketing system); (c) in-band MCP elicitation for the single-operator case, using form mode with a boolean + enum **[F on capabilities]**. Approver identity must be established server-side, never taken from the agent **[F, OpenAI docs and MCP elicitation security notes]**.
4. **Resumption**: with 2026-07-28 MRTR, the cleanest flow is: return `input_required` with a `requestState` containing the pending id; the client retries with the approval answer; if the pending record is already APPROVED via CLI/webhook the server proceeds regardless of the inline answer; if DENIED/EXPIRED it returns a structured error. For clients without elicitation, return a tool error whose text names the pending id and tells the agent to call `check_approval(id)` later. **[I]**
5. **Separation of duties** option: policy flag `approver_must_differ_from_requester` enforced by comparing authenticated identities. **[I]**
6. **Idempotency**: the executed write must be keyed by pending id so a retried `tools/call` does not push twice (LangGraph's node re-execution warning is the cautionary tale **[F]**).

---

## 3. Audit log design

### 3.1 Tamper-evidence mechanisms

- **Hash chain (simplest) [I]:** each JSONL record carries `prev_hash` and `hash = SHA256(canonical_json(record_without_hash) + prev_hash)`. Detects deletion/modification *after the fact* if the final hash is anchored somewhere the writer cannot alter (printed to a separate log sink, posted to a ticket, or periodically signed). It does **not** stop an attacker who controls the host from rewriting the whole chain; that is why anchoring matters.
- **AWS CloudTrail digest files [F]:** hourly digest files list SHA-256 hashes of every log file from the last hour, embed the *signature of the previous digest*, and are themselves signed with SHA-256/RSA using per-region keys; the current digest's signature lives in S3 object metadata. Validation walks the chain forward from a known-good digest; modified, deleted or forged log files break it. https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html . Custom validators are documented. https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-custom-validation.html . Pattern to copy: **periodic signed digests over batches**, not per-record signatures.
- **Sigstore Rekor [F]:** an append-only transparency log on a verifiable (Merkle-tree) data structure; supports inclusion proofs for entries and consistency proofs that the log is append-only; auditors and witnesses can monitor it. https://docs.sigstore.dev/logging/overview/ , https://github.com/sigstore/rekor . **[I]** Merkle trees add *efficient* proofs (O(log n)) over a plain hash chain; for a proxy writing thousands of events/day a hash chain plus signed daily checkpoints is enough, and a later "publish checkpoint to Rekor / a public witness" is a cheap external anchor.

### 3.2 Recommended MVP design [I]

- **Format:** JSONL, one event per line, UTF-8, RFC3339 UTC timestamps, canonicalized (sorted keys, no whitespace) before hashing.
- **Chain:** `seq`, `prev_hash`, `hash` per record; genesis `prev_hash = "0"*64`.
- **Checkpoints:** every N events or T minutes, write `{type: "checkpoint", seq, hash, signature}` signed with an Ed25519 key held outside the log directory (or an HSM/KMS later). Provide `proxy audit verify` that replays the chain and checks signatures, mirroring CloudTrail's `validate-logs` **[F on the CLI's existence]**.
- **Optional external anchor:** ship each checkpoint hash to syslog/SIEM and, later, to Rekor.
- **Immutability at rest:** append-only file opened with `O_APPEND`, rotated by size, with `chattr +a` or object-lock where available. **[I]**

### 3.3 Structured formats

- **OCSF [F]:** open schema led by AWS and partners; events are typed by class (`class_uid`/`class_name`, e.g. `API Activity`, `Authentication`, `Account Change`, `Network Activity`) with `metadata.product.*` and `metadata.version` identifying the source; Security Lake stores it as Parquet. https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html . **[I]** The closest class for "agent invoked tool X on device Y" is `API Activity` (category System/Application Activity). Worth offering as an *export mapping*, not as the native on-disk format, because OCSF is verbose.
- **CEF [I]:** ArcSight's pipe-delimited header plus key=value extensions. Still accepted by most SIEMs; trivial to emit from the JSONL. Offer as an exporter.
- **Native:** plain JSONL as above; easiest to hash-chain and diff.

### 3.4 Fields an ops audit event should carry [I]

| Group | Fields |
|---|---|
| Identity | `event_id` (ULID), `seq`, `ts`, `proxy_instance`, `schema_version` |
| Who | `principal` (authenticated MCP client/user), `agent_id`/`model` if supplied, `session_id`, `client_name`/version from MCP `initialize` |
| What | `tool_name`, `command_class` (read/diagnostic/config-write/destructive), `raw_args_redacted`, `args_sha256` (over unredacted args) |
| Where | `device_ids[]`, `device_roles[]`, `device_tags[]`, `vendor/os`, `mgmt_addr_redacted` |
| Policy | `policy_version` (git sha or file hash), `rule_ids_matched[]`, `decision` (allow/deny/require_approval), `reason`, `obligations[]` |
| Approval | `approval_id`, `approver`, `approval_channel` (cli/webhook/elicitation), `approved_at`, `ttl_expires_at` |
| Change safety | `dry_run_ok`, `diff_sha256`, `diff_ref` (path/object id of stored diff), `rollback_mechanism` (commit-confirmed/revert-timer/checkpoint/session), `rollback_deadline` |
| Outcome | `status` (executed/failed/denied/expired), `duration_ms`, `error_class`, `output_sha256`, `redactions_applied` (count + rule ids) |
| Integrity | `prev_hash`, `hash` |

Keep raw device output *out* of the audit line (store redacted output in a separate blob store keyed by `output_sha256`) so the audit log stays small and never carries secrets.

---

## 4. Secret redaction from device output

### 4.1 Generic secret-scanning libraries

- **gitleaks [F]:** Go CLI; rules are TOML with `id`, `regex` (Go RE2 syntax), `keywords` prefilter, `entropy` threshold, `secretGroup`, and `allowlists`; supports `stdin` and directory modes for non-git text, so it can be run as a subprocess from Python. https://github.com/gitleaks/gitleaks . **[I]** Good as a *second-pass* scanner in CI over stored outputs, poor as an inline filter (process per call, cloud-token-centric default rules).
- **detect-secrets (Yelp) [I, not fetched this pass]:** pure-Python plugin architecture (`BasePlugin`, `RegexBasedDetector`), so custom network-device detectors can live in-process. Its default plugins target cloud/API keys plus keyword and high-entropy heuristics; you would add vendor patterns yourself. Verify current maintenance status before adopting.
- **Recommendation [I]:** write a small in-process redactor with an ordered list of compiled regexes (vendor-specific first, generic keyword/entropy last), and optionally run gitleaks/detect-secrets in CI as a canary over sampled stored outputs.

### 4.2 Vendor-specific patterns

- **Cisco IOS/IOS-XE [F]:** type 0 cleartext (`password 0 ...`), type 4 (flawed SHA-256, `$4$`, deprecated), type 5 salted MD5 (`secret 5 $1$...`), type 6 reversible AES with a master key, type 7 Vigenère-reversible (`password 7 <hex>`), type 8 PBKDF2-SHA256 (`secret 8 $8$...`), type 9 scrypt (`secret 9 $9$...`, and `$14$` for converted hashes). https://community.cisco.com/t5/networking-knowledge-base/understanding-the-differences-between-the-cisco-password-secret/ta-p/3163238 . **[I]** Also redact `snmp-server community <str>`, `key-string`, `tacacs-server key`, `radius-server key`, `crypto isakmp key`, `neighbor X password`, `ip ospf message-digest-key N md5 ...`, `username X privilege 15 secret ...`. Type 7 must be treated as cleartext-equivalent.
- **NX-OS [I]:** same `$5$`/`$8$`/`$9$` family for `username ... password 5 ...`; `snmp-server user ... auth md5 0x...`; `key chain` `key-string 7 ...`; `feature tacacs+` keys. Note that NX-OS shows type 5 as `password 5 $5$...` (SHA-256 crypt) on newer releases; regex on `\$[0-9]+\$[A-Za-z0-9./]+` is safer than enumerating.
- **Junos [F]:** `encrypted-password "$1$..."` (MD5-crypt; one article mislabels it SHA-1) for login passwords; `$9$` reversible obfuscation for protocol keys (`authentication-key`, `pre-shared-key`, `md5 0 key`, RADIUS/TACACS secrets, SNMP `community`), which tools can decode. https://junipertrain.wordpress.com/2016/10/19/junos-passwords-in-configuration/ . **[I]** Newer Junos supports `$5$` (SHA-256-crypt) and `$6$` (SHA-512-crypt) for `encrypted-password`, and `$8$` for master-password AES-encrypted values (https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/master-password-configuration-encryption.html); Junos also annotates them with `## SECRET-DATA`, which is a convenient anchor for a line-level regex.
- **Arista EOS [I]:** `username X secret sha512 $6$...`, `secret 5 $1$...`, `enable password sha512 ...`, `snmp-server community ...`, `neighbor X password 7 ...` (reversible), `ip ospf message-digest-key N md5 7 ...`, `tacacs-server key 7 ...`, `radius-server key 7 ...`. Type 7 on EOS is the same weak scheme as Cisco's.
- **PAN-OS [I]:** `phash` values in user entries (`<phash>$1$...` / `$5$` style), `pre-shared-key` under IKE gateways, `-AQ==...` base64 encrypted strings for secrets in `show config` XML/set output, LDAP/RADIUS `secret` fields, API keys in `show system setting`. A generic rule for any `<phash>`, `pre-shared-key`, `secret`, `password` element/set-key is more robust than trying to enumerate encodings.
- **FortiOS [I]:** `set password ENC <base64>`, `set passwd ENC ...`, `set psksecret ENC ...`, `set secret ENC ...`, `set community ...`, `set private-key "-----BEGIN ..."`. The `ENC ` marker makes a single regex (`\bENC\s+[A-Za-z0-9+/=]{16,}`) cover most cases.

### 4.3 Deterministic hashing (netdev-ssh-mcp)

- **[F]** `krisiasty/netdev-ssh-mcp` (Go; read-only tools `get_config`, `run_show_command`, `run_ping`, `run_traceroute`) replaces passwords, SNMP communities and BGP/OSPF/TACACS/RADIUS/IKE keys in output with deterministic SHA-256 hashes so identical secrets on different devices still compare equal; obfuscation is on by default and disabled with `--no-obfuscate`. The README does not enumerate vendor formats. https://github.com/krisiasty/netdev-ssh-mcp
- **Design note [I]:** unsalted deterministic SHA-256 is safe against reversal only if the secret has entropy; a type-7 string or a short SNMP community could be brute-forced from its hash. Prefer **HMAC-SHA256 with a per-deployment key**, truncated (e.g. 12 hex chars) and prefixed (`<redacted:hmac:3f9a…>`). That preserves equality-comparison across devices within one deployment while defeating offline guessing. Log the count and rule ids of redactions (not the values) in the audit event.
- **Fail-closed [I]:** apply redaction at the response serializer so *every* tool output passes through it, and consider a whitelist mode for known-safe show commands (a community post argues that regex redaction "fails open": https://dev.to/hex_tracker/redaction-fails-open-whitelist-your-mcp-tools-output-instead-3mpn).

---

## 5. Blast-radius and change-safety patterns

### 5.1 Source-of-truth roles and tags as policy inputs [I]

- NetBox and Nautobot both model `device role`, `tags`, `site`, `tenant`, `status` and custom fields; both have REST/GraphQL APIs and dynamic-inventory integrations (e.g. Cisco's NX-OS + NetBox + AAP guide https://developer.cisco.com/docs/nexus-as-code/nx-os-with-netbox/ ; Nautobot overview https://networktocode.com/nautobot/ ). Not fetched in depth this pass.
- Proxy pattern: at session start (or on a cached TTL), pull `{device: {role, tags, site, status}}` from the SoT into the policy data set; policies reference tags such as `prod-core`, `change-frozen`, `canary`. Refuse writes to devices with `status != active` and to devices *absent from the SoT* (unknown = deny).

### 5.2 Batfish pre-change validation

- **[F]** Batfish workflow: initialize a base snapshot from current configs, create a candidate snapshot containing the changed configs, then run `differentialReachability` (and related differential questions) to list flows whose forwarding behaviour changed; use targeted `reachability` queries to confirm the intended effect and `invertSearch` to exclude expected changes. A passing test is an empty result set. https://batfish.readthedocs.io/en/latest/notebooks/linked/introduction-to-forwarding-change-validation.html ; ACL-specific companion: https://batfish.readthedocs.io/en/stable/notebooks/linked/provably-safe-acl-and-firewall-changes.html
- **Proxy fit [I]:** optional obligation `batfish_check` for `config-write` on routing/ACL classes: render candidate config, push to a Batfish service, fail the request if differential questions return rows outside an allowlist. Heavy dependency; keep behind a feature flag and a per-vendor support matrix (https://batfish.readthedocs.io/en/latest/supported_devices.html).

### 5.3 Canary device pattern [I]

- Tag one device per role as `canary`; policy for multi-device changes requires the first execution to target a `canary`-tagged device, then a soak timer (or an explicit health check tool call) before the rest are released. Combine with session counters: `max_devices_per_session`, `max_devices_per_approval`, `max_concurrent_pending`.

### 5.4 Native dry-run / rollback mechanisms per vendor

| Vendor / OS | Dry-run / diff | Timed auto-rollback | Confirm | Abort / revert | Notes |
|---|---|---|---|---|---|
| **Junos** | `show \| compare` in candidate; `commit check` **[F for compare; I for commit check]** | `commit confirmed <minutes>` **[F]** | second `commit` (or `commit confirmed` again) **[F]** | let timer expire, or `rollback 0` + `commit` **[I]** | Candidate config is native; commit is atomic. https://chewonice.com/2023/08/23/juniper-commit-confirmed-vs-arista-configure-session/ |
| **Arista EOS** | `configure session <name>` then `show session-config diffs` **[F]** | `commit timer hh:mm:ss` inside the session **[F]** | `configure session <name> commit` then `write` (separate step) **[F]** | `configure session <name> abort` **[F]** | Same source. **[I]** `rollback clean-config` also exists. |
| **Cisco IOS / IOS-XE** | `show archive config differences` **[I]**; `configure replace <file> list` for full replace **[I]** | `configure terminal revert timer <min>` (requires `archive` + `path` configured first) **[F]** | `configure confirm` **[F]** | `configure revert now` **[F]** | https://iosxrjunos.wordpress.com/2025/05/16/how-cisco-ios-ios-xe-implements-juniper-like-commit-and-rollback-behavior/ ; `reload in` is discouraged **[F]**. |
| **Cisco NX-OS** | `checkpoint <name>` then `show diff rollback-patch checkpoint <name> running-config` **[F]** | none documented **[F]** | n/a | `rollback running-config checkpoint <name> atomic` **[F]** | Max 10 checkpoints, one user at a time, names <=75 chars. https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus3548/102x/configuration/system-management/cisco-nexus-3548-switch-nx-os-system-management-configuration-guide-102x/m-configuring-rollback.html . **[I]** Proxy must schedule its own timed rollback (a watchdog issuing the rollback). |
| **Cisco IOS-XR** **[I]** | `show commit changes diff` / `show configuration` | `commit confirmed <sec>` | `commit` | `abort` / timer expiry | Not fetched; verify. |
| **PAN-OS** | `configure` -> edits live in candidate; `validate full` (also partial); `show config diff` **[F for configure/validate; I for show config diff]** | none documented **[F]** | `commit` / `commit partial ...` **[F]** | `load config from running-config` / revert candidate (GUI "Revert to running") **[I]** | Commits are queued jobs (`show jobs id N`) **[F]**. https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/use-the-cli/commit-configuration-changes . **[I]** Proxy watchdog must `load config from` a saved snapshot and commit to roll back. |
| **FortiOS** | none native; diff via config revisions in GUI, or proxy-side diff of `show full-configuration` **[F for revisions GUI diff; I otherwise]** | none **[F: not mentioned in docs]** | n/a (changes apply on `end`/`next`) **[I]** | `execute revision list config` -> `execute restore config flash <id>` (reboot-style restore) **[F]** | Revision-on-change and revision-backup-on-logout default on in 8.0. https://community.fortinet.com/fortigate-3/technical-tip-using-the-revision-option-to-revert-to-a-previous-configuration-96374 , https://docs.fortinet.com/document/fortigate/8.0.0/new-features/699547/configuration-revisions-and-logout-backup-default-changes . **[I]** `config system global / set cli-workspace enable`-style transaction mode exists on some releases; verify. |
| **gNMI (vendor-neutral)** | n/a | OpenConfig commit-confirmed extension: commit id, default 10-minute rollback, `confirm`/`cancel` by matching id, `SetRollbackDuration` mid-window; only one active commit at a time **[F]** | | | https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-commit-confirmed.md . Useful long-term abstraction target. |

**Proxy abstraction [I]:** define a `ChangeSafety` capability per platform driver with `prepare() -> diff`, `apply(timed_rollback=True)`, `confirm()`, `abort()`. Where the OS has no timer (NX-OS, PAN-OS, FortiOS) the proxy owns a watchdog: it stores the pre-change checkpoint/revision id and issues the vendor rollback if `confirm()` is not called before `rollback_deadline`. Record the mechanism and deadline in the audit event (section 3.4).

---

## 6. Testing

### 6.1 Unit-testing policies

- **Custom YAML DSL [I]:** pytest table tests: `(policy_fixture, request_dict) -> expected Decision`. Add a `proxy policy test policies/ tests/` CLI that loads `*.test.yaml` files in the same shape as the AWS Cedar sample's ALLOW/DENY request directories so non-Python users can write cases. Property-based tests (hypothesis) over random device/tag/command combinations to assert invariants such as "no rule ever yields allow for `destructive` on `prod-core`".
- **OPA [F]:** `test_*` rules, `opa test ./policy --coverage --format=json`, `with input as` mocks. https://www.openpolicyagent.org/docs/policy-testing
- **Cedar [F]:** `cedar validate --schema ... --policies ...` plus `cedar authorize --request-json <case>.json` with expected decisions, as in the AWS sample; or in-process with `cedarpy.is_authorized` in pytest. https://github.com/aws-samples/cedar-policy-validation-pipeline , https://pypi.org/project/cedarpy
- **Casbin [I]:** plain pytest against `Enforcer.enforce()`.

### 6.2 Testing the proxy as an MCP server/client

- **In-memory [F]:** the MCP Python SDK's recommended approach is an in-memory `Client` connected directly to the server object (no subprocess, no port), with `anyio` fixtures and `raise_exceptions=True` so unexpected server crashes surface; tool-body exceptions still arrive as `is_error=True` results. Dev deps: pytest, inline-snapshot. https://py.sdk.modelcontextprotocol.io/get-started/testing/ **[I]** For the proxy this means: unit-test the proxy's own MCP surface in-memory, with the *upstream* device MCP server replaced by a fake that records calls.
- **Containerized upstream [F]:** an Arm learning path shows pytest + testcontainers starting an MCP server image with `stdin_open=True`, waiting on a log line, attaching to the container's stdio socket and speaking JSON-RPC over stdio, asserting on `id`, `result`, `serverInfo` and tool outputs. https://learn.arm.com/learning-paths/cross-platform/automate-mcp-with-testcontainers/write-test-cases/ . **[I]** Prefer streamable-HTTP for containerized upstreams (map a port; use the SDK's HTTP client) over Docker stdio attachment, which requires parsing Docker's 8-byte frame headers.
- **Fake device tier [I]:** a fake SSH server (e.g. asyncssh-based) that returns canned `show` output and echoes config lines, so approval/redaction/rollback logic can be tested without images.

### 6.3 Real-device tier: containerlab + cEOS

- **[F]** containerlab (srl-labs) runs container-based network labs from YAML topologies; community CI examples exist for pytest-based network testing and simple pipelines. https://github.com/srl-labs/containerlab , https://github.com/ttafsir/automated-network-testing-pytest , https://www.packetswitch.co.uk/simple-network-ci-cd-pipeline/ , https://github.com/network-unit-testing-system/nuts-containerlab-demo
- **[I]** cEOS-lab images require an Arista account download and cannot be pulled from a public registry, so CI must run on a self-hosted runner or cache the image privately; Nokia SR Linux is freely pullable and a good second target; Juniper cRPD/vJunos and Cisco images have licensing constraints. Gate this tier behind a `--real-devices` pytest marker and run nightly rather than per-PR. Test matrix per vendor driver: diff generation, timed rollback fires when unconfirmed, confirm cancels rollback, abort restores, and redaction on `show running-config`.

---

## 7. Open questions to resolve before implementation [I]

1. Which MCP clients the first users actually run, to decide whether elicitation-based approval is worth building in v1 or only CLI/webhook.
2. Whether the proxy will ever run without network access to the SoT (affects policy data caching and the unknown-device default).
3. Key custody for audit checkpoints (file, OS keyring, KMS) and who holds the HMAC key for redaction hashing.
4. Whether to support IOS-XR and SR Linux in the first driver set given their native commit-confirmed support makes them the *easiest* to do safely.
