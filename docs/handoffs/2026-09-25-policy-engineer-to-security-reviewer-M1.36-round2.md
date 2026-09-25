# M1-36 round 2: every finding from the PR #170 security review addressed, ready for re-review

- **Task:** M1-36: Config lines that leave the configure session make a write EXEC_ARBITRARY
- **From → To:** policy-engineer → security-reviewer
- **State now:** in review
- **Branch / PR:** feat/classify-config-escape · https://github.com/fathomgate/fathomgate/pull/170
- **Date:** 2026-09-25

## Done

- H1: in the CLI dialect, a line containing `;` fails with the new check id `separator`. NX-OS (reached through netmiko `cisco_nxos` by upa and ntunes) is now named in spec 11.2.
- H2: `alias` and `cli` are escape words. The threat model has a new row for operator-configured aliases, marked accepted. Gate `TestConfigSessionEscape` covers the two-call sequence: the definition is denied, and `["hn", ""]` on its own is still a write.
- H3: scheduled execution is now `EXEC_ARBITRARY`.
  - CLI: `event`, `event-handler`, `schedule`, `scheduler`, `kron`, `daemon` and `command` are escape words. `event-monitor` still passes.
  - Junos set: a line fails with `exec-config` when any word after the first abbreviates `event-options`, `scripts`, `extensions` or `execute-commands`.
  - Junos text and xml: a line fails when it contains one of those words as a case-insensitive substring.
  - Spec 11.5 no longer lists scheduled execution as residual. The threat model has a new row "persistence and lock-out by configuration" (stays `WRITE_CONFIG` by design).
- M1: added `ping`, `traceroute`, `clock`, `send`, `watch`, `logout`, `terminal`, `agent`, `return`, `system-view` and `admin`. Spec 11.5 and the threat model name the EOS `push_config` top-level allow-list as the open long-term fix.
- M2: Junos `top` must stand alone and `up` may carry only a count. Anything else fails `set-verb`.
- L1: the `no-exec` reason in all three example policies now reads "EXEC_ARBITRARY is denied: the call runs commands outside the read allow-list or outside configuration mode". The pinned strings are updated in the gate and proxy tests and in profile-schema.md 8.2.
- L2: in Junos xml, a line containing `<!` fails with `dtd`.
- Note 1: a line may be at most 1024 bytes in the CLI and Junos set dialects (the command cap). The whole payload may be at most 64 KiB (the gate cap), in every dialect. Junos text and xml lines have no per-line cap.
- Note 2: the threat model has a new row for shell hosts behind netmiko.
- Merged origin/main first. Every input from the review is a case in `internal/classify/security_test.go`.

## Look at this first

- `internal/classify/config.go`, specifically `checkJunosSetLine`. It holds the new abbreviation rule, which uses prefix tokens with quotes stripped.

## Deliberately unfinished

- The EOS `push_config` allow-list of top-level configuration words is recorded as open in spec 11.5 and the threat model. It needs its own task.
- Tier-2 list for M1-28 on cEOS: whether `end` in one eAPI call escapes the session; `clock set`, `watch` and `terminal` from configuration mode; `alias hn reload now` followed by `hn`.
- `make conformance` was not run. The only `internal/proxy` change is a pinned deny string in a test; no proxy code changed.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./...        # -race needs cgo; not on this Windows host
~/go/bin/golangci-lint run ./...                       # 0 issues
go build -o bin/fathomgate.exe ./cmd/fathomgate
bin/fathomgate.exe policy test policies/examples/lab-open.test.yaml policies/examples/prod-approval.test.yaml policies/examples/read-only.test.yaml   # 45 cases, 45 passed
uv run --with pyyaml python tools/policy-lint/policy-lint policies/examples/lab-open.yaml policies/examples/prod-approval.yaml policies/examples/read-only.yaml
uv run --with pyyaml python tools/licences/spdx.py && uv run --with pyyaml python tools/licences/third_party.py --check
uv run --with pyyaml python tools/status/render.py --check
```

## Decisions made without an ADR

- H3 (Junos set): the reviewer asked for token equality. The code instead fails any word after the first that is a non-empty prefix of one of the four hierarchy names, with quotes stripped. This covers Junos unique abbreviations such as `set event-o ...`, and it is stricter.
- Removing `clock timezone` and `system mtu` from the lines that stay writes is an accepted cost: `clock` and `system-view` are now escape words.
- For the payload cap I kept one number, 64 KiB, the same as the gate cap. It applies to the classifier on its own too (`policy eval`).

## Questions for the receiver

- Is the prefix test for Junos hierarchy names acceptable, given it can fail a stray one-letter token such as `s` or `e`?
