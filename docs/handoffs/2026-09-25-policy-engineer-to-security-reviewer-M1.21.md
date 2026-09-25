# M1-21: example policy cases for matrix rows 3, 4 and 6, and lab-open without dry_run and diff until M3; review what the examples now allow

- **Task:** M1-21 — Example policy cases for the M1 matrix rows, and the M1 behaviour of lab-open and prod-approval
- **From → To:** policy-engineer → security-reviewer
- **State now:** in review. This PR does not edit `docs/milestones/` or `docs/adr/` (the board row and ADR 0026 as accepted are on PR #153's branch).
- **Branch / PR:** `feat/policy-m1-cases` · PR link in the PR description (opened with this note)
- **Date:** 2026-09-25

## Done

- `policies/examples/lab-open.yaml`: `lab-writes-free` drops `obligations: [dry_run, diff]` (ADR 0026 decision 1). Header and rule comments say they return in M3. No other rule changed; lab-open had no `redact` or other obligation to keep.
- `policies/examples/prod-approval.yaml`: comment only. Says a hold from `prod-core-needs-approval` and an allow from `lab-writes-free` are not forwarded in M1 and M2, and quotes the ADR 0026 hold text.
- `*.test.yaml`: 25 to 43 cases. Rows 3, 4 and 6 in all three suites; row 4 names netdev-ssh-mcp `run_show_command`, upa `send_command_and_get_output` and eos-mcp `run_command`; row 6 covers writes and exec. lab-open gains a non-firing case for `lab-lifecycle`, a mixed lab-plus-prod write, and pins `obligations: []` on the lab write (an empty list is enforced: checked against prod-approval, where it fails).
- `docs/specs/policy-schema.md` section 9: counts, lab-open's M1 behaviour, and the runner limit below. CHANGELOG Unreleased: Added and Changed.

## Look at this first

- `policies/examples/lab-open.yaml`: in M1 a lab write is now forwarded with no dry run and no diff. That is the maintainer's decision; check the unknown-target default (runs first) and `not-lab` (anything untagged) still fence it, which the row 6 and mixed-write cases pin.

## Deliberately unfinished

- **Runner gap.** A `*.test.yaml` case takes `class` as given; `server` and `tool` are carried into `Request` but nothing classifies, and a case has no field for arguments or commands. So rows 3 and 4 are class-level here; the profile half is tier 1 (`internal/classify`) and `policy eval --profile`. Closing it means adding `arguments` plus a profile to the test-file schema, which is a spec and CLI-surface change needing an ADR.
- **PR #152 injection inputs are not in the suites** for the same reason. On `main` today, through `read-only.yaml` with `inventory.example.yaml`, each of these is `allow READ_OPERATIONAL reads-anywhere`: `show clock\nconf t\nhostname pwned\nend` and `show clock\ntclsh` (netdev `run_show_command`), `show clock\ncopy run start` and `show clock\nrelo\n\nshow clock` (eos `run_command`). PR #152 makes them `deny EXEC_ARBITRARY no-exec`.
- No upa profile on `main` (PR #150); the upa cases name `server: upa`, which the runner does not resolve.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && make policy-test && make fixtures-check && make status-check && make licences-check
bin/fathomgate policy test policies/examples/*.test.yaml                  # 43 cases, 43 passed
uv run --with pyyaml python tools/policy-lint/policy-lint policies/examples/lab-open.yaml policies/examples/prod-approval.yaml policies/examples/read-only.yaml
bin/fathomgate policy eval --policy policies/examples/read-only.yaml --inventory inventory.example.yaml \
  --profile profiles/eos-mcp.yaml --server eos-mcp --tool run_command --arg hostname=lab-sw-01 --arg command=reload   # deny EXEC_ARBITRARY no-exec
```

## Decisions made without an ADR

- prod-approval gets a comment, not a rule change: the board note asks for the comment; the rules stay as the PLAN example.
- Row 6 in lab-open uses an unknown target that carries a `lab` tag, to pin that the unknown-target default wins over `lab-writes-free` whatever the tags say.

## Questions for the receiver

- Should lab-open in M1 add anything in place of `dry_run` and `diff` (for example a lower `max_devices` than 50), or is `not-lab` plus the unknown-target default enough until M3?
