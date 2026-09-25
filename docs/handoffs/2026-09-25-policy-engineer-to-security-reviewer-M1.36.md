# Config payload lines that leave the configure session make a write EXEC_ARBITRARY: ready for security review

- **Task:** M1-36: Config lines that leave the configure session make a write EXEC_ARBITRARY
- **From → To:** policy-engineer → security-reviewer
- **State now:** in review
- **Branch / PR:** feat/classify-config-escape · https://github.com/fathomgate/fathomgate/pull/170
- **Date:** 2026-09-25

## Done

- `internal/classify/config.go` (new): `checkConfigPayload`, which `Classify` calls before the command rules for any tool with `config_params` whose class is not `EXEC_ARBITRARY`. A failure makes the call `EXEC_ARBITRARY` with `class_source: reclassify`. The reason names the element, the line and the check id (`control-character`, `non-ascii`, `leading-symbol`, `escape-word` or `set-verb`) and never the text.
- CLI union list (`cliEscapeWords`) for eos-mcp, upa, ntunes and any profile the table does not name. The first word matches by one-way prefix, so abbreviations are caught.
- Junos load for junos-mcp-server `load_and_commit_config`. `config_format` set (the default) is an allow-list of set statements. `text` and `xml` are data, so only the byte checks apply.
- Docs:
  - `docs/specs/classification.md`: section 11 (new), plus the section 2 step 1, `reclassify` row, section 9 and section 10 updates
  - `docs/security/threat-model.md`: the push_config row and the JSON-string row
  - profile notes: eos-mcp hazard 3, upa, ntunes, junos

## Look at this first

- `internal/classify/config.go` `cliEscapeWords` and `checkCLIConfigLine`, then `TestConfigLinesThatStayWrites` in `security_test.go`, the negative cases that show what the list lets through.

## Deliberately unfinished

- Configuration that schedules execution stays `WRITE_CONFIG`: EOS `schedule`, `event-handler` and `daemon`, IOS EEM, Junos `event-options` (spec 11.5). This needs a separate decision on whether config content can raise a class.
- Tier 2 on cEOS, to prove whether a line after `end` runs inside one eAPI call, is M1-28. The check does not depend on the answer.
- The `no-exec` deny reason in the example policies still says "command did not pass the read allow-list" for a config escape. That text is pinned by the gate tests.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./...        # -race needs cgo; not available on this Windows host
~/go/bin/golangci-lint run ./...                       # 0 issues
go build -o bin/fathomgate.exe ./cmd/fathomgate
bin/fathomgate.exe policy test policies/examples/lab-open.test.yaml policies/examples/prod-approval.test.yaml policies/examples/read-only.test.yaml   # 45 cases, 45 passed
uv run --with pyyaml python tools/licences/spdx.py && uv run --with pyyaml python tools/licences/third_party.py --check
uv run --with pyyaml python tools/status/render.py --check
bin/fathomgate.exe policy eval --policy policies/examples/lab-open.yaml --inventory inventory.example.yaml --profile profiles/eos-mcp.yaml --tool push_config --arg hostname=lab-sw-01 --arg config_lines=end
# decision: deny, class EXEC_ARBITRARY (profile WRITE_CONFIG; config element 1 line 1 failed the config payload check (escape-word)), rule no-exec
```

## Decisions made without an ADR

- The dialect is a Go table keyed by profile server and tool (`configDialects`), not a profile field, because a profile field would be a schema change. An unknown server gets the union, which is stricter.
- `show` and `more` are escape words on every vendor. A write needs no read. On EOS, `show` runs inside the session and its output would ride on the write's result.
- `enable`, `disable`, `exit` and `delete` are blocked everywhere in the CLI dialect, at the costs listed in spec 11.2.
- For Junos set format, the conservative default is an allow-list, because whether the load-configuration RPC acts on `run` or `commit` is not established from source.

## Questions for the receiver

- Should the escape list also cover the execution-scheduling configuration in spec 11.5 (EOS `schedule`, `event-handler`, `daemon`), or should that wait for M3 diff review?
- Is the one-way prefix match with `[a-z0-9_-]` word boundaries right? `end!` counts as `end`, and `exit-address-family` passes.
