# <one line: what this handoff is>

- **Task:** <Tn.m> — <title from docs/milestones/<Mn>.yaml>
- **From → To:** <from-slug> → <to-slug>
- **State now:** <open | in progress | in review | merged | validated | blocked>
- **Branch / PR:** <branch name> · <PR link or "none yet">
- **Date:** <YYYY-MM-DD>

## Done

- <what changed, by file or package; one bullet per meaningful change>

## Look at this first

- <the one file, function or test the receiver should open first, and why>

## Deliberately unfinished

- <what was left out on purpose and the reason; "nothing" is a valid answer>

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check
# plus anything task-specific, e.g.:
# bin/fathomgate policy eval --policy policies/examples/prod-approval.yaml --inventory inventory.example.yaml --server junos-mcp-server --tool load_and_commit_config --class WRITE_CONFIG --target core-rtr-01
```

## Decisions made without an ADR

- <any judgement call the receiver might disagree with; if it changed an interface, stop and open an ADR instead>

## Questions for the receiver

- <at most three>
