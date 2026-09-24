# Status and handoffs

Work state lives in the repo, not in anyone's chat window. Three files carry it:

| File | Role | Who writes it |
| --- | --- | --- |
| `docs/milestones/<Mn>.yaml` | The board. One task per row: id, title, package, owner, reviewers, state, `blocked_by`, matrix rows, ADR. Source of truth. | The orchestrator on `/milestone`; any agent when its own task changes state |
| `STATUS.md` | One-screen render of the current board plus the last five handoffs. Generated; never edited by hand. CI fails if it is stale. | `make status` |
| `docs/handoffs/<date>-<from>-to-<to>-<task>.md` | What one agent leaves for the next: what is done, what to look at first, what is deliberately unfinished, how to reproduce green. | The agent handing work on |

`docs/milestones/CURRENT` names the milestone `STATUS.md` renders.

Notes written before [ADR 0019](../adr/0019-rename-to-fathomgate.md) use the placeholder name NetGuard and the identifiers in that record's scope table (`netguard`, `NETGUARD_*`, `ng3.`, the slug `netguard-orchestrator`), and are left as written, file names included; the scope table maps each one to its Fathomgate name.

## Task states

`open` → `in progress` → `in review` → `merged` → `validated`. Side states: `blocked` (derived when a `blocked_by` task is not yet merged, or set explicitly) and `dropped`.

- `merged` means the PR is on `main` and CI is green.
- `validated` means the test-matrix rows the task names have run against the named real upstream server and `docs/testing/test-matrix.md` says so. Only the test-engineer moves a task to `validated`.
- A milestone closes when every task is `validated` or `dropped` and every exit criterion is ticked. An open criterion is a plain string under `exit_criteria`; a met one is a mapping `{text: ..., met: "<date> (<evidence>)"}`, rendered as `- [x]` in `STATUS.md`.

## The handoff ritual

Every time work crosses an agent boundary (dev → reviewer, reviewer → dev with findings, dev → docs, anyone → orchestrator at end of session):

1. Update your task's `state` in `docs/milestones/<Mn>.yaml`.
2. Copy `docs/handoffs/_template.md` to `docs/handoffs/<YYYY-MM-DD>-<from-slug>-to-<to-slug>-<task-id>.md` and fill every section. Keep it under a screen. Commands, not prose, wherever possible.
3. Run `make status` and commit the YAML, the note and `STATUS.md` together, in the same commit as the code when there is code.
4. If the work has a PR, link the note from the PR description and the PR from the note.

The receiving agent's first action is to read the latest note addressed to it, then `STATUS.md`. Nothing about the task should need to be asked in chat.

Slash commands: `/status` prints the board and the latest handoffs; `/handoff <to> <task>` scaffolds the note and updates the YAML.

## Slugs

Agents: `orchestrator`, `mcp-protocol-engineer`, `policy-engineer`, `network-safety-engineer`, `security-reviewer`, `go-reviewer`, `test-engineer`, `design-guardian`, `docs-writer`, `release-engineer`, `upstream-server-scout`. A human is their GitHub handle (`joshscott13`).

## GitHub mirror

The board is mirrored to GitHub Issues so notifications and the Projects view work without making GitHub the source of truth:

- One issue per task, titled `<task-id> <title>`, labelled `agent:<owner>`, `state:<state>`, `milestone:<Mn>`.
- `/milestone` opens missing issues; `/handoff` updates the `state:` label and comments with the note's path.
- Labels are defined in `.github/labels.yml` (apply with `gh label create` or a labels-sync action).

If the YAML and the issue disagree, the YAML wins and the issue is corrected.

## Why files and not a tracker

Agents run in different tools (Claude Code, Codex, Cursor, a Kanban bot) and across sessions. A file in the repo is the one place all of them can read and write with the same tool, it is versioned with the code it describes, and it survives every context window. The render step exists so a human gets one page without reading YAML, and the CI check exists so that page cannot silently drift.
