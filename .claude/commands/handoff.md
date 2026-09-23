Hand a task to another agent: update the board, write the handoff note, re-render STATUS.md, and (if the GitHub mirror is configured) update the issue. Usage: `/handoff <to-agent-slug> <task-id> [new-state]`, e.g. `/handoff go-reviewer T0.2 "in review"`.

Stay in whatever agent you currently are; this command is the last thing an agent does before it stops.

Arguments: `$ARGUMENTS` — `<to>` (an agent slug from `.claude/agents/` or a GitHub handle), `<task-id>` (from `docs/milestones/<Mn>.yaml`), optional `<new-state>` (one of `open`, `in progress`, `in review`, `merged`, `validated`, `blocked`, `dropped`; if omitted, infer: handing to a reviewer means `in review`, a reviewer handing back to the owner means `in progress`, handing to test-engineer after merge means `merged`).

Do the following, in order:

1. Read `docs/milestones/CURRENT` and the matching YAML. Find the task. If it does not exist, stop and say so; do not invent a row.
2. Refuse to set `validated` unless you are `test-engineer`; refuse to set `merged` unless `git log origin/main` contains the PR's merge commit. Say why and set the closest permitted state instead.
3. Set the task's `state`. If the new state is `blocked`, add or update an entry under `blockers:` with an id, the text, and an owner.
4. Create `docs/handoffs/<YYYY-MM-DD>-<your-slug>-to-<to>-<task-id>.md` from `docs/handoffs/_template.md`. Fill every section from what you actually did in this session: file paths, commands run and their last line of output, the PR link if one exists. "Reproduce green" must contain the exact commands you ran. Keep it under a screen.
5. Run `make status` (equivalently `python3 tools/status/render.py`). Confirm `STATUS.md` changed.
6. If `gh` is available and authenticated, find the issue titled `<task-id> …`; if it exists, swap its `state:` label and add a comment linking the note by path. If `gh` is missing or unauthenticated, skip this step and say so in one line; the YAML is the source of truth.
7. Stage the YAML, the note and `STATUS.md` together with your code changes. Commit message scope is the package you touched, and the body's last line is `Handoff: <to> <task-id> (<new-state>)`.
8. Print: the task row as it now stands, the path of the note, and the one sentence the receiver should read first.

Never edit `STATUS.md` by hand. Never write a handoff note that says "see chat"; if the receiver would need the conversation to understand the task, the note is not finished.
