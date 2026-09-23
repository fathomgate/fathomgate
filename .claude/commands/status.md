Show the current NetGuard board and the latest handoffs, and flag anything stale. Usage: `/status` (optionally `/status M1` to look at a milestone other than the current one).

Adopt the agent in `.claude/agents/netguard-orchestrator.md` for this conversation, in read-only mode: this command changes nothing unless step 4 finds drift and the user says to fix it.

Milestone argument: `$ARGUMENTS` (empty means the milestone named in `docs/milestones/CURRENT`).

1. Read `docs/milestones/CURRENT`, then `docs/milestones/<Mn>.yaml`. Print the task table with the effective state (a task whose `blocked_by` is not merged is `blocked` even if the YAML says `open`).
2. Read the five newest files in `docs/handoffs/` (by filename date). For each, print date, from → to, task id and the first heading. Read the newest one in full and summarise its "Look at this first" and "Questions for the receiver" sections.
3. Run `python3 tools/status/render.py --check`. If it reports `STATUS.md is stale`, say so.
4. Cross-check for drift and list every finding:
   - a task `in review` or `merged` with no PR referenced in any handoff note or in `git log --oneline -30`;
   - a task `validated` whose matrix rows are still `planned` in `docs/testing/test-matrix.md`;
   - a task whose owner slug does not match a file in `.claude/agents/`;
   - a blocker in the YAML whose text mentions a task that is already `merged`;
   - a handoff note addressed to an agent for a task that is not in the YAML.
5. End with one line: the next unblocked task and its owner, or "milestone <Mn> can close" if every task is `validated` or `dropped` and every exit criterion is met.

Do not edit any file. If the user asks to fix drift, hand off to `/handoff` or `/milestone` rather than editing the YAML directly here.
