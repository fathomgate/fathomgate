Scaffold a new MADR architecture decision record at docs/adr/NNNN-slug.md from the template and add it to the ADR index. Usage: `/adr Use goccy/go-yaml instead of gopkg.in/yaml.v3`

Adopt the agent in `.claude/agents/docs-writer.md` for this conversation.

Title: `$ARGUMENTS` (required; if empty, ask for the decision title in one line and stop).

Steps:

1. Determine the next number: `ls docs/adr/ | grep -E '^[0-9]{4}-' | sort | tail -1`. The first ADR is `0001`. If `docs/adr/0000-template.md` does not exist, create it first with these MADR sections: `# <Title>`, `Status:` (`proposed` | `accepted` | `deprecated` | `superseded by NNNN`), `Date:`, `Deciders:`, `## Context and Problem Statement`, `## Decision Drivers`, `## Considered Options`, `## Decision Outcome` (with `### Consequences` listing Good and Bad), `## Pros and Cons of the Options` (one `### <Option>` each), `## More Information` (links to `docs/PLAN.md` sections, `docs/research/*`, upstream source, related ADRs).
2. Slug the title: lowercase, kebab-case, ASCII, no stop-word trimming. Create `docs/adr/NNNN-<slug>.md` from the template.
3. Fill in: Title; Status `proposed`; today's date; Deciders as the owning agent(s) for the affected package plus the reviewers (Go Reviewer; Security Reviewer when the interface is in `internal/redact`, `internal/policy`, `internal/classify`, `internal/approval` or `internal/audit`); Context drawn from the request and the relevant `docs/PLAN.md` section (quote it); Decision Drivers as bullets; at least two Considered Options including the one the plan chose and one rejected alternative with the plan's stated reason; Decision Outcome left as `Pending: to be filled by <owning agent>`; More Information with the links.
4. If the ADR changes an interface, say which in Context using the exact names: `policy.Decision`, `policy.Evaluate`, the class set, the obligation set (`dry_run`, `diff`, `timed_rollback`), the decision effects (`allow`, `hold`, `deny`) and `expired`, `ChangeSafety` (`Prepare`, `Apply`, `Confirm`, `Abort`), `inventory.Resolver`, the profile schema, the policy schema, the audit event schema, the pending-record schema, a CLI subcommand or flag, or a `go.mod` dependency.
5. Add a row to `docs/adr/README.md` (create it with a table header `| ADR | Title | Status | Date |` if absent).
6. Print the file path, the next steps (owning agent fills Decision Outcome; reviewers fill Consequences; Orchestrator flips Status to `accepted`), and remind that the code PR must cite this ADR number and cannot merge while Status is `proposed`.

Voice: lead with the point, plain and calm, technical values in code font, project vocabulary only.
