Run the NetGuard release checklist for a version: preflight on main, snapshot build and inspection, container and snippet checks, CHANGELOG cut, signed tag, post-release verification. Usage: `/release v0.2.0`

Adopt the agent in `.claude/agents/release-engineer.md` for this conversation.

Version: `$ARGUMENTS` (required; `vX.Y.Z`. If empty, propose the next version from `CHANGELOG.md` `[Unreleased]` using the semver rules in the agent file and stop for confirmation).

Steps; stop at the first failure and report the blocking reason:

1. Gate: `docs/adr/` has an `accepted` naming ADR if this is a public tag (otherwise only `goreleaser release --snapshot --clean` is permitted). `CHANGELOG.md` `[Unreleased]` is non-empty. No `critical` or `high` finding is open in `docs/security/threat-model.md`. The Orchestrator has marked the milestone closed in `ROADMAP.md` and the Test Engineer's report names the validated upstream servers with image tags.
2. Preflight on the candidate commit on `main`: `git status --porcelain` is empty; `go test ./... -race -count=1 && golangci-lint run && make policy-test && make conformance`; `uv run pytest tests/tier2 -q`; `gitleaks detect --no-git --source .`; `go mod verify`; `go version -m ./netguard | grep modelcontextprotocol/go-sdk` shows the pinned minor.
3. Snapshot: `goreleaser release --snapshot --clean`. For each artefact: `file dist/*/netguard*` reports statically linked; `dist/netguard_linux_amd64_v1/netguard version` prints the version, commit and go-sdk version; an SPDX SBOM exists per archive; `cosign sign-blob` dry-run works on `dist/checksums.txt`.
4. Container: build the distroless image; `docker run --rm <image> version`; `docker inspect --format '{{.Config.User}}' <image>` prints `nonroot`; `docker run --rm --entrypoint sh <image>` fails (no shell); multi-arch manifest present.
5. Snippets: `uv run pytest tests/tier2 -m launcher -v` runs the PATH-stripped launcher case against each `mcp.json` snippet in `docs/install.md` (Claude Desktop, Claude Code, Cursor) using this build. All must pass; fix absolute paths if the binary location or flags changed.
6. Cut `CHANGELOG.md`: rename `[Unreleased]` to `[X.Y.Z] - <today>`, add the compare link, open a new empty `[Unreleased]`. Draft release notes from that section plus the fixed footer: install commands (`brew install joshscott13/netguard/netguard`, `docker pull ghcr.io/joshscott13/netguard:vX.Y.Z`, release binary), `cosign verify-blob` and checksum commands, SBOM link, supported MCP eras (2025-11-25, 2026-07-28), validated upstream servers with image tags.
7. Open the release PR with the preflight links; request Docs Writer, Security Reviewer and Orchestrator approvals. After merge: `git tag -s vX.Y.Z -F <(sed -n '/^## \[X.Y.Z\]/,/^## \[/p' CHANGELOG.md)` and `git push origin vX.Y.Z`. Watch `.github/workflows/release.yaml`.
8. Post-release: `brew install joshscott13/netguard/netguard && netguard version`; `cosign verify-blob` on `checksums.txt`; `docker pull` and `cosign verify` on the image; confirm the GitHub release page shows notes, SBOMs, checksums and signatures. Hand the release URL and install commands to Docs Writer for the README status line and, at M1, the announce post.

Release notes use the project vocabulary (`allow`, `hold`, `deny`, `expired`; class names; `dry_run`, `diff`, `timed_rollback`) and no synonyms. Never tag from a red `main`, with cgo, without `-trimpath`, without a signed `checksums.txt` and SBOM, or with a relative path in any snippet.
