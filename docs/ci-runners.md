# CI runners

Every CI job runs on GitHub-hosted runners (`ubuntu-latest`, and `windows-latest` for the elevated audit job). The repository is public, so hosted minutes are free.

From 2026-09-24, for one day, CI ran on three self-hosted runners in the maintainer's WSL Ubuntu, because the private repository's free minutes had run out. They were removed when the repository was made public on 2026-09-24. Self-hosted runners on a public repository run code from pull requests opened on forks, on the maintainer's machine.

## Rules

- **No job in this repository targets a self-hosted runner that is reachable from a pull request.** The only self-hosted label left is `clab` (`nightly-clab.yaml`, tier 3, arriving M3/M5). That workflow runs on `schedule` and `workflow_dispatch` only, never on `pull_request`, and stays off until the repository variable `FATHOMGATE_CLAB_ENABLED` is `true`.
- Before a `clab` runner is registered, the repository setting **Actions → General → Approval for running fork pull request workflows** must be "Require approval for all outside collaborators", and the runner must run in an isolated VM or container with no access to the maintainer's files or credentials.
- The private commercial repository (ADR 0020) may use self-hosted runners, because nothing from a fork can reach it.
