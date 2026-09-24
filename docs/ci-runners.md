# CI runners

Every CI job runs on the maintainer's own machine, not on GitHub's hosted runners. The repository is private, and its free hosted-runner minutes ran out on 2026-09-24. Self-hosted runner minutes cost nothing, so the workflows stay as they are and point `runs-on` at those runners.

The consequence to keep in mind: **CI runs only while that machine is on and WSL is up.** A pull request pushed while it is off waits in the queue, and nothing is lost.

## What runs where

| Label set | Runner | Jobs |
| --- | --- | --- |
| `[self-hosted, Linux, X64, netguard]` | `ng-wsl-1`, `ng-wsl-2`, `ng-wsl-3`: three instances in the WSL `Ubuntu` distro, so three jobs run at once | every job in `ci.yaml` except the Windows one, plus `snapshot.yaml` and `release.yaml` |
| `[self-hosted, Windows, X64, netguard]` | none registered yet | `ci.yaml` job `windows` (elevated audit DACL tests), which is skipped until the repository variable `NETGUARD_WINDOWS_RUNNER` is `true` |
| `[self-hosted, clab]` | none yet (tier 3, M3/M5) | `nightly-clab.yaml` |

The conformance tests pick a free loopback port on every run, so jobs from different pull requests can share the machine.

The runners use Rancher Desktop's docker CLI. Its default config names `docker-credential-wincred.exe`, which a runner service cannot start, so every job that uses docker (`snapshot.yaml`, `release.yaml`) first points `DOCKER_CONFIG` at an empty, job-local config.

## While the Windows job is skipped

The Windows job is the only place the audit key-file DACL, junction and other-owner tests run elevated. Until an elevated Windows runner exists, a pull request that touches `internal/audit` must paste the result of this, run from an **elevated** PowerShell or Git Bash, into its description:

```sh
NETGUARD_REQUIRE_PRIVILEGED_TESTS=1 go test -count=1 -v -run 'Windows' ./internal/audit/
```

Every `TestNewWriterWindows*`, `TestSaveKeyWindowsDACL`, `TestWriterWindowsDACL` and `TestWindowsDanglingSymlinkNotFollowed` subtest must print `--- PASS`, and none may print `--- SKIP` (the list is in `.github/workflows/ci.yaml`, job `windows`).

An elevated runner would be a GitHub runner service running as an administrator on the maintainer's desktop, so any workflow step would run with that authority. That is why it is not registered by default.

## One-time setup (already done for ng-wsl-1..3)

Registration, with the maintainer's `gh` login:

```sh
TOKEN=$(gh api -X POST repos/joshscott13/netguard/actions/runners/registration-token -q .token)
# in WSL, for i in 1 2 3: download actions-runner-linux-x64 into ~/actions-runner-$i, then
./config.sh --unattended --url https://github.com/joshscott13/netguard --token "$TOKEN" \
  --name "ng-wsl-$i" --labels netguard,wsl --work _work
```

Then, once, in the WSL `Ubuntu` shell (needs `sudo`), [`tools/ci/wsl-runner-setup.sh`](../tools/ci/wsl-runner-setup.sh) installs `shellcheck` for actionlint and installs and starts the three runners as systemd services.

Keep WSL running when no terminal is open, in `%UserProfile%\.wslconfig` on Windows:

```ini
[general]
instanceIdleTimeout=-1

[wsl2]
vmIdleTimeout=-1
```

WSL starts when the maintainer logs in and opens any WSL-based tool (Rancher Desktop starts it too); the services then start with systemd.

## Checking and removing

```sh
gh api repos/joshscott13/netguard/actions/runners -q '.runners[]|.name+" "+.status'
```

To remove a runner: in WSL, `cd ~/actions-runner-N && sudo ./svc.sh stop && sudo ./svc.sh uninstall`, then `./config.sh remove --token <a removal token from gh api -X POST repos/joshscott13/netguard/actions/runners/remove-token -q .token>`.

## Security

The runners run as the WSL user, who can reach Docker and the Windows drive under `/mnt/c`. That is acceptable only because the repository is private and every push comes from the maintainer or the maintainer's agents. **If the repository ever becomes public, move every job back to hosted runners first**: a pull request from a fork would otherwise run its code on this machine.
