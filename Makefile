# Fathomgate build and test entry points. Tier 1 (no network) is everything here
# except release-snapshot, which needs goreleaser installed, and conformance,
# which needs Node.js and npm (it installs the pinned suite from the registry).

BINARY   := fathomgate
MODULE   := github.com/fathomgate/fathomgate
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

GO       ?= go
GOFLAGS  ?=
PYTHON   ?= python3
BIN_DIR  := bin

# The Go toolchain CI and releases build with: the `toolchain` line in go.mod
# (ADR 0013). Bump it there, never here.
GO_TOOLCHAIN := $(shell sed -n 's/^toolchain //p' go.mod)

# Pinned CI tools, run with `go run pkg@version` so go.mod stays unchanged.
# govulncheck v1.8.0 declares go 1.26.0; `make vulncheck` runs it under the
# go.mod toolchain (go1.26 since T0.14), so it scans the standard library that
# ships. Keep its Go requirement at or below the toolchain minor.
GOVULNCHECK_VERSION ?= v1.8.0
ACTIONLINT_VERSION  ?= v1.7.12

# golangci-lint is the upstream release binary, not a source build (upstream
# supports only its binaries). `make lint` downloads the archive for the host
# once and checks it against the sha256 pinned below before unpacking it; CI
# runs the same target (T0.20, CONTRIBUTING.md "Bumping golangci-lint"). The
# hashes are the release's checksums.txt lines. v2.9.0 is the first release
# built with Go 1.26; it must be built with a Go minor at least the go.mod
# toolchain's, or it refuses to run.
GOLANGCI_LINT_VERSION             := 2.9.0
GOLANGCI_LINT_SHA256_linux_amd64  := 493aaaca2eba6c8bcef847d92716bbd91bbac4b22cdbb0ab5b6a581b32946091
GOLANGCI_LINT_SHA256_linux_arm64  := 94e80cdb51c73c20a313bd3afa1fb23137728813c19fd730248a1e8678fcc46d
GOLANGCI_LINT_SHA256_darwin_amd64 := ba29a353be54a74c45946763983808dc8305eeeca73db1761b5ab112f87f8157
GOLANGCI_LINT_SHA256_darwin_arm64 := a86eabba3507deddd21f2a01a1df2a0ee5bc5c8178d4165cdcaaad8597358760
GOLANGCI_LINT_PLATFORM            := $(shell $(GO) env GOHOSTOS)-$(shell $(GO) env GOHOSTARCH)
GOLANGCI_LINT_SHA256              := $(GOLANGCI_LINT_SHA256_$(subst -,_,$(GOLANGCI_LINT_PLATFORM)))
GOLANGCI_LINT_DIR                 := $(BIN_DIR)/tools/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(GOLANGCI_LINT_PLATFORM)
GOLANGCI_LINT                     := $(GOLANGCI_LINT_DIR)/golangci-lint

# gitleaks is the upstream release binary too (M1-42), fetched and checked the
# same way: `make secrets-scan` downloads the archive for the host once and
# compares it with the sha256 pinned below (the release's
# gitleaks_<version>_checksums.txt lines, which match GitHub's asset digests)
# before unpacking it. Its release archives name amd64 `x64`. The rules are the
# built-in set of this version plus .gitleaks.toml; findings already judged
# false positives are listed by fingerprint in .gitleaksignore.
# GITLEAKS_LOG_OPTS is passed to `git log`: the default scans every commit
# reachable from HEAD; CI passes `<base>..<head>` on a pull request.
GITLEAKS_VERSION             := 8.30.1
GITLEAKS_SHA256_linux_x64    := 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
GITLEAKS_SHA256_linux_arm64  := e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
GITLEAKS_SHA256_darwin_x64   := dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709
GITLEAKS_SHA256_darwin_arm64 := b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5
# The platform comes from uname, so the scan needs no Go toolchain.
GITLEAKS_OS                  := $(shell uname -s | tr '[:upper:]' '[:lower:]')
GITLEAKS_ARCH                := $(subst x86_64,x64,$(subst aarch64,arm64,$(shell uname -m)))
GITLEAKS_PLATFORM            := $(GITLEAKS_OS)_$(GITLEAKS_ARCH)
GITLEAKS_SHA256              := $(GITLEAKS_SHA256_$(GITLEAKS_PLATFORM))
GITLEAKS_DIR                 := $(BIN_DIR)/tools/gitleaks-$(GITLEAKS_VERSION)-$(GITLEAKS_PLATFORM)
GITLEAKS                     := $(GITLEAKS_DIR)/gitleaks
GITLEAKS_LOG_OPTS            ?= --full-history HEAD

# MCP conformance (T0.4, T0.19, T0.32). The suite version is pinned in
# tests/conformance/package.json and package-lock.json (npm ci). It drives
# each leg over Streamable HTTP through tests/conformance/shim.py: the real
# `fathomgate serve --listen` (a FAKE token, the conf. prefix) or, on a
# control leg, the upstream's own -http handler. Two fixture upstreams, both
# go-sdk's own conformance everything-server:
#   CONFORMANCE_SERVER       at the go-sdk version in go.mod, so a go-sdk bump
#                            rebuilds it in lockstep (legs control, fathomgate)
#   CONFORMANCE_SERVER_2025  at go-sdk v1.6.1, the last release without
#                            2026-07-28, pinned in the test-only module
#                            tests/conformance/upstream-2025 (legs
#                            control-up2025, fathomgate-up2025); never linked
#                            into fathomgate, and go.mod does not change
CONFORMANCE_DIR          := tests/conformance
CONFORMANCE_SERVER       := $(BIN_DIR)/conformance/everything-server
CONFORMANCE_SERVER_2025  := $(BIN_DIR)/conformance/everything-server-2025
CONFORMANCE_UP2025_MOD   := $(CONFORMANCE_DIR)/upstream-2025
CONFORMANCE_REVS         ?= 2025-11-25 2026-07-28
CONFORMANCE_LEGS         ?= control fathomgate control-up2025 fathomgate-up2025
NPM                 ?= npm

.PHONY: all build test vet lint secrets-scan secrets-control vulncheck toolchain-check actionlint fmt policy-test fixtures-check conformance conformance-deps status status-check licences licences-check release-snapshot clean help

all: build test policy-test ## Build, unit-test and run the policy suites

build: ## Build the fathomgate binary into bin/
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) ./cmd/fathomgate

test: ## Run Go unit tests with the race detector
	$(GO) test $(GOFLAGS) -race -count=1 ./...

vet: ## go vet + gofmt check
	$(GO) vet ./...
	@out=$$(gofmt -l . 2>/dev/null); if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

# Runs under the go.mod toolchain once per target in LINT_TARGETS, so a local
# run reports what CI reports whatever Go and host you have. Build tags change
# the result (syscall field types differ per OS and arch, which is how T0.24
# got past a linux/amd64-only lint), so every supported target is linted.
# LINT_GOOS (and optionally LINT_GOARCH, default amd64) lint just one target.
ifdef LINT_GOOS
LINT_TARGETS ?= $(LINT_GOOS)/$(or $(LINT_GOARCH),amd64)
endif
LINT_TARGETS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

lint: $(GOLANGCI_LINT) ## golangci-lint at GOLANGCI_LINT_VERSION (sha256-verified release binary) for each of LINT_TARGETS
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GOLANGCI_LINT) config verify
	@set -e; for t in $(LINT_TARGETS); do \
		echo "golangci-lint run ./... for $$t"; \
		GOTOOLCHAIN=$(GO_TOOLCHAIN) GOOS=$${t%/*} GOARCH=$${t#*/} $(GOLANGCI_LINT) run ./...; \
	done

# Download into a temp dir, compare the sha256 with the pin, and only then
# unpack and move the binary into place, so a failed or mismatched download
# leaves nothing behind for the next run to trust.
$(GOLANGCI_LINT):
	@set -eu; \
	want='$(GOLANGCI_LINT_SHA256)'; \
	name='golangci-lint-$(GOLANGCI_LINT_VERSION)-$(GOLANGCI_LINT_PLATFORM)'; \
	if [ -z "$$want" ]; then \
		echo "no pinned golangci-lint sha256 for $(GOLANGCI_LINT_PLATFORM); see CONTRIBUTING.md"; exit 1; \
	fi; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	url="https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCI_LINT_VERSION)/$$name.tar.gz"; \
	echo "downloading $$url"; \
	curl -fsSL --proto '=https' --tlsv1.2 -o "$$tmp/$$name.tar.gz" "$$url"; \
	if command -v sha256sum >/dev/null 2>&1; then got=$$(sha256sum "$$tmp/$$name.tar.gz"); \
	else got=$$(shasum -a 256 "$$tmp/$$name.tar.gz"); fi; \
	got=$${got%% *}; \
	if [ "$$got" != "$$want" ]; then \
		echo "golangci-lint sha256 mismatch for $$name.tar.gz: got $$got, want $$want"; exit 1; \
	fi; \
	echo "sha256 OK $$got"; \
	tar -xzf "$$tmp/$$name.tar.gz" -C "$$tmp" "$$name/golangci-lint"; \
	mkdir -p '$(GOLANGCI_LINT_DIR)'; \
	mv "$$tmp/$$name/golangci-lint" '$(GOLANGCI_LINT)'

# Scans git history, not the working tree: CI runs it with the full history on
# a push to main and with the pull request's commits on a pull request (M1-42).
# --redact keeps the matched value out of the log; a finding prints its file,
# line, commit, rule and fingerprint. Exit 1 on any finding.
secrets-scan: $(GITLEAKS) ## gitleaks at GITLEAKS_VERSION (sha256-verified release binary) over git history (GITLEAKS_LOG_OPTS)
	$(GITLEAKS) git --config .gitleaks.toml --gitleaks-ignore-path .gitleaksignore \
		--log-opts='$(GITLEAKS_LOG_OPTS)' --redact --verbose --no-banner --exit-code 1 .

# Negative control for .gitleaks.toml: a throwaway repository with FAKE and
# non-FAKE fixture secrets must give exactly the non-FAKE findings, in git
# and dir mode (tools/secrets/control.sh). CI runs it before the scan.
secrets-control: $(GITLEAKS) ## Prove .gitleaks.toml passes only FAKE fixture secrets (negative control)
	sh tools/secrets/control.sh '$(GITLEAKS)' .gitleaks.toml

# Same download discipline as golangci-lint: nothing is unpacked or kept
# unless the archive matches the pinned sha256.
$(GITLEAKS):
	@set -eu; \
	want='$(GITLEAKS_SHA256)'; \
	name='gitleaks_$(GITLEAKS_VERSION)_$(GITLEAKS_PLATFORM).tar.gz'; \
	if [ -z "$$want" ]; then \
		echo "no pinned gitleaks sha256 for $(GITLEAKS_PLATFORM); see Bumping gitleaks in docs/maintainers.md"; exit 1; \
	fi; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	url="https://github.com/gitleaks/gitleaks/releases/download/v$(GITLEAKS_VERSION)/$$name"; \
	echo "downloading $$url"; \
	curl -fsSL --proto '=https' --tlsv1.2 -o "$$tmp/$$name" "$$url"; \
	if command -v sha256sum >/dev/null 2>&1; then got=$$(sha256sum "$$tmp/$$name"); \
	else got=$$(shasum -a 256 "$$tmp/$$name"); fi; \
	got=$${got%% *}; \
	if [ "$$got" != "$$want" ]; then \
		echo "gitleaks sha256 mismatch for $$name: got $$got, want $$want"; exit 1; \
	fi; \
	echo "sha256 OK $$got"; \
	tar -xzf "$$tmp/$$name" -C "$$tmp" gitleaks; \
	mkdir -p '$(GITLEAKS_DIR)'; \
	mv "$$tmp/gitleaks" '$(GITLEAKS)'

# GOTOOLCHAIN is set to the go.mod toolchain so govulncheck scans the standard
# library that ships, whatever Go is installed locally (older or newer). The Go
# command downloads that toolchain once through the module proxy, checked
# against the checksum database.
vulncheck: ## govulncheck ./... at GOVULNCHECK_VERSION with the go.mod toolchain; fails on reachable vulnerabilities
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

toolchain-check: ## Fail unless the Go in use is the go.mod toolchain (CI and release guard)
	@want='$(GO_TOOLCHAIN)'; \
	got="$$($(GO) env GOVERSION)"; \
	if [ -z "$$want" ]; then \
		echo "go.mod has no toolchain line (ADR 0013)"; \
		exit 1; \
	fi; \
	if [ "$$got" != "$$want" ]; then \
		echo "Go in use is $$got, go.mod toolchain is $$want (ADR 0013)"; \
		exit 1; \
	fi; \
	echo "Go in use is $$got, the go.mod toolchain"

actionlint: ## Lint .github/workflows at ACTIONLINT_VERSION (uses shellcheck if on PATH)
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION) -config-file .github/actionlint.yaml

fmt: ## gofmt the tree
	gofmt -w .

policy-test: build ## Run every policies/**/*.test.yaml through fathomgate policy test
	$(BIN_DIR)/$(BINARY) policy test $(shell find policies -name '*.test.yaml' | sort)

fixtures-check: build ## Every redaction fixture must have an expect file and redact cleanly
	@set -e; for f in tests/fixtures/configs/*.txt; do \
		exp="$${f%.txt}.expect.json"; \
		[ -f "$$exp" ] || { echo "missing $$exp"; exit 1; }; \
		FATHOMGATE_REDACT_KEY=fixtures-check $(BIN_DIR)/$(BINARY) redact "$$f" >/dev/null; \
	done; echo "fixtures ok"
	$(GO) test -count=1 -run 'TestFixtureCorpus' ./internal/redact/

# Every leg and revision runs even if an earlier one fails; the target fails
# at the end if any did. era_pairs.py then drives the two upstream-prompt
# cells the suite cannot reach for a 2025 upstream (ADR 0014 among them),
# over stdio and over the listener.
# tests/conformance/README.md explains the legs and the baselines.
conformance: build conformance-deps ## Official MCP conformance suite against fathomgate serve, both eras (needs Node.js)
	@failed=""; \
	for rev in $(CONFORMANCE_REVS); do \
		for leg in $(CONFORMANCE_LEGS); do \
			FATHOMGATE_BIN=$(CURDIR)/$(BIN_DIR)/$(BINARY) CONFORMANCE_SERVER=$(CURDIR)/$(CONFORMANCE_SERVER) \
			CONFORMANCE_SERVER_2025=$(CURDIR)/$(CONFORMANCE_SERVER_2025) PYTHON="$(PYTHON)" \
				$(CONFORMANCE_DIR)/run.sh $$leg $$rev || failed="$$failed $$leg/$$rev"; \
		done; \
	done; \
	echo "== era pairs, 2025-11-25 upstream"; \
	$(PYTHON) $(CONFORMANCE_DIR)/era_pairs.py --fathomgate $(BIN_DIR)/$(BINARY) --upstream $(CONFORMANCE_SERVER_2025) || failed="$$failed era-pairs"; \
	if [ -n "$$failed" ]; then echo "conformance failed:$$failed"; exit 1; fi; \
	echo "conformance ok: $(CONFORMANCE_LEGS) x $(CONFORMANCE_REVS), era pairs"

conformance-deps: $(CONFORMANCE_SERVER) $(CONFORMANCE_SERVER_2025) $(CONFORMANCE_DIR)/node_modules/.package-lock.json

# A file target: rebuilt whenever go.mod or go.sum changes (a go-sdk bump).
$(CONFORMANCE_SERVER): go.mod go.sum
	@mkdir -p $(dir $@)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -o $@ github.com/modelcontextprotocol/go-sdk/conformance/everything-server

# Built from its own module (a `tool` line in upstream-2025/go.mod), so the
# root go.mod never sees go-sdk v1.6.1. Rebuilt only when that module changes.
$(CONFORMANCE_SERVER_2025): $(CONFORMANCE_UP2025_MOD)/go.mod $(CONFORMANCE_UP2025_MOD)/go.sum
	@mkdir -p $(dir $@)
	CGO_ENABLED=0 $(GO) -C $(CONFORMANCE_UP2025_MOD) build $(GOFLAGS) -trimpath -o $(CURDIR)/$@ github.com/modelcontextprotocol/go-sdk/conformance/everything-server

$(CONFORMANCE_DIR)/node_modules/.package-lock.json: $(CONFORMANCE_DIR)/package.json $(CONFORMANCE_DIR)/package-lock.json
	cd $(CONFORMANCE_DIR) && $(NPM) ci --ignore-scripts --no-audit --no-fund

release-snapshot: ## Local GoReleaser dry run (needs goreleaser)
	goreleaser release --snapshot --clean --skip=publish

clean: ## Remove build outputs
	rm -rf $(BIN_DIR) dist $(CONFORMANCE_DIR)/node_modules $(CONFORMANCE_DIR)/results

status: ## Re-render STATUS.md from docs/milestones/<CURRENT>.yaml and docs/handoffs/
	$(PYTHON) tools/status/render.py

status-check: ## Fail if STATUS.md is stale relative to the board (CI)
	$(PYTHON) tools/status/render.py --check

# ADR 0020: THIRD_PARTY_LICENSES/ holds the licence text of every module linked
# into fathomgate on every release target, and ships in each archive and
# image. Regenerate after a dependency change; CI and the GoReleaser before
# hook run the check. Standard-library Python plus the go and git commands;
# no new Go dependency.
licences: ## Regenerate THIRD_PARTY_LICENSES/ from the modules linked into fathomgate (ADR 0020)
	$(PYTHON) tools/licences/third_party.py

licences-check: ## Fail if THIRD_PARTY_LICENSES/ or NOTICE is stale, or a source file lacks the SPDX line for its path (CI, ADR 0034)
	$(PYTHON) tools/licences/third_party.py --check
	$(PYTHON) tools/licences/spdx.py

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'
