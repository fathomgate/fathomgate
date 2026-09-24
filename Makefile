# NetGuard build and test entry points. Tier 1 (no network) is everything here
# except release-snapshot, which needs goreleaser installed, and conformance,
# which needs Node.js and npm (it installs the pinned suite from the registry).

BINARY   := netguard
MODULE   := github.com/joshscott13/netguard
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

# MCP conformance (T0.4). The suite version is pinned in
# tests/conformance/package.json and package-lock.json (npm ci). The fixture
# upstream is go-sdk's own conformance everything-server at the go-sdk
# version in go.mod, so a go-sdk bump rebuilds it in lockstep.
CONFORMANCE_DIR     := tests/conformance
CONFORMANCE_SERVER  := $(BIN_DIR)/conformance/everything-server
CONFORMANCE_REVS    ?= 2025-11-25 2026-07-28
CONFORMANCE_LEGS    ?= control netguard
NPM                 ?= npm

.PHONY: all build test vet lint vulncheck toolchain-check actionlint fmt policy-test fixtures-check conformance conformance-deps status status-check release-snapshot clean help

all: build test policy-test ## Build, unit-test and run the policy suites

build: ## Build the netguard binary into bin/
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) ./cmd/netguard

test: ## Run Go unit tests with the race detector
	$(GO) test $(GOFLAGS) -race -count=1 ./...

vet: ## go vet + gofmt check
	$(GO) vet ./...
	@out=$$(gofmt -l . 2>/dev/null); if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

lint: ## golangci-lint (falls back to vet if not installed)
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; else echo "golangci-lint not installed; running go vet"; $(MAKE) vet; fi

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

policy-test: build ## Run every policies/**/*.test.yaml through netguard policy test
	$(BIN_DIR)/$(BINARY) policy test $(shell find policies -name '*.test.yaml' | sort)

fixtures-check: build ## Every redaction fixture must have an expect file and redact cleanly
	@set -e; for f in tests/fixtures/configs/*.txt; do \
		exp="$${f%.txt}.expect.json"; \
		[ -f "$$exp" ] || { echo "missing $$exp"; exit 1; }; \
		NETGUARD_REDACT_KEY=fixtures-check $(BIN_DIR)/$(BINARY) redact "$$f" >/dev/null; \
	done; echo "fixtures ok"
	$(GO) test -count=1 -run 'TestFixtureCorpus' ./internal/redact/

# Every leg and revision runs even if an earlier one fails; the target fails
# at the end if any did. tests/conformance/README.md explains the legs and the
# baselines.
conformance: build conformance-deps ## Official MCP conformance suite against netguard serve, both eras (needs Node.js)
	@failed=""; \
	for rev in $(CONFORMANCE_REVS); do \
		for leg in $(CONFORMANCE_LEGS); do \
			NETGUARD_BIN=$(CURDIR)/$(BIN_DIR)/$(BINARY) CONFORMANCE_SERVER=$(CURDIR)/$(CONFORMANCE_SERVER) PYTHON="$(PYTHON)" \
				$(CONFORMANCE_DIR)/run.sh $$leg $$rev || failed="$$failed $$leg/$$rev"; \
		done; \
	done; \
	if [ -n "$$failed" ]; then echo "conformance failed:$$failed"; exit 1; fi; \
	echo "conformance ok: $(CONFORMANCE_LEGS) x $(CONFORMANCE_REVS)"

conformance-deps: $(CONFORMANCE_SERVER) $(CONFORMANCE_DIR)/node_modules/.package-lock.json

# A file target: rebuilt whenever go.mod or go.sum changes (a go-sdk bump).
$(CONFORMANCE_SERVER): go.mod go.sum
	@mkdir -p $(dir $@)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -o $@ github.com/modelcontextprotocol/go-sdk/conformance/everything-server

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

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'
