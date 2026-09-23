# NetGuard build and test entry points. Tier 1 (no network) is everything here
# except release-snapshot, which needs goreleaser installed.

BINARY   := netguard
MODULE   := github.com/joshscott13/netguard
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

GO       ?= go
GOFLAGS  ?=
BIN_DIR  := bin

.PHONY: all build test vet lint fmt policy-test fixtures-check release-snapshot clean help

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

release-snapshot: ## Local GoReleaser dry run (needs goreleaser)
	goreleaser release --snapshot --clean --skip=publish

clean: ## Remove build outputs
	rm -rf $(BIN_DIR) dist

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'
