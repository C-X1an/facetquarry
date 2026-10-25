SHELL := $(if $(FQ_SHELL),$(FQ_SHELL),$(if $(filter Windows_NT,$(OS)),sh.exe,/bin/sh))
EXE := $(if $(filter Windows_NT,$(OS)),.exe,)
PYTHON ?= python3
export GOTOOLCHAIN := local
export GOCACHE := $(CURDIR)/.cache/go-build
export GOMODCACHE := $(CURDIR)/.cache/go-mod
export GOTMPDIR := $(CURDIR)/.cache/tmp
export TMPDIR := $(CURDIR)/.cache/tmp
export GOMAXPROCS := 2
export PYTHONPATH := $(CURDIR)/scripts
GO ?= go
FQ_FILESYSTEM_FREE_FLOOR ?= 2000000000

.PHONY: bootstrap build format fmt lint check test integration acceptance race property fuzz mutation security security-online benchmark-smoke benchmark demo clean-verify ci verify release-verify clean integrity disk

bootstrap:
	@mkdir -p .cache/go-build .cache/go-mod .cache/tmp .local bin
	$(PYTHON) scripts/bootstrap.py
	$(PYTHON) scripts/disk_guard.py --reserve 2000000000 --filesystem-free-floor $(FQ_FILESYSTEM_FREE_FLOOR)
integrity: bootstrap
	$(PYTHON) scripts/check_integrity.py
build: integrity
	$(GO) build -trimpath -ldflags "-X main.sourceID=$$($(PYTHON) scripts/common.py)" -o bin/facetquarry$(EXE) ./cmd/facetquarry
	$(GO) build -trimpath -ldflags "-X main.sourceID=$$($(PYTHON) scripts/common.py)" -o bin/fqbench$(EXE) ./cmd/fqbench
format:
	gofmt -w cmd internal
fmt:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }
lint: bootstrap
	$(GO) vet ./...
check: bootstrap
	$(GO) test -run '^$$' ./...
	$(PYTHON) -m compileall -q scripts tests
test: bootstrap
	$(GO) test -count=1 ./...
integration: build
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v
acceptance: test integration
	$(PYTHON) scripts/check_integrity.py
race: bootstrap
	$(GO) test -race -count=1 ./...
property: build
	$(PYTHON) scripts/oracle.py --seeds 1000
fuzz: bootstrap
	$(GO) test ./internal/engine -run '^$$' -fuzz '^FuzzQuery$$' -fuzztime 30s -parallel 2
	$(GO) test ./internal/engine -run '^$$' -fuzz '^FuzzSnapshot$$' -fuzztime 30s -parallel 2
mutation: bootstrap
	$(PYTHON) scripts/mutation.py
	$(PYTHON) scripts/integrity_negative.py
security: test
	$(PYTHON) scripts/public_audit.py
security-online: bootstrap
	@command -v govulncheck >/dev/null || { echo 'NOT RUN: install a verified pinned govulncheck before this gate'; exit 2; }
	govulncheck ./...
benchmark-smoke: build
	$(PYTHON) scripts/benchmark.py --profile smoke
benchmark: build
	$(PYTHON) scripts/benchmark.py --profile full

demo: build
	$(PYTHON) scripts/demo.py
clean-verify: bootstrap
	$(PYTHON) scripts/clean_verify.py
ci: build fmt lint check test integration race mutation demo benchmark-smoke
verify: ci property fuzz security
release-verify: integrity
	$(PYTHON) scripts/bootstrap.py --release
	$(PYTHON) scripts/release_gate.py
clean:
	$(PYTHON) scripts/clean_owned.py

disk:
	$(PYTHON) scripts/disk_guard.py --reserve 2000000000
