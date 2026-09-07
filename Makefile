# zk-threat-exchange :: unified build/test/run interface
# Author: Ciprian Ștefan Pleșca
#
# One entry point across four toolchains (Rust, Go, Julia, Scheme) so you
# don't need to remember per-language invocations. Run `make help` to list
# targets.

.DEFAULT_GOAL := help
.PHONY: help build test test-rust test-go test-julia test-scheme \
        lint fmt clean docker docker-up docker-down

## help: show this list of targets
help:
	@echo "zk-threat-exchange — available targets:"
	@echo ""
	@echo "  make build         Build the Rust core-node and Go enterprise-api binaries"
	@echo "  make test          Run the full test matrix (Rust, Go, Julia, Scheme)"
	@echo "  make test-rust     cargo test in core-node/"
	@echo "  make test-go       go test ./... in enterprise-api/"
	@echo "  make test-julia    julia --project=. test/runtests.jl in heuristics-engine/"
	@echo "  make test-scheme   guile run_tests.scm in rule-mutator/test/"
	@echo "  make lint          cargo clippy + go vet (see CONTRIBUTING.md)"
	@echo "  make fmt           cargo fmt (Rust)"
	@echo "  make docker        Build all Docker images defined in deployments/"
	@echo "  make docker-up     docker-compose up -d (local, zero-cost stack)"
	@echo "  make docker-down   docker-compose down"
	@echo "  make clean         Remove build artifacts across all four toolchains"

## build: build the compiled components (Rust + Go)
build:
	cd core-node && cargo build --release
	cd enterprise-api && go build ./...

## test: run the full cross-language test matrix (mirrors CONTRIBUTING.md)
test: test-rust test-go test-scheme test-julia

## test-rust: Rust unit/integration tests for core-node (ZKP, gossip, memory_pool)
test-rust:
	cd core-node && cargo test

## test-go: Go tests for enterprise-api (auth, handlers, billing)
test-go:
	cd enterprise-api && go test ./...

## test-julia: Julia tests for the tensor inference engine
test-julia:
	cd heuristics-engine && julia --project=. test/runtests.jl

## test-scheme: Scheme tests for the rule-mutator, including the backtest gate
test-scheme:
	cd rule-mutator/test && guile --no-auto-compile run_tests.scm

## lint: static analysis across languages with enforced style rules
lint:
	cd core-node && cargo fmt --check && cargo clippy -- -D warnings
	cd enterprise-api && go vet ./...

## fmt: auto-format Rust sources
fmt:
	cd core-node && cargo fmt

## docker: build every image defined in deployments/docker-compose.yml
docker:
	docker-compose -f deployments/docker-compose.yml build

## docker-up: bring up the local, zero-cost three-container stack
docker-up:
	docker-compose -f deployments/docker-compose.yml up -d

## docker-down: tear down the local stack
docker-down:
	docker-compose -f deployments/docker-compose.yml down

## clean: remove build artifacts from every toolchain
clean:
	cd core-node && cargo clean
	cd enterprise-api && go clean
	rm -rf heuristics-engine/deps heuristics-engine/Manifest.toml
