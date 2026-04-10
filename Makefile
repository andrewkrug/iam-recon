# ──────────────────────────────────────────────────────────────────
#  IAM Recon Makefile
# ──────────────────────────────────────────────────────────────────
CARGO   := cargo
DOCKER  := docker
BINARY  := iam-recon
BENCH_DIR := ../bench

.PHONY: all build release check test bench bench-python bench-compare \
        clippy fmt clean install uninstall \
        docker-python run-python-bench \
        graph-create graph-display graph-list graph-refresh \
        query argquery repl visualize interactive analysis \
        pathfinding help

# ── Default ──────────────────────────────────────────────────────
all: help

# ── Build ────────────────────────────────────────────────────────
build:                          ## Build debug binary
	$(CARGO) build

release:                        ## Build optimized release binary
	$(CARGO) build --release

check:                          ## Type-check without building
	$(CARGO) check

# ── Quality ──────────────────────────────────────────────────────
test:                           ## Run all unit tests
	$(CARGO) test

clippy:                         ## Run clippy lints
	$(CARGO) clippy -- -W clippy::all

fmt:                            ## Format code
	$(CARGO) fmt

fmt-check:                      ## Check formatting without modifying
	$(CARGO) fmt -- --check

# ── Benchmarks ───────────────────────────────────────────────────
bench:                          ## Run Rust benchmarks (release)
	$(CARGO) test --release --test bench_compare -- --nocapture

bench-python: docker-python     ## Run Python benchmarks in Docker (Python 3.9)
	$(DOCKER) run --rm -v /tmp:/tmp iam-recon-python-bench

docker-python:                  ## Build Python 3.9 Docker image
	$(DOCKER) build -t iam-recon-python-bench \
		-f $(BENCH_DIR)/Dockerfile.python \
		$(BENCH_DIR)/..

bench-compare: bench-python bench ## Run both Python and Rust benchmarks
	@echo ""
	@echo "══════════════════════════════════════════════════════"
	@echo " Python results: /tmp/iam_recon_python_bench.json"
	@echo " Rust results:   printed above"
	@echo "══════════════════════════════════════════════════════"

# ── Install / Uninstall ──────────────────────────────────────────
install: release                ## Install binary to ~/.cargo/bin
	$(CARGO) install --path .

uninstall:                      ## Remove installed binary
	$(CARGO) uninstall iam-recon 2>/dev/null || true

# ── Clean ────────────────────────────────────────────────────────
clean:                          ## Remove build artifacts
	$(CARGO) clean

# ── AWS Graph Operations (require --profile or --account) ────────
#
# Usage:
#   make graph-create PROFILE=myprofile
#   make graph-display ACCOUNT=123456789012
#   make query ACCOUNT=123456789012 Q="who can do iam:CreateUser"
#

PROFILE ?=
ACCOUNT ?=
Q       ?=

PROFILE_FLAG = $(if $(PROFILE),--profile $(PROFILE),)
ACCOUNT_FLAG = $(if $(ACCOUNT),--account $(ACCOUNT),)

graph-create: release           ## Scan AWS and create graph (PROFILE=xxx)
	./target/release/$(BINARY) $(PROFILE_FLAG) graph create

graph-display: release          ## Show graph info (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) graph display

graph-list: release             ## List stored graphs
	./target/release/$(BINARY) graph list

graph-refresh: release          ## Re-run edge analysis from cache (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) graph refresh

# ── Querying ─────────────────────────────────────────────────────
query: release                  ## Natural language query (ACCOUNT=xxx Q="who can do ...")
	./target/release/$(BINARY) $(ACCOUNT_FLAG) query $(Q)

argquery: release               ## Structured query (ACCOUNT=xxx, pass extra args via ARGS=)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) argquery $(ARGS)

repl: release                   ## Interactive REPL (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) repl

# ── Presets ──────────────────────────────────────────────────────
privesc: release                ## Find privilege escalation paths (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) argquery --preset privesc

wrongadmin: release             ## Find admin nodes without AdministratorAccess (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) argquery --preset wrongadmin

serviceaccess: release          ## Map services to assumable roles (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) argquery --preset serviceaccess

# ── Visualization ────────────────────────────────────────────────
visualize: release              ## Generate DOT graph (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) visualize --format dot

visualize-svg: release          ## Generate SVG graph (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) visualize --format svg

visualize-png: release          ## Generate PNG graph (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) visualize --format png

visualize-graphml: release      ## Generate GraphML (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) visualize --format graphml

interactive: release            ## Launch interactive browser visualization (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) visualize --interactive-viz

# ── Analysis ─────────────────────────────────────────────────────
analysis: release               ## Run security analysis (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) analysis

analysis-json: release          ## Run security analysis, JSON output (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) analysis --format json

analysis-csv: release           ## Export findings as CSV (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) analysis --format csv -o findings.csv

analysis-ocsf: release          ## Export findings as OCSF JSON (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) analysis --format ocsf -o findings_ocsf.json

visualize-pdf: release          ## Generate PDF graph (ACCOUNT=xxx, requires Graphviz)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) visualize --format pdf

# ── TUI Dashboard ────────────────────────────────────────────────
tui: release                    ## Launch TUI dashboard (ACCOUNT=xxx)
	./target/release/$(BINARY) --tui $(ACCOUNT_FLAG)

# ── Pathfinding.cloud ────────────────────────────────────────────
pathfinding: release            ## Map privileges to pathfinding.cloud paths (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) pathfinding

pathfinding-json: release       ## Pathfinding.cloud report, JSON output (ACCOUNT=xxx)
	./target/release/$(BINARY) $(ACCOUNT_FLAG) pathfinding --format json

# ── Help ─────────────────────────────────────────────────────────
help:                           ## Show this help
	@echo ""
	@echo "  \033[1mIAM Recon\033[0m — AWS IAM privilege escalation mapper"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  \033[1mVariables:\033[0m PROFILE=aws-profile  ACCOUNT=account-id  Q=\"query string\"  ARGS=\"--flag val\""
	@echo ""
