# Makefile for cargo-vuln-policy-validator
#
# Mirrors the CI suite so contributors can reproduce CI failures locally.

.PHONY: help fmt fmt-check clippy test build clean \
        ci ci-format ci-lint ci-test ci-audit ci-coverage ci-deny ci-package \
        spec-check lockfile ci-lockfile-diff ci-changelog pre-commit

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Development:"
	@echo "  fmt            Format code"
	@echo "  fmt-check      Check code formatting"
	@echo "  clippy         Run clippy lints"
	@echo "  test           Run tests"
	@echo "  build          Build the crate"
	@echo "  clean          Clean build artifacts"
	@echo ""
	@echo "CI mirrors (reproduce CI failures locally):"
	@echo "  ci             Full CI suite"
	@echo "  ci-format      Check formatting"
	@echo "  ci-lint        Run clippy"
	@echo "  ci-test        Run tests via nextest"
	@echo "  ci-audit       Security audit"
	@echo "  ci-coverage    Coverage check"
	@echo "  ci-deny        Dependency license audit"
	@echo "  ci-package     Validate crate packaging"

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features --no-deps -- -D warnings

test:
	cargo test --workspace

build:
	cargo build --release

clean:
	cargo clean

ci-format:
	cargo fmt --all -- --check

ci-lint:
	cargo clippy --workspace --all-targets --all-features --no-deps -- -D warnings

ci-test:
	cargo nextest run --all-features

ci-audit:
	cargo audit

ci-coverage:
	cargo llvm-cov nextest --all-features --lcov --output-path lcov.info \
		--fail-under-lines 80
	cargo llvm-cov report --summary-only

ci-deny:
	cargo deny check licenses

ci-package:
	cargo package --allow-dirty --locked --offline

lockfile: ## Regenerate Cargo.lock
	cargo generate-lockfile

ci-lockfile-diff: ## Assert committed Cargo.lock matches resolved lock
	@cargo generate-lockfile
	@if ! git diff --quiet Cargo.lock; then \
	  echo 'ERROR: Cargo.lock is out of date. Run: make lockfile && git add Cargo.lock'; \
	  git diff Cargo.lock; exit 1; \
	fi

ci-changelog: ## CI: verify CHANGELOG.md has entry for current package version
	@curl -fsSL https://raw.githubusercontent.com/brefwiz/shared-ci-workflows/main/scripts/check-release-changelog.sh | bash

pre-commit: ci-format ci-lint ci-test ci-changelog ## Run all pre-commit checks

spec-check: ## ADR-0086 L1: validate SPEC.md wire_surface field
	@VALID="proto-source utoipa-legacy mixed-transition"; \
	WS=$$(grep '^wire_surface:' SPEC.md 2>/dev/null | awk '{print $$2}'); \
	[ -n "$$WS" ] || { echo "ERROR: wire_surface field missing (ADR-0086 L1)"; exit 1; }; \
	echo "$$VALID" | tr ' ' '\n' | grep -qx "$$WS" \
		|| { echo "ERROR: wire_surface='$$WS' invalid. Must be one of: $$VALID"; exit 1; }; \
	echo "spec-check OK: wire_surface=$$WS"

ci: ci-format ci-lint ci-test ci-audit ci-deny ci-package
	@echo "All CI checks passed"
