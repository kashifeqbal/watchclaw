.PHONY: all lint check test e2e docker-build

SCRIPT_DIRS := lib scripts modules

# Find all .sh files across script dirs
SH_FILES := $(shell find $(SCRIPT_DIRS) -name "*.sh" 2>/dev/null)

all: lint check test

lint: ## bash -n syntax check on all .sh files
	@fail=0; \
	for f in $(SH_FILES); do \
		echo "Linting: $$f"; \
		bash -n "$$f" || { echo "FAIL: $$f"; fail=1; }; \
	done; \
	[ $$fail -eq 0 ] && echo "Lint passed." || { echo "Lint failed."; exit 1; }

check: ## shellcheck on all .sh files (errors fail, warnings OK)
	@which shellcheck > /dev/null 2>&1 || { echo "shellcheck not installed. Run: apt install shellcheck"; exit 1; }
	@fail=0; \
	for f in $(SH_FILES); do \
		echo "ShellCheck: $$f"; \
		shellcheck --severity=error -e SC1091 "$$f" || fail=1; \
	done; \
	[ $$fail -eq 0 ] && echo "ShellCheck passed." || { echo "ShellCheck failed."; exit 1; }

test: ## run bats tests from tests/ (skips if no .bats files found)
	@which bats > /dev/null 2>&1 || { echo "bats not installed. Run: apt install bats"; exit 1; }
	@if ls tests/*.bats > /dev/null 2>&1; then \
		echo "Running bats tests..."; \
		bats tests/*.bats; \
	else \
		echo "No .bats test files found in tests/ — skipping."; \
	fi

docker-build: ## build the e2e test Docker image (watchclaw-e2e:latest)
	docker build -f tests/Dockerfile.e2e -t watchclaw-e2e:latest .

e2e: docker-build ## build Docker image and run all e2e tests
	docker run --rm --name watchclaw-e2e watchclaw-e2e:latest

help: ## show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-12s %s\n", $$1, $$2}'
