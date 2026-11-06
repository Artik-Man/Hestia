SHFMT ?= shfmt
SHELLCHECK ?= shellcheck
GO_PACKAGES := ./cmd/... ./internal/... ./tools/...
SHFMT_FLAGS := -i 4 -ci

.PHONY: build build-go fmt fmt-check lint test check

fmt:
	go -C backend fmt $(GO_PACKAGES)
	find deploy tests/lab scripts -type f -name '*.sh' -exec $(SHFMT) $(SHFMT_FLAGS) -w {} +

# Build both distribution artifacts without accessing a stand.
build:
	bash scripts/build/run.sh

# CI compilation gate; frontend and runtime packaging are checked separately.
build-go:
	python3 scripts/build/run.py --check-go --output dist/go

.PHONY: test-source deploy deploy-dev deploy-prod test-installed test-dev test-prod
test-source:
	python3 scripts/test-source/run.py

deploy:
	bash scripts/deploy/run.sh --stand "$(STAND)" --bundle "$(BUNDLE)" --type "$(TYPE)"

deploy-dev:
	bash scripts/deploy/run.sh --stand scripts/shared/stands/dev.json --bundle "$(BUNDLE)" --type linux

deploy-prod:
	bash scripts/deploy/run.sh --stand scripts/shared/stands/prod.json --bundle "$(BUNDLE)" --type linux

test-installed:
	python3 scripts/test/run.py --stand "$(STAND)"

test-dev:
	python3 scripts/test/run.py --stand scripts/shared/stands/dev.json

test-prod:
	python3 scripts/test/run.py --stand scripts/shared/stands/prod.json

fmt-check:
	find deploy tests/lab scripts -type f -name '*.sh' -exec $(SHFMT) $(SHFMT_FLAGS) -d {} +
	@files=$$(gofmt -l backend) || exit 1; \
	if [ -n "$$files" ]; then echo "$$files"; echo "Run make fmt"; exit 1; fi

lint:
	go -C backend vet $(GO_PACKAGES)
	find deploy tests/lab scripts -type f -name '*.sh' -exec $(SHELLCHECK) -x -P SCRIPTDIR -s bash {} +

test:
	go -C backend test $(GO_PACKAGES)

test-installer:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy
	bash -n deploy/install.sh
	bash -n deploy/build-installer.sh

.PHONY: test-installer test-lab test-experiments
test-experiments: test-lab

test-lab:
	python3 -B -m unittest discover -s tools -p 'test_*.py'
	python3 -B tools/run_lab_tests.py

.PHONY: test-workflows
test-workflows:
	python3 -B tools/run_lab_tests.py --tree scripts

.PHONY: docs-check
docs-check:
	SHFMT=$(SHFMT) python3 tools/check_docs.py

check: fmt-check lint test test-installer test-lab test-workflows docs-check

.PHONY: generate-api
generate-api:
	go -C backend run ./tools/openapi -output api/openapi.yaml
	cd frontend && npm run generate

.PHONY: stage1-fresh
stage1-fresh:
	bash deploy/stage1-awg-update.sh --fresh

.PHONY: push
push:
	sh tools/push-version.sh
