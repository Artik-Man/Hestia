SHFMT ?= shfmt
SHELLCHECK ?= shellcheck
GO_PACKAGES := ./cmd/... ./internal/... ./tools/...
SHFMT_FLAGS := -i 4 -ci

.PHONY: build fmt fmt-check lint test check

fmt:
	go fmt $(GO_PACKAGES)
	find deploy experiments -type f -name '*.sh' -exec $(SHFMT) $(SHFMT_FLAGS) -w {} +

# Gateway executables have one distribution target, regardless of the build host.
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o dist/ ./cmd/hestia ./cmd/hestia-observe ./cmd/hestia-panel

fmt-check:
	find deploy experiments -type f -name '*.sh' -exec $(SHFMT) $(SHFMT_FLAGS) -d {} +
	@files=$$(gofmt -l cmd internal tools) || exit 1; \
	if [ -n "$$files" ]; then echo "$$files"; echo "Run make fmt"; exit 1; fi

lint:
	go vet $(GO_PACKAGES)
	find deploy experiments -type f -name '*.sh' -exec $(SHELLCHECK) -x -P SCRIPTDIR -s bash {} +

test:
	go test $(GO_PACKAGES)

test-installer:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy
	bash -n deploy/install.sh
	bash -n deploy/build-installer.sh

.PHONY: test-installer test-experiments
test-experiments:
	python3 -B -m unittest discover -s tools -p test_run_experiment_tests.py
	python3 -B tools/run_experiment_tests.py

.PHONY: docs-check
docs-check:
	SHFMT=$(SHFMT) python3 tools/check_docs.py

check: fmt-check lint test test-installer test-experiments docs-check

.PHONY: generate-api
generate-api:
	go run ./tools/openapi -output api/openapi.yaml
	cd frontend && npm run generate

.PHONY: stage1-fresh
stage1-fresh:
	bash deploy/stage1-awg-update.sh --fresh
