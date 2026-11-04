SHFMT ?= shfmt
SHELLCHECK ?= shellcheck
GO_PACKAGES := ./cmd/... ./internal/... ./tools/...
SHFMT_FLAGS := -i 4 -ci

.PHONY: fmt fmt-check lint test check

fmt:
	go fmt $(GO_PACKAGES)
	find deploy experiments -type f -name '*.sh' -exec $(SHFMT) $(SHFMT_FLAGS) -w {} +

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

.PHONY: test-installer
.PHONY: docs-check
docs-check:
	SHFMT=$(SHFMT) python3 tools/check_docs.py

check: fmt-check lint test test-installer docs-check

.PHONY: generate-api
generate-api:
	go run ./cmd/hestia-panel -openapi api/openapi.yaml
	cd frontend && npm run generate
