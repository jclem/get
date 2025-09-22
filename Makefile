.PHONY: docs-sync docs-check build

build:
	go build -o ./tmp/get ./internal/cmd/main

docs-sync: build
	bash scripts/sync-usage.sh

docs-check: build
	bash scripts/check-usage.sh

