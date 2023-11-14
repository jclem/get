.PHONY: check

tmp/get: internal/**/*.go
	go build -o ./tmp/get ./internal/cli/main

check:
	golangci-lint run
