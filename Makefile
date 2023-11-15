.PHONY: ci check test

tmp/get: main.go internal/**/*.go
	go build -o ./tmp/get .

ci: check test

check:
	golangci-lint run

test:
	go test -v ./...
