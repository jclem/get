.PHONY: check

tmp/get: internal/**/*.go
	go build -o ./tmp/get .

check:
	golangci-lint run
