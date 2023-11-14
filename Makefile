.PHONY: check

tmp/get: main.go internal/**/*.go
	go build -o ./tmp/get .

check:
	golangci-lint run
