.PHONY: ci check test

tmp/get: main.go $(find internal -type f)
	go build -o ./tmp/get .

/usr/local/bin/get: tmp/get
	sudo cp ./tmp/get /usr/local/bin/get

ci: check test

check:
	golangci-lint run

test:
	go test -v ./...
