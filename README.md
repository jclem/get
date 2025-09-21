# get

A friendly, flexible HTTP client for your terminal. `get` makes requests easier
with smart URL and method parsing, rich output (color, syntax highlighting,
optional formatting), and a concise, script‑friendly interface.

## Features

- Smart URL handling (bare domains → HTTPS, ports → localhost)
- Method inference (POST when a body is provided without `-X`)
- Pretty printing and syntax highlighting (JSON auto‑formatted)
- Toggleable headers/body/format/highlighting for clean scripts
- Verbose mode prints the request; streaming for large responses

## Installation

- Build from source:
  - `go build -o ./bin/get ./internal/cmd/main`
  - Optionally move to your `PATH`: `mv ./bin/get /usr/local/bin/`
- Run without installing: `go run ./internal/cmd/main --help`

## Usage

```text
Get is a CLI tool for making HTTP requests with intelligent URL parsing, method handling, and rich output formatting.

URL PARSING BEHAVIOR:
The tool automatically handles various URL formats to make requests more convenient:

  • Port-only (e.g., ":8080")     → http://localhost:8080
  • localhost (e.g., "localhost:3000") → http://localhost:3000
  • Full URLs (e.g., "https://api.example.com") → Used as-is
  • Domain-only (e.g., "example.com") → https://example.com

METHOD PARSING:
Use the -X or --method flag to specify the HTTP method.
POST will be used by default if a body is provided and no explicit method is set.

OUTPUT FORMATTING:
The tool provides rich output formatting with syntax highlighting and structured display.
Use the various output control flags to customize what is displayed and how it's formatted.

EXAMPLES:
  # Basic GET request to a domain (defaults to HTTPS)
  get example.com

  # GET request to localhost on port 8080
  get :8080

  # POST request to an API endpoint
  get -X POST api.example.com/users

  # PUT request with full URL
  get -X PUT https://api.example.com/users/123

  # Request to localhost with explicit hostname
  get localhost:3000/api/health

  # HEAD request to check if resource exists
  get -X HEAD https://example.com/file.txt

  # Disable colors and headers for clean output
  get -C -H api.example.com/data

  # Stream a large response
  get -s https://api.example.com/large-dataset

  # Debug mode for troubleshooting
  get -d -X POST api.example.com/upload

Usage:
  get <url> [request-options] [flags]

Flags:
  -d, --debug           Debug mode
      --form            Format the request body as a form, instead of JSON
  -h, --help            help for get
  -X, --method string   The HTTP method to use (default "GET")
  -B, --no-body         Do not print the response body
  -C, --no-color        Do not use color in the output (NO_COLOR is also respected)
  -F, --no-format       Do not format the request/response body
  -H, --no-headers      Do not print the response headers
  -L, --no-highlight    Do not highlight the request/response body
  -s, --stream          Stream the response
  -v, --verbose         Verbose mode (prints the request)
```

## Examples

- Add headers and query params:
  - `get example.com "Authorization:Bearer TOKEN" "q==search term"`
- JSON body (auto POST when body provided):
  - `get api.example.com/users 'user:={"name":"Jane"}'`
- Form body:
  - `get --form -X POST api.example.com/login 'email=jane@example.com' 'password=secret'`
- Disable color for scripts:
  - `NO_COLOR=1 get -H -B example.com` or `get -C ...`

## Development

- Build: `go build -o ./tmp/main ./internal/cmd/main`
- Test: `go test ./...`
- Lint: `golangci-lint run` (configured via `.golangci.toml`)
- Dev loop: `air` (after `mise install` and `lefthook install` for hooks)
