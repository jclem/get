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
  - `go build -o ./tmp/main ./internal/cmd/main`
  - Optionally move to your `PATH`: `mv ./tmp/main /usr/local/bin/get`
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

SESSIONS:
By default, get persists a small subset of request headers (currently:
Authorization) between runs, keyed by a session name.

The default session name is the request host; use --session to override, or
-S/--no-session to disable reading and writing.  Sessions are stored at
${XDG_CONFIG_HOME}/get/sessions.json.

Use -A/--save-all-headers to persist all request headers for this run.

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
  -d, --debug              Debug mode
      --form               Format the request body as a form, instead of JSON
  -h, --help               help for get
  -X, --method string      The HTTP method to use (default "GET")
  -B, --no-body            Do not print the response body
  -C, --no-color           Do not use color in the output (NO_COLOR is also respected)
  -F, --no-format          Do not format the request/response body
  -H, --no-headers         Do not print the response headers
  -L, --no-highlight       Do not highlight the request/response body
  -S, --no-session         Do not read or save the session
  -A, --save-all-headers   Save all headers to the session
      --session string     The name of the session to use
  -s, --stream             Stream the response
  -v, --verbose            Verbose mode (prints the request)
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

## Sessions

- What persists:
  - By default, `get` persists a small subset of request headers between runs, keyed by session name (defaults to the request host).
  - Currently whitelisted: `Authorization`.
  - Use `-A` / `--save-all-headers` to persist all headers from the request for this run (useful for custom auth headers).
- Where stored:
  - `${XDG_CONFIG_HOME}/get/sessions.json` (a JSON file created if missing).
- Control behavior:
  - Disable sessions: `-S` / `--no-session`.
  - Use a custom session name: `--session my-api` (useful when multiple hosts share credentials, or for staging vs prod).
  - Save all headers: `-A` / `--save-all-headers`.
- Header precedence:
  - Headers you pass on the command line override persisted headers for the same request; repeated header inputs add additional values.

Examples:

- First request saves `Authorization` under the host session:
  - `get api.example.com 'Authorization:Bearer <token>' /me`
- Subsequent requests reuse it automatically:
  - `get api.example.com /me`
- Use a named session instead of the host:
  - `get --session my-api api.example.com 'Authorization:Bearer <token>'`
  - `get --session my-api api.example.com /me`
- Save and reuse a custom header as well:
  - `get -A api.example.com 'X-Env:staging' 'Authorization:Bearer <token>' /me`
  - `get api.example.com /me` # uses both Authorization and X-Env from session
- Skip session reads/writes entirely:
  - `get -S api.example.com /me`

## Development

- Build: `go build -o ./tmp/main ./internal/cmd/main`
- Test: `go test ./...`
- Lint: `golangci-lint run` (configured via `.golangci.toml`)
- Tools: `mise install`
- Hooks: `lefthook install`
- Dev loop: `air`
