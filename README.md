# Get

Get is a CLI for making HTTP requests.

## Installation

```shell
go install github.com/jclem/get@latest
```

## Usage

This CLI is still rudimentary compared to [httpie](https://httpie.io/cli),
especially in terms of parsing JSON body paths and supporting other request body
types (no file support, etc). Your mileage may vary.

```text
Get is a command-line interface for making HTTP requests

Usage:
  get <url> [header:value] [queryParam==value] [bodyParam=value] [bodyParam:=rawValue] [flags]
  get [command]

Available Commands:
  completion                        Generate the autocompletion script for the specified shell
  help                              Help about any command
  session                           Manage sessions

Flags:
  -d, --data string      Data to send in the request body
  -h, --help             help for get
      --http             Use HTTP instead of HTTPS
  -X, --method string    HTTP method to use (default "GET")
  -B, --no-body          Do not print the response body
  -H, --no-headers       Do not print the response headers
  -S, --no-session       Do not use a stored session if one exists for this host
  -s, --session string   Session name to use (defaults to URL host)
  -v, --verbose          Print verbose output

Use "get [command] --help" for more information about a command.
```
