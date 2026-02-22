# get

A convenient HTTP CLI with expressive inline request syntax.

`get` starts simple (`GET` a URL) and scales to real request building with:

- headers (`Header:Value`)
- query params (`name==value`)
- body fields (`path=value`)
- typed JSON values (`path:=json`)

## Install

### With mise (recommended)

Install the latest release:

```bash
mise use -g github:jclem/get@latest
```

Install a specific release:

```bash
mise use -g github:jclem/get@0.1.0
```

### With Homebrew (macOS)

```bash
brew install jclem/tap/get
```

### From GitHub Releases (manual fallback)

Download the platform archive and checksum file from the release page:

```bash
VERSION=v0.1.0
gh release download "$VERSION" --repo jclem/get --pattern 'get-aarch64-apple-darwin.tar.xz' --pattern 'sha256.sum'
```

Verify checksums:

```bash
grep 'get-aarch64-apple-darwin.tar.xz' sha256.sum | shasum -a 256 -c -
```

Extract and install:

```bash
tar -xJf get-aarch64-apple-darwin.tar.xz
install -m 0755 get-aarch64-apple-darwin/get "$HOME/.local/bin/get"
```

### From source (contributors)

```bash
cargo install --path .
```

Or run directly in this repo:

```bash
cargo run -- <args>
```

## Quick Start

```bash
# Plain GET
get https://httpbin.org/get

# Add a header
get https://httpbin.org/headers Authorization:Bearer_token

# Add query params
get https://httpbin.org/get q==rust page==1

# Send a JSON body (auto-switches method to POST)
get https://httpbin.org/anything title=ship-it
```

## Request Input Syntax

Every extra argument after the URL is parsed as one of these forms:

| Form | Meaning | Example |
| --- | --- | --- |
| `Header:Value` | Request header | `Accept:application/json` |
| `name==value` | Query parameter | `q==hello` |
| `path=value` | Body string assignment | `title=fix-parser-docs` |
| `path:=json` | Body typed JSON assignment | `count:=10`, `enabled:=true` |

Parser precedence is:

1. `path:=json`
2. `name==value`
3. `Header:Value`
4. `path=value`

This matters when syntax could overlap.

## Headers

Use `:` to set headers:

```bash
get https://api.example.com/me \
  Authorization:Bearer_sk_live_123 \
  X-Trace-Id:abc-123
```

Notes:

- Header names allow letters, numbers, `-`, and `_`.
- Header values may contain additional `:` characters.
- Repeating a header name is appended.

## Query Params

Use `==` to append query params:

```bash
get https://api.example.com/search \
  q==observability \
  sort==updated \
  tag==rust \
  tag==cli
```

Resulting URL contains repeated keys when repeated in input (for example `tag=rust&tag=cli`).

Notes:

- Query names can contain almost any character except `=`.
- Empty values are allowed (for example `q==`).

## Body Syntax

### String assignment (`=`)

`=` always stores a JSON string value:

```bash
get https://api.example.com/issues \
  title=fix-login-redirect \
  meta.priority=high
```

Body produced:

```json
{
  "title": "fix-login-redirect",
  "meta": {
    "priority": "high"
  }
}
```

### Typed assignment (`:=`)

`:=` parses the right side as JSON:

```bash
get https://api.example.com/issues \
  count:=10 \
  is_draft:=false \
  'labels:=["bug","urgent"]' \
  'owner:={"id":42,"name":"jules"}'
```

Body produced:

```json
{
  "count": 10,
  "is_draft": false,
  "labels": ["bug", "urgent"],
  "owner": {
    "id": 42,
    "name": "jules"
  }
}
```

### Path expressions

`path` supports nested objects and arrays:

```bash
# Nested object keys
project.name=apollo

# Bracket keys (useful for special chars)
project[build.version]=v1

# Array append
items[]=a
items[]=b

# Array index
items[0]=first
items[2]=third

# Root array
[]=first
[]=second
```

## Mixed Example: Header + Query + Body

```bash
get -X POST https://api.example.com/tasks \
  Authorization:Bearer_token \
  X-Request-Id:req-123 \
  expand==owner \
  expand==labels \
  title=write-readme \
  priority:=2 \
  labels:=["docs","cli"] \
  owner[id]:=42
```

## Method Selection Rules

- Default method is `GET`.
- If body input exists (`=` or `:=`) and no `-X/--method` is set, method becomes `POST`.
- `-X/--method` always wins.

Examples:

```bash
# Auto POST because body exists
get https://httpbin.org/anything title=hello

# Force GET even with body
get -X GET https://httpbin.org/anything title=hello
```

## Useful Flags

```bash
# Show request + response headers
get -v https://httpbin.org/get

# Print request and exit (no network call)
get --dry-run https://httpbin.org/post title=preview

# Send body as x-www-form-urlencoded instead of JSON
get --form https://httpbin.org/post title=hello meta[level]:=2

# Stream response body as it arrives
get --stream https://httpbin.org/stream/20

# Disable response body output
get -B https://httpbin.org/get

# Disable response formatting + syntax highlighting
get -H https://httpbin.org/json
```

## Sessions and Profiles

`get` can persist selected headers per host/session and manage profiles:

```bash
# Show session/profile commands
get session --help
get profile --help

# Switch active profile
get session switch work

# Inspect a saved session
get session show api.example.com
```

To edit config (including `session-headers`):

```bash
get config edit
```

Example config snippet:

```toml
session-headers = ["Authorization", "x-api-key"]

[sessions."api.example.com"]
session-headers = ["x-session-token"]
```

When requesting `api.example.com`, host-specific `session-headers` replace the global list (no merge).

## Shell Completions

```bash
get completions zsh
get completions bash
get completions fish
```

## Tips

- With `:=`, JSON must be valid. Use JSON strings when needed: `name:='"alice"'`.
- Use `--dry-run` when building complex request syntax to verify the final request before sending.
- Response formatting (JSON/HTML) and syntax highlighting are enabled only when stdout is a TTY; `-H/--no-highlight` disables both.
