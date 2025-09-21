# Repository Guidelines

## Project Structure & Module Organization
- `internal/cmd`: Cobra CLI entrypoint and command wiring (`internal/cmd/main/main.go` builds the binary).
- `internal/parser`: Flexible input parser for headers, query, and body (`parser.go` with tests in `parser_test.go`).
- `internal/writer`: Human‑readable request/response output and highlighting.
- `tmp/`: Local build artifacts (ignored by Git).

## Build, Test, and Development Commands
- Build: `go build -o ./tmp/main ./internal/cmd/main`
- Run: `go run ./internal/cmd/main --help` or `./tmp/main example.com`
- Test: `go test ./...` (coverage: `go test -cover ./...`)
- Lint: `golangci-lint run` (configured via `.golangci.toml`)
- Dev loop: `air` (reads `.air.toml`). Install pinned tools with `mise install` (Go/Air/golangci‑lint/lefthook). Enable hooks with `lefthook install`.

## Coding Style & Naming Conventions
- Use standard Go formatting: `go fmt ./...` before pushing.
- Follow Go naming: packages `lowercase`, exported identifiers `PascalCase`, locals `camelCase`.
- Prefer descriptive names; short names allowed for common cases (`i`, `k`, `b`, `r`, `v`, `w`, `id`, `ok`) per `.golangci.toml`.
- Keep functions focused; wrap errors with context: `fmt.Errorf("doing X: %w", err)`.

## Testing Guidelines
- Place tests alongside code in `*_test.go` files; use table‑driven tests where helpful.
- Frameworks: standard `testing` with `testify/assert` and `testify/require`.
- Name tests clearly (e.g., `TestParseInput`). Avoid network calls; keep unit tests deterministic.
- Run `go test ./...` locally; ensure coverage meaningfully exercises new code.

## Commit & Pull Request Guidelines
- Commits: imperative, concise subject (e.g., `Add parsing and writing`); include rationale in the body when useful.
- PRs: clear description, linked issues, usage examples (e.g., `get -v example.com`), and docs updates if behavior changes.
- CI must pass (lint + tests via GitHub Actions). Pre‑commit hooks (`lefthook`) run `golangci-lint` and `go test`.

## Security & Configuration Tips
- Disable color via `NO_COLOR=1` or flag `-C` when scripting.
- Do not commit build outputs; `tmp/` is ignored.
- Avoid real external services in tests; mock or isolate side effects.

