# Repository Guidelines

## Project Structure & Module Organization
- `internal/cmd`: Cobra CLI entrypoint and command wiring (`internal/cmd/main/main.go` builds the binary).
- `internal/parser`: Flexible input parser for headers, query, and body (`parser.go` with tests in `parser_test.go`).
- `internal/writer`: Human‑readable request/response output and highlighting.
- `tmp/`: Local build artifacts (ignored by Git).

## Build, Test, and Development Commands
- Install toolchains: `mise install`
- Bootstrap hooks and setup: `mise bootstrap`
- Build: `mise build` (produces `./tmp/get` via `go build -o ./tmp/get ./internal/cmd/main`)
- Run: `go run ./internal/cmd/main --help` or `./tmp/get example.com`
- Test: `mise test` (wraps `go test ./...`, coverage: `go test -cover ./...`)
- Lint: `mise lint` (configured via `.golangci.toml`)
- Format: `mise format`
- Maintain dependencies: `mise deps`
- Dev loop: `mise watch build`
- Always check the linter after making changes (CI enforces a clean lint run).

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
- Use a fresh Viper instance per command in tests to avoid shared global state (e.g., `v := viper.New(); v.BindPFlags(cmd.Flags()); v.Unmarshal(&flags)`).

## Commit & Pull Request Guidelines
- Commits: imperative, concise subject (e.g., `Add parsing and writing`); include rationale in the body when useful.
- PRs: clear description, linked issues, usage examples (e.g., `get -v example.com`), and docs updates if behavior changes.
- CI must pass (lint + tests via GitHub Actions). Pre‑commit hooks invoke `mise format`, `mise deps`, `mise lint`, `mise test`, and `mise docs-sync`.

## Security & Configuration Tips
- Disable color via `NO_COLOR=1` or flag `-C` when scripting.
- Do not commit build outputs; `tmp/` is ignored.
- Avoid real external services in tests; mock or isolate side effects.

- README usage block must exactly match CLI help:
  - The code block under README “Usage” should be a verbatim copy of `./tmp/get --help` (including spacing, ordering, and sections like SESSIONS).
  - After changing flags, long help text, or behaviors, rebuild and regenerate help:
    - `mise build`
    - `./tmp/get --help` and paste the full output into the README usage block (or run `mise docs-sync`).
- Quick verification (macOS/Linux):
  - `mise build`
  - `./tmp/get --help > /tmp/get_help.txt`
  - Extract README block and diff:
    - `awk '/^```text/{flag=1;next} /^```$/{flag=0} flag' README.md > /tmp/readme_usage.txt`
    - `diff -u /tmp/readme_usage.txt /tmp/get_help.txt` (no output means in sync)
- Doc comments and examples should reflect current behavior. Update parser/request examples and the Sessions section when inputs, flags, or persistence rules change.
- Any changes to CLI flags, help text, or behavior should include a documentation check as part of the PR (ensure README, command help, and doc comments are updated and consistent).

### Helpers
- `mise tasks` lists available automations.
- `mise build` runs the Go build into `./tmp/get`.
- `mise test` runs the Go test suite.
- `mise lint` wraps `golangci-lint run`.
- `mise format` wraps `go fmt ./...`.
- `mise docs-sync` rebuilds and rewrites the README usage block from `./tmp/get --help`.
