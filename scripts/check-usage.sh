#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
README="$ROOT_DIR/README.md"
BIN="$ROOT_DIR/tmp/main"

cd "$ROOT_DIR"

# Build the CLI if missing
if [ ! -x "$BIN" ]; then
  echo "Building CLI to $BIN" >&2
  go build -o "$BIN" ./internal/cmd/main
fi

HELP_FILE="${TMPDIR:-/tmp}/get_help.$$"
README_USAGE_FILE="${TMPDIR:-/tmp}/readme_usage.$$"
trap 'rm -f "$HELP_FILE" "$README_USAGE_FILE"' EXIT

"$BIN" --help > "$HELP_FILE"

# Extract the usage code block content (without the ``` fences) under the Usage section
USAGE_HDR_LINE=$(awk '/^## Usage$/ {print NR; exit}' "$README")
if [ -z "${USAGE_HDR_LINE:-}" ]; then
  echo "Could not find '## Usage' section in README.md" >&2
  exit 1
fi

START_LINE=$(awk -v start="$USAGE_HDR_LINE" 'NR>start && /^```/ {print NR; exit}' "$README")
END_LINE=$(awk -v start="$START_LINE" 'NR>start && /^```$/ {print NR; exit}' "$README")

if [ -z "${START_LINE:-}" ] || [ -z "${END_LINE:-}" ]; then
  echo "Could not locate code block for Usage section in README.md" >&2
  exit 1
fi

sed -n "$(( START_LINE + 1 )),$(( END_LINE - 1 ))p" "$README" > "$README_USAGE_FILE"

if diff -u "$README_USAGE_FILE" "$HELP_FILE"; then
  echo "README Usage block is in sync with --help output." >&2
  exit 0
else
  echo "README Usage block is OUT OF SYNC. Run: make docs-sync" >&2
  exit 1
fi

