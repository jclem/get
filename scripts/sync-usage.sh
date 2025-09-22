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
trap 'rm -f "$HELP_FILE"' EXIT

"$BIN" --help > "$HELP_FILE"

# Locate the Usage code block under the README Usage section
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

TMP_README="${TMPDIR:-/tmp}/README.$$"

# Write new README with updated help block
head -n $(( START_LINE - 1 )) "$README" > "$TMP_README"
printf '```text\n' >> "$TMP_README"
cat "$HELP_FILE" >> "$TMP_README"
printf '```\n' >> "$TMP_README"
tail -n +$(( END_LINE + 1 )) "$README" >> "$TMP_README"

mv "$TMP_README" "$README"
echo "README Usage block updated from --help output." >&2

