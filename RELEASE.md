# Releasing `get`

This project ships binaries through GitHub Releases and is installed primarily through `mise` (`github:jclem/get`).

## Versioning

- Use SemVer in `Cargo.toml` (`0.2.0`, `0.2.1`, etc.).
- Release tags must be prefixed with `v` (`v0.2.0`).

## Prerequisites

- `mise` installed
- `gh` authenticated (`gh auth status`)
- Rust toolchain installed (via `mise` from `mise.toml`)

## 1. Bump version

Update `version` in `Cargo.toml`.

## 2. Run preflight checks

```bash
mise run release:check
```

Optional local archive smoke build (host target only):

```bash
TARGET=$(rustc -vV | awk '/host:/ {print $2}')
cargo build --locked --release --target "$TARGET"
mkdir -p target/release-smoke/get-"$TARGET"
cp target/"$TARGET"/release/get target/release-smoke/get-"$TARGET"/get
tar -C target/release-smoke -cJf target/release-smoke/get-"$TARGET".tar.xz get-"$TARGET"
shasum -a 256 target/release-smoke/get-"$TARGET".tar.xz
```

## 3. Merge to `main`

Merge the release commit to `main`.

## 4. Create and push the release tag

```bash
TAG=v0.2.0
git checkout main
git pull --ff-only
git tag -a "$TAG" -m "Release $TAG"
git push origin "$TAG"
```

Pushing the tag triggers `.github/workflows/release.yml`, which builds archives for all
supported targets and publishes a GitHub Release.

## 5. Verify GitHub Release assets

After the workflow finishes, verify that the release includes archives for:

- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`

Also verify a SHA256 checksum file is attached.

## 6. Verify checksums

Download one archive and checksum file, then verify:

```bash
TAG=v0.2.0
gh release download "$TAG" --repo jclem/get --pattern 'get-x86_64-unknown-linux-gnu.tar.xz' --pattern 'sha256.sum'
grep 'get-x86_64-unknown-linux-gnu.tar.xz' sha256.sum | shasum -a 256 -c -
```

## 7. Verify `mise` install

Confirm `mise` sees the release and can execute it:

```bash
VERSION=0.2.0
mise ls-remote github:jclem/get | head
mise x github:jclem/get@"$VERSION" -- get --version
```

## 8. Verify Homebrew tap

The release workflow automatically updates the formula in `jclem/homebrew-tap`. Verify:

```bash
brew update
brew install jclem/tap/get
get --version
```

Note: The Homebrew tap update is skipped for prerelease tags (those containing `-`).

## 9. Publish notes

Release notes are generated automatically by the workflow.
