# Releasing `get`

This project ships binaries through GitHub Releases and is installed primarily through `mise` (`github:jclem/get`).

## Versioning

- Use SemVer in `Cargo.toml` (`0.2.0`, `0.2.1`, etc.).
- Release tags must be prefixed with `v` (`v0.2.0`).

## Prerequisites

- `mise` installed
- `gh` authenticated (`gh auth status`)
- Rust toolchain installed (via `mise` from `mise.toml`)

## 1. Bump, tag, and push

```bash
mise bump <major | minor | patch>
```

This bumps `Cargo.toml` and `Cargo.lock`, commits, creates a signed tag, and pushes with `--follow-tags`. Pushing the tag triggers `.github/workflows/release.yml`, which builds archives for all supported targets, publishes a GitHub Release, and updates the Homebrew tap.

## 2. Verify GitHub Release assets

After the workflow finishes, verify that the release includes archives for:

- `aarch64-apple-darwin`
- `x86_64-apple-darwin`

Also verify a SHA256 checksum file is attached.

## 3. Verify checksums

Download one archive and checksum file, then verify:

```bash
TAG=v0.2.0
gh release download "$TAG" --repo jclem/get --pattern 'get-aarch64-apple-darwin.tar.xz' --pattern 'sha256.sum'
grep 'get-aarch64-apple-darwin.tar.xz' sha256.sum | shasum -a 256 -c -
```

## 4. Verify `mise` install

Confirm `mise` sees the release and can execute it:

```bash
VERSION=0.2.0
mise ls-remote github:jclem/get | head
mise x github:jclem/get@"$VERSION" -- get --version
```

## 5. Verify Homebrew tap

The release workflow automatically updates the formula in `jclem/homebrew-tap`. Verify:

```bash
brew update
brew upgrade jclem/tap/get
get --version
```

Note: The Homebrew tap update is skipped for prerelease tags (those containing `-`).

## 6. Publish notes

Release notes are generated automatically by the workflow.
