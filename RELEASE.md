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

Optional local dist smoke build (host target only):

```bash
mise run release:smoke-dist
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

Pushing the tag triggers `.github/workflows/release.yml`.

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

## 8. Publish notes

Use GitHub release notes (auto-generated notes are acceptable).
