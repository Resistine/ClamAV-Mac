# CI Workflows

## build-artifacts.yml (Primary — Resistine Desktop depends on this)

Builds ClamAV macOS binaries and uploads them as GitHub Actions artifacts for consumption by Resistine-Desktop.

### Triggers
- Push to `main` or `clamav-artifact` branches
- Pull requests targeting `main`
- Manual `workflow_dispatch`

Uses concurrency groups to cancel in-progress runs on the same ref.

### Build Pipeline (macos-14 runner)
1. Install build tools (bison, flex) and dependencies (openssl@3, json-c, pcre2, etc.)
2. Cache Rust/Cargo (used by libclamav_rust)
3. CMake configure with `RelWithDebInfo`, `ENABLE_CLAMONACC=ON`, tests/docs disabled
4. Build and install to `$GITHUB_WORKSPACE/install`
5. Fix rpaths — rewrites OpenSSL/json-c dylib references to use `@rpath/` and adds rpath entries for the install lib dir and brew prefixes
6. Assemble artifact directory from the install tree
7. Generate SHA-256 checksums
8. Upload SHA-tagged artifact (`clamav-macos-<sha>`, 30-day retention)
9. On main push only: also upload `clamav-macos-latest` (90-day retention, overwrites)

### Artifact Contents
- `binaries/` — clamd, clamonacc, clamscan, clamdscan, freshclam
- `lib/` — libclamav, libfreshclam, libclammspack, libclamunrar dylibs + OpenSSL (libssl.3, libcrypto.3) + libjson-c + `symlinks.txt` manifest
- `launchd/` — LaunchDaemon plist files for clamd and clamonacc auto-start
- `entitlements.plist` — ESF entitlement for clamonacc code signing
- `checksums.txt` — SHA-256 hashes of all files

### Symlink Handling
`upload-artifact` does not preserve symlinks (they become full copies). The workflow uploads only real (versioned) dylib files and records symlinks in `lib/symlinks.txt`. The downstream script recreates symlinks from this manifest.

### How Resistine Desktop Consumes Artifacts
`Resistine-Desktop/scripts/build/download-clamav-artifacts.sh` uses `gh` CLI to download the latest artifact. It recreates symlinks from `symlinks.txt` and rewrites rpaths to match the final install location inside `Resistine.app`.

### Rpath Caveat
CI-built binaries carry hardcoded rpaths pointing to the GitHub Actions runner's brew paths (e.g., `/opt/homebrew/lib`). These are non-functional on end-user machines. Resistine Desktop's download script rewrites them at download time using `install_name_tool`.

---

## cmake.yml (Upstream CI — build + test)

Multi-platform build and test inherited from upstream ClamAV. Runs on push to `main`, `rel/*`, `dev/*`; PRs to `main`, `rel/*`, `dev/*`, `feature/*`.

- **Windows**: vcpkg dependencies, Ninja multi-config, includes packaging
- **macOS**: brew dependencies, Release build, runs CTest
- **Ubuntu**: apt dependencies, Release build, runs CTest

This workflow validates that the codebase compiles and passes tests across all platforms.

---

## clang-format.yml (Code style)

Runs `clang-format` (v16) style checks on C/C++ source directories (libclamav, clamd, clamonacc, clamscan, clamsubmit, freshclam, common, sigtool, examples, win32/compat, etc.) via a matrix strategy. Triggers on push/PR to `main`, `rel/*`, `dev/*`. Some directories have exclusion patterns for vendored code (e.g., bytecode, rijndael, yara in libclamav; c-thread-pool/fts in clamonacc).

---

## codeql.yml (Security scanning)

GitHub CodeQL analysis for C++ and Python. Runs on push/PR and weekly (Wednesday 10:20 UTC). Builds on Ubuntu with autobuild, reports to Security tab.

---

## docker-db-update.yml (Database maintenance)

Monthly cron job (1st of each month) that updates the virus database in a Docker image. Uses Docker Hub credentials from repository secrets.
