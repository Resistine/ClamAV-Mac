# ClamAV-Mac Project

ClamAV fork adding macOS on-access scanning via Apple's Endpoint Security Framework (ESF).

## Build & Run

```bash
# Full build + sign + start (recommended)
./scripts/build-and-start.sh

# Manual CMake build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=../install
make -j$(sysctl -n hw.ncpu)
make install
```

## Test

```bash
./scripts/test-eicar.sh             # Quick smoke test with EICAR
./scripts/tests/macos-verify.sh     # Full macOS verification suite
```

## Key Architecture

- **Language**: C (core), shell scripts (build/test tooling)
- **ESF integration**: `clamonacc` uses Apple's Endpoint Security Framework for file event monitoring
- **Code signing required**: ESF demands `com.apple.developer.endpoint-security.client` entitlement
- **Signing identity**: `Developer ID Application: Resistine GmbH (C7KSRZC3Q9)`
- **Install prefix**: `./install/` (dev builds), `/usr/local/clamav` (system)

## Subsystem Documentation

Detailed docs live alongside each subsystem. Read these when working on that area:

| Subsystem | Doc Path | What It Covers |
|---|---|---|
| **clamd** | `clamd/.claude/CLAUDE.md` | Daemon architecture, threading, protocol commands, config options |
| **clamonacc** | `clamonacc/.claude/CLAUDE.md` | ESF integration, event pipeline, scan queue, NOTIFY vs AUTH mode |
| **libclamav** | `libclamav/.claude/CLAUDE.md` | Scanning engine, matchers, file parsers, bytecode, public API |
| **freshclam** | `freshclam/.claude/CLAUDE.md` | Database updater, CVD verification, libfreshclam relationship |
| **CI workflows** | `.github/workflows/.claude/CLAUDE.md` | build-artifacts.yml pipeline, artifact contents, rpath handling |
| **scripts** | `scripts/.claude/CLAUDE.md` | build-and-start.sh steps, CI vs local differences, prerequisites |
| **launchd** | `launchd/.claude/CLAUDE.md` | LaunchDaemon plists, boot config, CVD_CERTS_DIR override, debugging |

## Integration with Resistine Desktop

This repo is a **build-time dependency** of [Resistine-Desktop](../Resistine-Desktop/).

1. CI builds binaries + libs and uploads as GitHub Actions artifacts
2. Desktop downloads artifacts via `gh` CLI
3. Desktop bundles into `Resistine.app` (binaries in `Contents/Helpers/`, clamonacc in nested `.app` bundle)
4. LaunchDaemon plists installed to `/Library/LaunchDaemons/`

### What this repo provides (artifacts)
- `binaries/` — clamd, clamonacc, clamscan, clamdscan, freshclam
- `lib/` — libclamav, libfreshclam, libclammspack, libclamunrar + symlinks manifest
- `launchd/` — LaunchDaemon plists
- `entitlements.plist` — ESF entitlement for clamonacc
- `certs/clamav.crt` — CVD signature verification certificate

### Production paths (after Desktop install)
- Binaries: `/Applications/Resistine.app/Contents/Helpers/`
- Config: `/Library/Application Support/Resistine/clamav/clamd.conf`
- Database: `/Library/Application Support/Resistine/clamav/db/`
- Logs: `/Library/Application Support/Resistine/clamav/log/`
- Socket: `/Library/Application Support/Resistine/clamav/run/clamd.sock`

## Gotchas

- `clamonacc` MUST run as root with `-F` (foreground) flag for ESF to work
- Terminal/app running `clamonacc` needs Full Disk Access in macOS Privacy settings
- Scripts use `$PROJECT_DIR` relative paths — don't hardcode absolute paths
- The build system is CMake, not Make — `Makefile` is generated, not checked in
- CI-built binaries have hardcoded rpaths from the GitHub Actions runner — Desktop's `download-clamav-artifacts.sh` rewrites them at download time
- clamd's `CVDCertsDirectory` is hardcoded at compile time; the LaunchDaemon plist overrides it via `CVD_CERTS_DIR` env var
