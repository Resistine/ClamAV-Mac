# scripts/ Directory

## Scripts

### build-and-start.sh
Full local dev workflow. Requires Homebrew OpenSSL, a valid signing identity, and a virus DB.

**Steps (in order):**
1. CMake configure with ESF enabled, OpenSSL from Homebrew
2. Build with all CPU cores (`-j$(sysctl -n hw.ncpu)`)
3. Install to `$PROJECT_DIR/install/`
4. Embed provisioning profile (`clamAV.provisionprofile`) into clamonacc
5. Fix rpaths — rewrite OpenSSL load paths to `@rpath/` for relocatability
6. Codesign all dylibs and binaries; clamonacc gets ESF entitlements
7. Verify signatures and check ESF entitlement is present
8. Generate `clamd.conf` if missing (TCPSocket 3310, OnAccess on `/Users`)
9. Kill old clamd/clamonacc, start clamd, wait for TCP 3310
10. Start clamonacc via `sudo` in foreground (`-F` flag required for ESF)

**Key variables (hardcoded in script):**
- `SIGN_ID` — `Developer ID Application: Resistine GmbH (C7KSRZC3Q9)`
- `OPENSSL_DIR` — resolved via `brew --prefix openssl@3`
- `INSTALL_DIR` — `$PROJECT_DIR/install/`
- Virus DB — checked at `/opt/homebrew/var/lib/clamav` or `/usr/local/var/lib/clamav`

### Test Scripts (referenced in root CLAUDE.md but not yet created)
- `scripts/test-eicar.sh` — Quick EICAR smoke test (does not exist yet)
- `scripts/tests/macos-verify.sh` — Full macOS verification suite (does not exist yet)

## CI Relationship

`.github/workflows/build-artifacts.yml` duplicates the same CMake configure/build/install/rpath-fix
steps but does NOT call `build-and-start.sh` directly. Key differences from local:
- CI adds `-DENABLE_TESTS=OFF -DENABLE_MAN_PAGES=OFF -DENABLE_DOXYGEN=OFF`
- CI does NOT codesign (no signing identity on runner); downstream Desktop signs
- CI rpath-fix also rewrites libjson-c paths (local script only rewrites OpenSSL)
- CI assembles a minimal artifact: `binaries/`, `lib/` (real files + symlinks.txt manifest),
  `entitlements.plist`, `launchd/*.plist`, and `checksums.txt`
- CI also bundles OpenSSL and libjson-c dylibs from Homebrew into the artifact
- Artifacts uploaded as `clamav-macos-<sha>` (30-day) and `clamav-macos-latest` (90-day, main only)

## macOS-Specific Considerations

- **Code signing**: All binaries must be signed. clamonacc additionally needs the
  `com.apple.developer.endpoint-security.client` entitlement from `entitlements.plist`.
- **Provisioning profile**: `clamAV.provisionprofile` at project root enables ESF. The build script
  warns and continues if missing (not a hard failure).
- **sudo required**: clamonacc must run as root for ESF to function.
- **Full Disk Access**: The terminal or app running clamonacc needs FDA in System Settings.
- **Rpaths**: Binaries link to Homebrew OpenSSL at build time. The rpath-fix step rewrites
  paths to `@rpath/` so binaries work when relocated (CI artifacts, Desktop .app bundle).
- **ARM vs Intel**: DB path detection supports both `/opt/homebrew` and `/usr/local`.

## Prerequisites

- macOS with Xcode CLI tools
- Homebrew packages: `openssl@3`, `bison`, `flex`, `check`, `curl`, `json-c`,
  `libxml2`, `ncurses`, `pcre2`, `zlib`
- Rust toolchain (for `libclamav_rust`)
- Apple Developer signing identity and provisioning profile (for local builds)
- Virus database downloaded via `freshclam`
