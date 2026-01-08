#!/bin/bash
# Build, install, (optionally) sign, and start clamd + clamonacc on macOS.
#
# Why this exists:
# - clamonacc requires clamd to be running first.
# - clamonacc must run with -F (foreground) to avoid ESF-forbidden forking.
# - clamonacc must NOT load build-tree dylibs (library validation). We fix rpaths.
#
# Usage:
#   ./build-and-start.sh                 # build+install+sign+start (interactive sudo)
#   SKIP_SIGN=1 ./build-and-start.sh     # build+install+start (no codesign)
#   SIGNING_IDENTITY="Developer ID Application: ..." ./build-and-start.sh
#
# Notes:
# - This script intentionally uses interactive sudo. Run it in a real Terminal.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

CLAMD="/usr/local/clamav/sbin/clamd"
CLAMONACC="/usr/local/clamav/sbin/clamonacc"
CONFIG="/usr/local/clamav/etc/clamd.conf"
BUILD_DIR="$SCRIPT_DIR/build"
ENTITLEMENTS="$SCRIPT_DIR/entitlements.plist"

SIGNING_IDENTITY_DEFAULT="Developer ID Application: Resistine GmbH (C7KSRZC3Q9)"
SIGNING_IDENTITY="${SIGNING_IDENTITY:-$SIGNING_IDENTITY_DEFAULT}"

NCPU="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"

echo "=== Build + Install + Start (clamd + clamonacc) ==="
echo ""

CLAMD_PID=""
cleanup_on_error() {
  # If we started clamd and then failed before starting clamonacc, don't leave a stray daemon running.
  if [[ -n "${CLAMD_PID}" ]]; then
    sudo kill "${CLAMD_PID}" 2>/dev/null || true
  fi
}
trap cleanup_on_error ERR

if [[ ! -d "$BUILD_DIR" ]]; then
  echo "Build directory not found at: $BUILD_DIR"
  echo "Configuring CMake..."
  cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR"
  echo ""
fi

echo "1) Building clamd + clamonacc..."
cmake --build "$BUILD_DIR" --target clamd clamonacc -j"$NCPU"
echo "   ✓ Built"
echo ""

echo "2) Stopping any running instances (requires sudo)..."
sudo pkill -x clamonacc 2>/dev/null || true
sudo pkill -x clamd 2>/dev/null || true
echo "   ✓ Stopped (if they were running)"
echo ""

echo "3) Installing programs to /usr/local/clamav (requires sudo)..."
sudo cmake --install "$BUILD_DIR" --component programs
echo "   ✓ Installed"
echo ""

echo "4) Force-copying freshly built binaries into place (avoids 'Up-to-date' issues)..."
BUILD_CLAMD="$BUILD_DIR/clamd/clamd"
BUILD_CLAMONACC="$BUILD_DIR/clamonacc/clamonacc"

if [[ ! -f "$BUILD_CLAMD" ]]; then
  echo "ERROR: built clamd not found at: $BUILD_CLAMD"
  exit 1
fi
if [[ ! -f "$BUILD_CLAMONACC" ]]; then
  echo "ERROR: built clamonacc not found at: $BUILD_CLAMONACC"
  exit 1
fi

sudo install -m 0755 "$BUILD_CLAMD" "$CLAMD"
sudo install -m 0755 "$BUILD_CLAMONACC" "$CLAMONACC"
echo "   ✓ Copied"
echo ""

echo "5) Fixing rpaths (avoid loading build-tree dylibs)..."

# clamd
sudo install_name_tool -delete_rpath "$BUILD_DIR/libclamav" "$CLAMD" 2>/dev/null || true
sudo install_name_tool -delete_rpath "$BUILD_DIR/libclammspack" "$CLAMD" 2>/dev/null || true
sudo install_name_tool -add_rpath "@executable_path/../lib" "$CLAMD" 2>/dev/null || true

# clamonacc
sudo install_name_tool -delete_rpath "$BUILD_DIR/libclamav" "$CLAMONACC" 2>/dev/null || true
sudo install_name_tool -delete_rpath "$BUILD_DIR/libclammspack" "$CLAMONACC" 2>/dev/null || true
sudo install_name_tool -add_rpath "@executable_path/../lib" "$CLAMONACC" 2>/dev/null || true

echo "   ✓ RPATH set to @executable_path/../lib (clamd + clamonacc)"
echo ""

if [[ "${SKIP_SIGN:-0}" == "1" ]]; then
  echo "6) SKIP_SIGN=1 set — skipping codesign."
  echo ""
else
  echo "6) Codesigning binaries (requires sudo)..."
  if [[ ! -f "$ENTITLEMENTS" ]]; then
    echo "ERROR: entitlements file not found: $ENTITLEMENTS"
    exit 1
  fi

  # clamd (no entitlements needed)
  sudo codesign --remove-signature "$CLAMD" 2>/dev/null || true
  sudo codesign \
    --force \
    --strict \
    --timestamp \
    --options runtime \
    -s "$SIGNING_IDENTITY" \
    "$CLAMD"

  # clamonacc (ESF entitlement required)
  sudo codesign --remove-signature "$CLAMONACC" 2>/dev/null || true
  sudo codesign \
    --force \
    --strict \
    --timestamp \
    --options runtime \
    --entitlements "$ENTITLEMENTS" \
    -s "$SIGNING_IDENTITY" \
    -i "com.resistine" \
    "$CLAMONACC"

  echo "   ✓ Signed"
  echo ""

  echo "7) Verifying signatures..."
  sudo codesign --verify --strict --verbose=2 "$CLAMD"
  sudo codesign --verify --strict --verbose=2 "$CLAMONACC"
  echo "   ✓ Verified"
  echo ""
fi

echo "8) Starting clamd..."
sudo "$CLAMD" --config-file="$CONFIG" &
CLAMD_PID=$!
echo "   ✓ clamd started (pid $CLAMD_PID)"
echo ""

echo "9) Waiting for clamd to listen on 127.0.0.1:3310..."
for _ in {1..30}; do
  # Using `lsof` without sudo can return empty results on macOS even when the port is open.
  if nc -z 127.0.0.1 3310 >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! nc -z 127.0.0.1 3310 >/dev/null 2>&1; then
  echo "ERROR: clamd did not start listening on port 3310."
  echo "Try running clamd in foreground to see the real error:"
  echo "  sudo $CLAMD --config-file=$CONFIG"
  exit 1
fi
echo "   ✓ clamd is listening"
echo ""

echo "10) Starting clamonacc (foreground, ESF-safe: -F)..."
echo "    Press Ctrl+C to stop clamonacc."
echo ""
exec sudo "$CLAMONACC" -F --config-file="$CONFIG"


