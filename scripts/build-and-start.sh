#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
INSTALL_DIR="$PROJECT_DIR/install"
ENTITLEMENTS="$PROJECT_DIR/entitlements.plist"
PROV_PROFILE="$PROJECT_DIR/clamAV.provisionprofile"
SIGN_ID="Developer ID Application: Resistine GmbH (C7KSRZC3Q9)"
OPENSSL_DIR="$(brew --prefix openssl@3)"

echo "=== ClamAV macOS ESF Build & Run ==="
echo "Project:  $PROJECT_DIR"
echo "OpenSSL:  $OPENSSL_DIR"
echo ""

# ── 1) Build ──────────────────────────────────────────────────
echo "1) Configuring CMake..."
mkdir -p "$BUILD_DIR"
cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
    -DENABLE_CLAMONACC=ON \
    -DENABLE_EXAMPLES=OFF \
    -DENABLE_MILTER=OFF \
    -DOPENSSL_ROOT_DIR="$OPENSSL_DIR" \
    -DOPENSSL_CRYPTO_LIBRARY="$OPENSSL_DIR/lib/libcrypto.dylib" \
    -DOPENSSL_SSL_LIBRARY="$OPENSSL_DIR/lib/libssl.dylib"
echo "   ✓ CMake configured"

echo ""
echo "2) Building..."
cmake --build "$BUILD_DIR" -j "$(sysctl -n hw.ncpu)"
echo "   ✓ Build complete"

echo ""
echo "3) Installing..."
cmake --install "$BUILD_DIR"
echo "   ✓ Installed to $INSTALL_DIR"

# ── 2) Embed provisioning profile ────────────────────────────
echo ""
echo "4) Embedding provisioning profile..."
if [ -f "$PROV_PROFILE" ]; then
    cp "$PROV_PROFILE" "$INSTALL_DIR/sbin/clamonacc.provisionprofile"
    mkdir -p "$INSTALL_DIR/sbin/clamonacc.bundle/Contents"
    cp "$PROV_PROFILE" "$INSTALL_DIR/sbin/clamonacc.bundle/Contents/embedded.provisionprofile"
    echo "   ✓ Provisioning profile embedded"
else
    echo "   ⚠ No provisioning profile found at $PROV_PROFILE"
fi

# ── 3) Fix rpaths / OpenSSL load paths ───────────────────────
echo ""
echo "5) Fixing rpaths and OpenSSL load paths..."
INSTALL_LIB="$INSTALL_DIR/lib"

fix_openssl_paths() {
    local binary="$1"
    for lib in libssl.3.dylib libcrypto.3.dylib; do
        local old_path=""
        old_path=$(otool -L "$binary" 2>/dev/null | grep "$lib" | awk '{print $1}' | head -1) || true
        if [ -n "$old_path" ] && [ "$old_path" != "@rpath/$lib" ]; then
            install_name_tool -change "$old_path" "@rpath/$lib" "$binary" 2>/dev/null || true
        fi
    done
    # Add rpath to our lib dir and OpenSSL dir
    install_name_tool -add_rpath "$INSTALL_LIB" "$binary" 2>/dev/null || true
    install_name_tool -add_rpath "$OPENSSL_DIR/lib" "$binary" 2>/dev/null || true
}

# Fix libraries (skip symlinks)
for dylib in "$INSTALL_LIB"/*.dylib; do
    [ -f "$dylib" ] || continue
    [ -L "$dylib" ] && continue
    fix_openssl_paths "$dylib"
    echo "   - Fixed $(basename "$dylib")"
done

# Fix binaries
for bin in clamd clamonacc freshclam clamscan clamdscan clamsubmit clambc clamconf; do
    local_bin="$INSTALL_DIR/sbin/$bin"
    [ -f "$local_bin" ] || local_bin="$INSTALL_DIR/bin/$bin"
    [ -f "$local_bin" ] || continue
    fix_openssl_paths "$local_bin"
    echo "   - Fixed $bin"
done
echo "   ✓ All rpaths fixed"

# ── 4) Codesign ──────────────────────────────────────────────
echo ""
echo "6) Codesigning..."

# Sign libraries first (skip symlinks, no entitlements needed)
for dylib in "$INSTALL_LIB"/*.dylib; do
    [ -f "$dylib" ] || continue
    [ -L "$dylib" ] && continue
    codesign --force --sign "$SIGN_ID" --timestamp "$dylib"
done
echo "   ✓ Libraries signed"

# Sign binaries
for bin in clamd freshclam clamscan clamdscan clamsubmit clambc clamconf sigtool clamdtop; do
    local_bin="$INSTALL_DIR/sbin/$bin"
    [ -f "$local_bin" ] || local_bin="$INSTALL_DIR/bin/$bin"
    [ -f "$local_bin" ] || continue
    codesign --force --sign "$SIGN_ID" --timestamp "$local_bin"
done
echo "   ✓ Binaries signed"

# Sign clamonacc with ESF entitlements
codesign --force --sign "$SIGN_ID" \
    --entitlements "$ENTITLEMENTS" \
    --timestamp \
    "$INSTALL_DIR/sbin/clamonacc"
echo "   ✓ clamonacc signed with ESF entitlements"

# ── 5) Verify signatures ─────────────────────────────────────
echo ""
echo "7) Verifying signatures..."
codesign --verify --verbose "$INSTALL_DIR/sbin/clamd"
codesign --verify --verbose "$INSTALL_DIR/sbin/clamonacc"
echo "   ✓ Signatures valid"

echo ""
echo "   Checking clamonacc entitlements:"
codesign -d --entitlements - "$INSTALL_DIR/sbin/clamonacc" 2>/dev/null | grep -o "endpoint-security" && echo "   ✓ ESF entitlement present" || echo "   ⚠ ESF entitlement NOT found"

# ── 6) Setup config ──────────────────────────────────────────
echo ""
echo "8) Setting up config..."
CONF_DIR="$INSTALL_DIR/etc"
mkdir -p "$CONF_DIR"

if [ ! -f "$CONF_DIR/clamd.conf" ]; then
    cat > "$CONF_DIR/clamd.conf" << 'CONF'
# ClamAV daemon config for macOS ESF on-access scanning
LogFile /tmp/clamd.log
LogTime yes
LogVerbose yes
DatabaseDirectory /opt/homebrew/var/lib/clamav
TCPSocket 3310
TCPAddr 127.0.0.1
MaxThreads 4
OnAccessIncludePath /Users
OnAccessExcludePath /Users/Shared
OnAccessPrevention no
CONF
    echo "   ✓ Created clamd.conf"
else
    echo "   ✓ clamd.conf already exists"
fi

# ── 7) Kill old instances ────────────────────────────────────
echo ""
echo "9) Stopping any running instances..."
killall clamonacc 2>/dev/null || true
killall clamd 2>/dev/null || true
sleep 1
echo "   ✓ Clean"

# Check for virus database
# Support both ARM (/opt/homebrew) and Intel (/usr/local) Homebrew paths
if [ -d "/opt/homebrew/var/lib/clamav" ]; then
    DB_DIR="/opt/homebrew/var/lib/clamav"
elif [ -d "/usr/local/var/lib/clamav" ]; then
    DB_DIR="/usr/local/var/lib/clamav"
else
    DB_DIR="/opt/homebrew/var/lib/clamav"
fi
if [ ! -f "$DB_DIR/main.cvd" ] && [ ! -f "$DB_DIR/main.cld" ]; then
    echo ""
    echo "   ⚠ No virus database found at $DB_DIR"
    echo "     Run: freshclam  (or brew install clamav && freshclam)"
    echo "     to download signature databases before starting."
    exit 1
fi

# ── 8) Start clamd ───────────────────────────────────────────
echo ""
echo "10) Starting clamd..."
"$INSTALL_DIR/sbin/clamd" --config-file="$CONF_DIR/clamd.conf"
echo "   ✓ clamd started (pid $(pgrep -f "$INSTALL_DIR/sbin/clamd" | head -1))"

# Wait for clamd to be ready
echo ""
echo "11) Waiting for clamd to listen on 127.0.0.1:3310..."
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 3310 2>/dev/null; then
        echo "   ✓ clamd is listening"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "   ✗ clamd did not start in time. Check /tmp/clamd.log"
        exit 1
    fi
    sleep 1
done

# ── 9) Start clamonacc ───────────────────────────────────────
echo ""
echo "12) Starting clamonacc (foreground, ESF mode)..."
echo "    clamonacc requires root for ESF — you may be prompted for your password."
echo "    Press Ctrl+C to stop."
echo ""
sudo "$INSTALL_DIR/sbin/clamonacc" \
    --config-file="$CONF_DIR/clamd.conf" \
    -F
