#!/bin/bash
# Add ClamAV binaries to PATH

set -e

ZSHRC="$HOME/.zshrc"
CLAMAV_BIN="/usr/local/clamav/bin"

echo "=== Adding ClamAV to PATH ==="
echo ""

# Check if already added
if grep -q "$CLAMAV_BIN" "$ZSHRC" 2>/dev/null; then
    echo "✓ ClamAV is already in your PATH"
    echo ""
    echo "To use it in this session, run:"
    echo "  export PATH=\"$CLAMAV_BIN:\$PATH\""
    exit 0
fi

# Add to .zshrc
echo "" >> "$ZSHRC"
echo "# ClamAV binaries" >> "$ZSHRC"
echo "export PATH=\"$CLAMAV_BIN:\$PATH\"" >> "$ZSHRC"

echo "✓ Added ClamAV to ~/.zshrc"
echo ""
echo "To use it in this session, run:"
echo "  export PATH=\"$CLAMAV_BIN:\$PATH\""
echo ""
echo "Or restart your terminal (new sessions will have it automatically)"

