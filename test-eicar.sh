#!/bin/bash
# Test ClamAV with EICAR test file

set -e

echo "=== ClamAV EICAR Test ==="
echo ""

# Create EICAR test file (properly escaped for shell)
EICAR_FILE="/tmp/eicar-test-$(date +%s).txt"
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n' > "$EICAR_FILE"

echo "1) Created EICAR test file: $EICAR_FILE"
echo ""

# Test with clamdscan (requires clamd running)
echo "2) Testing with clamdscan (requires clamd)..."
if nc -z 127.0.0.1 3310 2>/dev/null; then
    echo "   ✓ clamd is listening"
    /usr/local/clamav/bin/clamdscan "$EICAR_FILE" 2>&1
else
    echo "   ✗ clamd is not listening on port 3310"
    echo "   Start it with: sudo /usr/local/clamav/sbin/clamd --config-file=/usr/local/clamav/etc/clamd.conf &"
fi

echo ""

# Test with clamscan (standalone, doesn't need clamd)
echo "3) Testing with clamscan (standalone)..."
/usr/local/clamav/bin/clamscan "$EICAR_FILE" 2>&1 | head -5

echo ""
echo "=== Test Complete ==="
echo ""
echo "If you see 'FOUND' or 'Infected', ClamAV is working correctly!"
echo "EICAR is a harmless test file that all antivirus software recognizes."

