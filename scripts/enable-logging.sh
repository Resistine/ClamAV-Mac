#!/bin/bash
# Enable logging in clamd.conf

set -e

CONFIG="/usr/local/clamav/etc/clamd.conf"
BACKUP="${CONFIG}.backup-$(date +%Y%m%d-%H%M%S)"

echo "=== Enabling ClamAV Logging ==="
echo ""

# Backup config
if [ ! -f "$BACKUP" ]; then
    sudo cp "$CONFIG" "$BACKUP"
    echo "✓ Backed up config to: $BACKUP"
fi

# Check if logging is already enabled
if grep -q "^LogSyslog" "$CONFIG" 2>/dev/null; then
    echo "⚠️  LogSyslog already configured"
else
    # Add LogSyslog
    echo "" | sudo tee -a "$CONFIG" > /dev/null
    echo "# Enable syslog logging" | sudo tee -a "$CONFIG" > /dev/null
    echo "LogSyslog yes" | sudo tee -a "$CONFIG" > /dev/null
    echo "✓ Enabled LogSyslog"
fi

if grep -q "^LogVerbose" "$CONFIG" 2>/dev/null; then
    echo "⚠️  LogVerbose already configured"
else
    echo "LogVerbose yes" | sudo tee -a "$CONFIG" > /dev/null
    echo "✓ Enabled LogVerbose"
fi

if grep -q "^LogTime" "$CONFIG" 2>/dev/null; then
    echo "⚠️  LogTime already configured"
else
    echo "LogTime yes" | sudo tee -a "$CONFIG" > /dev/null
    echo "✓ Enabled LogTime"
fi

# Optional: Enable file logging
if ! grep -q "^LogFile" "$CONFIG" 2>/dev/null; then
    LOG_DIR="/usr/local/clamav/var/log"
    sudo mkdir -p "$LOG_DIR"
    sudo chown root:wheel "$LOG_DIR"
    echo "LogFile $LOG_DIR/clamd.log" | sudo tee -a "$CONFIG" > /dev/null
    echo "✓ Enabled LogFile: $LOG_DIR/clamd.log"
fi

echo ""
echo "=== Configuration Updated ==="
echo ""
echo "To apply changes, restart clamd:"
echo "  sudo pkill -x clamd"
echo "  sudo /usr/local/clamav/sbin/clamd --config-file=$CONFIG &"
echo ""
echo "Then view logs with:"
echo "  log stream --predicate 'process == \"clamd\" || process == \"clamonacc\"'"
echo "  # or"
echo "  tail -f $LOG_DIR/clamd.log"

