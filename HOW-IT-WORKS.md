# How ClamAV Works (macOS ESF Version)

## Architecture

ClamAV on macOS uses **two components** working together:

### 1. `clamd` (ClamAV Daemon)
- **What it does**: The scanning engine that loads virus definitions and performs actual scans
- **Where it runs**: Background daemon listening on `127.0.0.1:3310`
- **What it needs**: Virus definition databases in `/usr/local/clamav/share/clamav/`

### 2. `clamonacc` (ClamAV On-Access Scanner)
- **What it does**: Monitors file system events using macOS Endpoint Security Framework (ESF)
- **How it works**:
  1. Subscribes to `ES_EVENT_TYPE_AUTH_OPEN` events (when files are opened)
  2. When a file is opened, ESF calls `onas_esf_handler()` **immediately**
  3. Handler responds to ESF **first** (to meet deadline), then queues the file path for scanning
  4. A worker thread picks up the queued file and sends it to `clamd` for scanning
  5. If malware is detected, it logs an alert (but can't block the open since it already allowed it)

## Flow Diagram

```
File Open Event
    ↓
macOS Endpoint Security Framework
    ↓
clamonacc ESF Handler (responds immediately)
    ↓
Queue file path for async scanning
    ↓
Worker thread picks up file
    ↓
Send to clamd via TCP (127.0.0.1:3310)
    ↓
clamd scans file with virus definitions
    ↓
Result: Clean or Infected (logged)
```

## Important Notes

- **On-access scanning**: Files are scanned when they're **opened**, not when they're created
- **Async scanning**: The file open is **allowed immediately** (to meet ESF deadline), then scanned in background
- **No blocking**: If malware is found, it's logged but the file open already happened
- **Self-muting**: `clamonacc` mutes its own process to avoid scanning files it opens itself

## How to Verify It's Working

### 1. Check Both Services Are Running

```bash
# Check clamd
pgrep -fl clamd
nc -z 127.0.0.1 3310 && echo "✓ clamd is listening"

# Check clamonacc
pgrep -fl clamonacc
```

### 2. Test with EICAR Test File

EICAR is a harmless test file that all antivirus software recognizes as "malware" for testing:

```bash
# Create EICAR test file (zsh-safe)
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\\n' > /tmp/eicar-test.txt

# Open it (this should trigger a scan)
cat /tmp/eicar-test.txt

# Check clamd logs (if configured)
tail -f /usr/local/clamav/var/log/clamd.log
```

### 3. Check ClamAV Logs

ClamAV logs to syslog. Check for scan results:

```bash
# Recent ClamAV activity
log show --last 5m --style compact --predicate 'process == "clamd" || process == "clamonacc"' | grep -i "scan\|infected\|clean"

# Or watch in real-time
log stream --predicate 'process == "clamd" || process == "clamonacc"'
```

### 4. Manual Scan Test

You can also manually scan a file to verify `clamd` is working:

```bash
# Scan a file manually
/usr/local/clamav/bin/clamdscan /tmp/eicar-test.txt

# Or use clamscan (standalone, doesn't need clamd)
/usr/local/clamav/bin/clamscan /tmp/eicar-test.txt
```

### 5. Monitor File Access Events

To see if `clamonacc` is receiving ESF events (though they may not appear in logs):

```bash
# Check for ESF errors (should be none)
log show --last 2m --predicate 'process == "clamonacc" && (eventMessage CONTAINS "Corpse" || eventMessage CONTAINS "timeout")'

# Should return nothing if working correctly
```

## Configuration Files

- **`/usr/local/clamav/etc/clamd.conf`**: Main configuration for `clamd`
- **`/usr/local/clamav/etc/freshclam.conf`**: Configuration for updating virus definitions
- **Virus definitions**: `/usr/local/clamav/share/clamav/`

## Updating Virus Definitions

```bash
sudo freshclam
```

This downloads the latest virus signatures from ClamAV's servers.

