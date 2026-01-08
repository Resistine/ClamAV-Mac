# How to Start ClamAV

## Quick Start (Recommended)

Use the automated script that builds, installs, signs, and starts everything:

```bash
cd /Users/dlesher/Desktop/Resistine/Resistine-ClamAV-Mac/ClamAV-Mac
./scripts/build-and-start.sh
```

This script will:
1. Build `clamd` and `clamonacc`
2. Install them to `/usr/local/clamav`
3. Fix RPATHs and code sign them
4. Start `clamd` (waits for it to be ready)
5. Start `clamonacc` in foreground mode

**Note**: The script will run `clamonacc` in the foreground, so it will stay running in your terminal. Press `Ctrl+C` to stop it.

---

## Manual Start (Step by Step)

If you prefer to start services manually:

### 1. Start `clamd` (the scanning daemon)

```bash
sudo /usr/local/clamav/sbin/clamd --config-file=/usr/local/clamav/etc/clamd.conf &
```

Or run in foreground to see logs:
```bash
sudo /usr/local/clamav/sbin/clamd --config-file=/usr/local/clamav/etc/clamd.conf
```

### 2. Verify `clamd` is listening

```bash
# Wait a few seconds, then check:
nc -z 127.0.0.1 3310 && echo "✓ clamd is ready"
```

### 3. Start `clamonacc` (the on-access scanner)

**IMPORTANT**: Must use `-F` (foreground) flag for ESF to work:

```bash
sudo /usr/local/clamav/sbin/clamonacc -F --config-file=/usr/local/clamav/etc/clamd.conf
```

This will run in the foreground. Press `Ctrl+C` to stop.

---

## Check if It's Running

```bash
# Check clamd
pgrep -fl clamd
nc -z 127.0.0.1 3310 && echo "✓ clamd listening"

# Check clamonacc
pgrep -fl clamonacc
```

---

## Stop ClamAV

```bash
# Stop clamonacc
sudo pkill -x clamonacc

# Stop clamd
sudo pkill -x clamd
```

Or stop both:
```bash
sudo pkill -x clamonacc
sudo pkill -x clamd
```

---

## Troubleshooting

### "Could not connect to clamd"
- Make sure `clamd` is running first
- Check it's listening: `nc -z 127.0.0.1 3310`

### "Address already in use"
- Another `clamd` is already running
- Stop it: `sudo pkill -x clamd`

### Multiple `clamonacc` instances
- Stop all: `sudo pkill -x clamonacc`
- Start one: `sudo /usr/local/clamav/sbin/clamonacc -F --config-file=/usr/local/clamav/etc/clamd.conf`

### No events / permission errors (macOS)
- `clamonacc` typically needs **Full Disk Access** (and sometimes the app launching it, e.g. Terminal/Cursor).
- After granting permissions, restart `clamonacc`.

