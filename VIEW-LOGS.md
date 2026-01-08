# How to See ClamAV Logs

## Why You Don't See Logs

ClamAV **doesn't log to syslog by default**. That's why `log stream` shows nothing.

## Option 1: Enable Syslog Logging (Recommended)

Run this script to enable logging:

```bash
./scripts/enable-logging.sh
```

Then restart `clamd`:

```bash
sudo pkill -x clamd
sudo /usr/local/clamav/sbin/clamd --config-file=/usr/local/clamav/etc/clamd.conf &
```

Now you'll see logs:

```bash
log stream --predicate 'process == "clamd" || process == "clamonacc"'
```

## Option 2: Manual Config Edit

Edit `/usr/local/clamav/etc/clamd.conf` and add:

```
LogSyslog yes
LogVerbose yes
LogTime yes
LogFile /usr/local/clamav/var/log/clamd.log
```

Then restart `clamd`.

## Option 3: See Activity Without Logging

### Test with EICAR (triggers a scan)

```bash
# Create test file (zsh-safe)
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\\n' > /tmp/eicar.txt

# Open it (triggers on-access scan)
cat /tmp/eicar.txt

# Check if it was detected
/usr/local/clamav/bin/clamdscan /tmp/eicar.txt
```

### Check Process Activity

```bash
# See if processes are running
ps aux | grep -E '(clamd|clamonacc)'

# Check if clamd is responding
echo "PING" | nc 127.0.0.1 3310
```

### Monitor File Access (if logging enabled)

```bash
# Watch syslog in real-time
log stream --predicate 'process == "clamd" || process == "clamonacc"'

# Or watch log file
tail -f /usr/local/clamav/var/log/clamd.log
```

## What Gets Logged (when enabled)

- File scans (clean/infected)
- Virus detections
- Scan errors
- Connection events
- Database reloads

## Quick Test

After enabling logging, test it:

```bash
# Create and open a file
touch /tmp/test-scan.txt
cat /tmp/test-scan.txt

# Check logs (should see scan activity)
log show --last 10s --predicate 'process == "clamd"'
```

