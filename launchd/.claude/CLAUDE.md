# launchd/ — macOS LaunchDaemon Plists

LaunchDaemon plist files that run ClamAV services at boot as root.
These are bundled into CI artifacts by `build-artifacts.yml` and installed
to `/Library/LaunchDaemons/` by Resistine Desktop's `build-distribution.sh`.

## Files

### com.resistine.clamd.plist
ClamAV scanning daemon. Listens on a Unix socket for scan requests from
`clamonacc` and `clamdscan`. Must be running before `clamonacc` can operate.

- **Binary**: `/Applications/Resistine.app/Contents/Helpers/clamd`
- **Args**: `--config-file <clamd.conf> --foreground`
- **Env**: `CVD_CERTS_DIR=/Applications/Resistine.app/Contents/certs`
- **Logs**: `/Library/Application Support/Resistine/clamav/log/clamd.{stdout,stderr}.log`

### com.resistine.clamonacc.plist
On-access scanner using Apple's Endpoint Security Framework (ESF).
Monitors file events system-wide and forwards them to `clamd` for scanning.

- **Binary**: `.../Resistine.app/Contents/Helpers/ResistineClamAV.app/Contents/MacOS/clamonacc`
- **Args**: `--config-file <clamd.conf> -F` (`-F` = foreground, required for ESF)
- **ProcessType**: `Interactive` (needed for ESF event handling)
- **Logs**: `/Library/Application Support/Resistine/clamav/log/clamonacc.{stdout,stderr}.log`

## Common Configuration

Both plists share these settings:
- **RunAtLoad**: `true` — start automatically at boot
- **KeepAlive/SuccessfulExit**: `false` — restart on crash (but not on clean exit)
- **UserName/GroupName**: `root`/`wheel` — required for ESF and daemon operation
- **ThrottleInterval**: 10 seconds between crash-restarts

## CVD_CERTS_DIR Environment Variable

`clamd` has a `CVDCertsDirectory` path hardcoded at compile time, which points to
the CI runner's filesystem. The `CVD_CERTS_DIR` env var in the clamd plist overrides
this at runtime so clamd can verify CVD signature databases in production.

## How LaunchDaemons Work

macOS LaunchDaemons are system-level services managed by `launchd`. Plists in
`/Library/LaunchDaemons/` run as root and start at boot (if `RunAtLoad` is set).

### Installation (done by Resistine Desktop)
```bash
sudo cp com.resistine.clamd.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.resistine.clamd.plist
```

### Debugging
```bash
# Check if services are loaded (0 = running, non-zero = error code)
sudo launchctl list | grep resistine

# View detailed service info
sudo launchctl print system/com.resistine.clamd
sudo launchctl print system/com.resistine.clamonacc

# Tail logs
tail -f "/Library/Application Support/Resistine/clamav/log/clamd.stderr.log"
tail -f "/Library/Application Support/Resistine/clamav/log/clamonacc.stderr.log"

# Restart a service
sudo launchctl kickstart -k system/com.resistine.clamd
```

## Gotchas

- ProgramArguments paths are **rewritten at install time** by `build-distribution.sh`
- `clamonacc` requires Full Disk Access in System Settings > Privacy & Security
- `clamonacc` lives inside a nested `.app` bundle for ESF entitlement signing
- `clamd` must start before `clamonacc` — no explicit ordering exists in these plists;
  `clamonacc` retries its connection to the clamd socket internally
