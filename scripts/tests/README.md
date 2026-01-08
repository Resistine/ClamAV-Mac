# scripts/tests (macOS verification)

These scripts are meant to answer: **“Is ClamAV actually working on this Mac?”**

## Quick start

```bash
cd /Users/dlesher/Desktop/Resistine/Resistine-ClamAV-Mac/ClamAV-Mac
./scripts/tests/macos-verify.sh
```

## What it verifies

- **Binaries present** under `/usr/local/clamav/{sbin,bin}`
- **`clamd` TCP socket** reachable on `127.0.0.1:3310`
- **Database present** (signatures installed) and optionally runs `freshclam` if you request it
- **On-demand scan works** via `clamdscan` and `clamscan` using the EICAR test string
- **Code signing & entitlements** (confirms the ESF entitlement on `clamonacc`)
- **RPATH sanity** (no accidental dependency on build-tree paths)
- **On-access smoke test** for `clamonacc` (process running + no recent ESF deadline crashes)

## Notes

- Some checks require **sudo** (reading signatures / processes owned by root).
- Full Disk Access (TCC) **cannot be reliably verified programmatically**; the script will only tell you what to check.


