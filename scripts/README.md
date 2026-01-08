# scripts/

Canonical helper scripts for macOS `clamd` + `clamonacc`.

- **`build-and-start.sh`**: build + install + (optionally) sign + start `clamd` then `clamonacc -F`
- **`enable-logging.sh`**: enable `clamd` logging (syslog + file), then restart `clamd`
- **`test-eicar.sh`**: create EICAR test file and verify detection via `clamdscan` + `clamscan`
- **`add-to-path.sh`**: add `/usr/local/clamav/bin` to your `PATH` (zsh)


