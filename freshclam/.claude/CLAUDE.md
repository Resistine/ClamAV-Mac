# freshclam — ClamAV Signature Database Updater

## What It Does

freshclam downloads and updates ClamAV virus signature databases (CVD files). It fetches `daily.cvd`, `main.cvd`, and `bytecode.cvd` from configured mirrors over HTTPS, verifies their digital signatures against a CA certificate, and stores them in the database directory for clamd/clamscan to load.

## Key Files

- **freshclam.c** — CLI entry point and main logic: parses config/args, initializes libfreshclam, runs the update loop, and optionally sends a RELOAD command to clamd after updates
- **notify.c** — Connects to clamd (via Unix socket or TCP) and sends a `RELOAD` command so clamd picks up new databases without restarting
- **execute.c** — Runs user-defined hook commands (OnUpdateExecute, OnErrorExecute) as child processes after update events
- **CMakeLists.txt** — Build target `freshclam-bin` (renamed to `freshclam`), links against `ClamAV::libfreshclam`, `ClamAV::libclamav`, and `ClamAV::common`

## How Database Updates Work

1. freshclam reads `DatabaseMirror` (or `PrivateMirror`) from `freshclam.conf`
2. Queries DNS TXT record for update info (version checks, available databases)
3. Calls `fc_update_databases()` in **libfreshclam** which does the actual HTTP download via libcurl, differential (cdiff) patching when possible, and CVD signature verification using the CA cert from `CVDCertsDirectory` or the `CVD_CERTS_DIR` env var
4. After download, `download_complete_callback()` in freshclam.c tests the database by loading it into libclamav to verify integrity
5. If databases were updated, sends `RELOAD` to clamd via `notify()`

Standard databases: `daily`, `main`, `bytecode`. Optional: `safebrowsing`, `test`, `valhalla`.

## Relationship with libfreshclam

freshclam is a thin CLI wrapper. The heavy lifting (HTTP transport, cdiff patching, CVD parsing, signature verification, database pruning) lives in `libfreshclam/`. freshclam calls `fc_initialize()` with an `fc_config` struct, sets a download-complete callback, then calls `fc_update_databases()` and `fc_download_url_databases()`.

## Key Configuration Options (freshclam.conf)

| Option | Purpose |
|---|---|
| `DatabaseDirectory` | Where CVD files are stored |
| `DatabaseMirror` | HTTPS mirror URL (default: database.clamav.net) |
| `CVDCertsDirectory` | CA cert for CVD signature verification |
| `NotifyClamd` | Path to clamd.conf; triggers RELOAD after update |
| `Checks` | Number of update checks per day (1-50) |
| `HTTPProxyServer/Port/Username/Password` | Proxy settings |
| `CompressLocalDatabase` | Keep databases compressed on disk |
| `UpdateLogFile` | Log file path |

The `CVD_CERTS_DIR` environment variable overrides `CVDCertsDirectory`.

## Resistine Desktop Integration

Resistine Desktop runs freshclam as a **one-shot subprocess** from the Python antivirus plugin (`plugins/antivirus/clamav.py`), NOT as a background daemon. The plugin invokes freshclam when the user triggers a database update or on a scheduled basis.

- **Database path**: `/Library/Application Support/Resistine/clamav/db/`
- **Config**: Generated at install time by `build-distribution.sh`; not managed by this repo
- **Binary location** (installed): `/Applications/Resistine.app/Contents/Helpers/freshclam`

## macOS-Specific Notes

- No code signing entitlements required (unlike clamonacc)
- Apple code signing is configured in CMakeLists.txt when `CLAMAV_SIGN_FILE` is set
- On macOS, the `CURL_CA_BUNDLE` env var is not advertised (system TLS handles CA certs)
- Daemon mode (`-d`) is not used in the Resistine integration; freshclam runs once and exits
- The LaunchDaemon plists in `launchd/` are for clamd and clamonacc only, not freshclam
