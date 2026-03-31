# clamd -- ClamAV Daemon

The ClamAV scanning daemon. It loads signature databases into memory once, then accepts scan requests over Unix socket or TCP, returning results to clients. In the Resistine stack, clamd is the always-running backend that the Desktop GUI talks to.

## Key Files

| File | Role |
|---|---|
| `clamd.c` | Entry point. Parses CLI args, loads config (`clamd.conf`), initializes the ClamAV engine (`cl_engine`), drops privileges, then calls `recvloop()`. |
| `server-th.c` | Core event loop (`recvloop()`). Accepts connections via `poll()`/`select()`, dispatches them to the thread pool, handles signal-driven reload (SIGUSR2) and shutdown (SIGINT/SIGTERM). Contains `scanner_thread()` -- the per-request worker that calls `command()`. |
| `session.c` | Protocol parser. `parse_command()` maps wire strings to `enum commands`. `execute_or_dispatch_command()` routes parsed commands. `conn_reply*()` functions format responses back to the client. |
| `scanner.c` | Scan execution. `scanfd()` scans a file descriptor, `scanstream()` scans streamed data, `scan_callback()` is the per-file callback for directory walks. Handles SCAN, CONTSCAN, MULTISCAN, ALLMATCHSCAN, FILDES, and INSTREAM. |
| `localserver.c` | Creates and binds the Unix domain socket (`LocalSocket` config option). |
| `tcpserver.c` | Creates and binds TCP listening socket(s) (`TCPSocket`/`TCPAddr` config options). |
| `thrmgr.c` / `thrmgr.h` | Thread pool manager. Maintains a pool of worker pthreads with two priority queues (single and bulk). Key struct: `threadpool_t` with `thr_max`, `thr_alive`, `thr_idle` tracking. `jobgroup_t` groups related sub-scans (for MULTISCAN). |
| `clamd_others.c` / `clamd_others.h` | Utility functions: `poll_fd()`, `virusaction()` (runs VirusEvent command), `fds_add()`/`fds_poll_recv()` (fd-set management for the accept loop). Defines `struct fd_buf` and `struct fd_data`. |
| `shared.h` | Globals: `debug_mode`, `logok`. |

## Connection Model

1. `clamd.c` calls `localserver()` and/or `tcpserver()` to create listening sockets
2. `recvloop()` in `server-th.c` polls all listening sockets for new connections
3. New connections get an `fd_buf` entry; incoming data is buffered until a complete command arrives
4. Commands are dispatched to `scanner_thread()` via `thrmgr_dispatch()`

Resistine Desktop connects exclusively via Unix socket.

## Protocol Commands

Clients send newline- or null-terminated commands. Key commands used by Resistine Desktop:

- **PING** -- returns `PONG`, used for health checks
- **SCAN path** -- scan a single file, returns `path: OK` or `path: VirusName FOUND`
- **CONTSCAN path** -- scan directory, continue on virus found
- **MULTISCAN path** -- scan directory with parallel threads
- **INSTREAM** -- scan data streamed over the socket (chunk-length prefixed)
- **FILDES** -- scan a file descriptor passed via Unix socket ancillary data
- **RELOAD** -- reload signature databases
- **SHUTDOWN** -- graceful shutdown
- **VERSION** -- returns version string

Responses use `: OK`, `: FOUND`, or `: ERROR` suffixes.

## Threading Model

- `thrmgr_new()` creates a pool with configurable `MaxThreads` (default 10) and `MaxQueue`
- Two queues: **single** (interactive commands like SCAN) and **bulk** (MULTISCAN sub-jobs)
- Single-queue jobs get priority to keep interactive latency low
- Idle threads exit after `IdleTimeout` seconds; new threads spawn on demand up to `thr_max`
- `jobgroup_t` tracks MULTISCAN groups -- the connection closes only when all sub-jobs finish

## Signature Database Reload

- Triggered by SIGUSR2, `SelfCheck` timer, or the RELOAD command (SIGHUP only re-opens the log file, it does not trigger reload)
- `server-th.c` uses a staged reload: a background thread loads the new engine (`RELOAD_STAGE__RELOADING`), then the accept loop swaps it in (`RELOAD_STAGE__NEW_DB_AVAILABLE`)
- Active scans continue using the old engine (refcounted via `cl_engine`)

## Relevant clamd.conf Options

| Option | Purpose |
|---|---|
| `LocalSocket` | Unix socket path |
| `TCPSocket` / `TCPAddr` | TCP listen port and address |
| `MaxThreads` | Thread pool size |
| `MaxQueue` | Max pending scan requests |
| `ScanOnAccess` | Enable on-access scanning (separate from clamonacc) |
| `DatabaseDirectory` | Signature database path |
| `LogFile` | Log output path |
| `SelfCheck` | Interval (seconds) to check for DB updates |
| `VirusEvent` | Command to run on virus detection |
| `CVDCertsDirectory` | Path to CVD signature verification certs |

## Resistine Desktop Integration

Desktop's `plugins/antivirus/clamav.py` manages clamd:

1. **Start**: LaunchDaemon plist or direct exec; waits for socket to appear
2. **Health check**: sends `PING`, expects `PONG`
3. **On-demand scan**: sends `SCAN /path/to/file`, parses `FOUND`/`OK`/`ERROR` response
4. **DB reload**: after freshclam updates, sends `RELOAD`
5. **Shutdown**: sends `SHUTDOWN` or kills the process

## Production Paths (after Resistine Desktop install)

- Config: `/Library/Application Support/Resistine/clamav/clamd.conf`
- Socket: `/Library/Application Support/Resistine/clamav/run/clamd.sock`
- Database: `/Library/Application Support/Resistine/clamav/db/`
- Logs: `/Library/Application Support/Resistine/clamav/log/`
- Binary: `/Applications/Resistine.app/Contents/Helpers/clamd`

## macOS Considerations

- clamd itself does not require ESF entitlements (that is clamonacc's job)
- The LaunchDaemon plist sets `CVD_CERTS_DIR` env var to override the compile-time cert path
- CI-built binaries have rpaths rewritten by Desktop's download script at integration time
- Unix socket permissions must allow the Desktop app (running as the user) to connect
