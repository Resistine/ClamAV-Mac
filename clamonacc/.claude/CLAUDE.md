# clamonacc -- macOS On-Access Scanner

ClamAV's on-access scanning daemon. On macOS, it uses Apple's Endpoint Security Framework (ESF) to receive file-open notifications and forwards files to `clamd` for scanning via Unix socket or TCP.

## Directory Structure

```
clamonacc/
  clamonacc.c/h     -- Entry point, context init, signal handling, event loop dispatch
  esf/              -- macOS ESF integration (compiled only on Apple, gated by HAVE_MACOS_ESF)
  client/           -- Communication with clamd (curl-based socket/TCP, scan protocol)
  scan/             -- Event queue and worker thread logic
  c-thread-pool/    -- Third-party thread pool library (MIT, by Johan Hanssen Seferidis)
  misc/             -- Utilities: path list parsing, FTS directory traversal
  fanotif/          -- Linux fanotify (not used on macOS)
  inotif/           -- Linux inotify (not used on macOS)
```

## Key Files and Roles

### `clamonacc.c` -- Main Entry Point
- Parses CLI args and `clamd.conf` options into `struct onas_context`
- Runs startup checks, sets up the clamd client connection, starts the scan queue thread
- Dispatches to platform-specific event source: `onas_setup_esf()` on macOS, `onas_setup_fanotif()` on Linux
- Calls `onas_start_eloop()` which invokes `onas_esf_eloop()` on macOS
- Signal handler (`onas_clamonacc_exit`) cleans up threads on SIGTERM/SIGINT

### `esf/esf_interface.c` -- ESF Integration (macOS Only)
- **`onas_setup_esf()`**: Creates an ESF client via `es_new_client()`, self-mutes clamonacc's own process to prevent scan loops, sets up inverted target path muting so only `OnAccessIncludePath` directories are monitored, subscribes to `ES_EVENT_TYPE_NOTIFY_OPEN`
- **`onas_esf_handler()`**: Callback invoked by ESF on file-open events. Skips clamd/clamonacc processes, checks `OnAccessExcludePath`, runs a dedup cache (3-second cooldown, 4096-slot hash table), then queues a `struct onas_scan_event` via `onas_queue_event()`
- **`onas_esf_eloop()`**: Blocks the main thread with `sleep(10)` in a loop. ESF callbacks run on Apple's internal dispatch queue, not on the main thread
- Currently uses **NOTIFY mode only** (no blocking/denying). AUTH mode scaffolding exists in `scan/thread.c` (`es_respond_auth_result`) but is not active

### `client/` -- clamd Communication
- **`client.c`**: Sets up curl connection to clamd (Unix socket via `LocalSocket` or TCP via `TCPAddr`/`TCPSocket`). `onas_client_scan()` is the main scan entry point -- connects to clamd and calls `onas_dsresult()` to send the file and parse the verdict
- **`protocol.c`**: Implements the clamd wire protocol -- `CONTSCAN`, `INSTREAM`, `FILDES`, `MULTISCAN`, `ALLMATCHSCAN`. Parses `FOUND`/`ERROR` responses from clamd
- **`communication.c`**: Low-level send/recv over curl sockets with timeout handling
- **`socket.c`**: Unix socket setup for fd-passing mode (`HAVE_FD_PASSING`)

### `scan/` -- Event Queue and Workers
- **`onas_queue.c`**: Doubly-linked-list event queue protected by `onas_queue_lock` mutex. The queue consumer thread (`onas_scan_queue_th`) blocks on a condition variable, dequeues events, and dispatches them to the thread pool via `thpool_add_work()`
- **`thread.c`**: `onas_scan_worker()` is the thread pool work function. Calls `onas_client_scan()` for each file, logs MALWARE DETECTED / Clean / Error results. Contains the scan-with-retry logic and ESF AUTH response path (unused in NOTIFY mode)

### `c-thread-pool/` -- Thread Pool
- Third-party MIT-licensed library. Pool size is set by `OnAccessMaxThreads` from `clamd.conf`
- Workers pull jobs from an internal job queue using binary semaphores

## Data Flow (macOS)

```
ESF kernel -> onas_esf_handler() [dispatch queue]
  -> dedup check, path filtering
  -> onas_queue_event() [enqueue with mutex]
  -> onas_scan_queue_th [consumer thread, blocks on cond var]
  -> thpool_add_work(onas_scan_worker)
  -> onas_client_scan() [curl to clamd socket]
  -> parse clamd response (FOUND / OK / ERROR)
  -> log result
```

## Configuration Dependencies (from clamd.conf)

| Option | Purpose |
|---|---|
| `OnAccessIncludePath` | Directories to monitor (registered as ESF target path prefixes) |
| `OnAccessExcludePath` | Directories to skip (checked in handler, not kernel-level) |
| `OnAccessMaxThreads` | Thread pool size for scan workers |
| `OnAccessCurlTimeout` | Timeout (ms) for clamd communication |
| `OnAccessRetryAttempts` | Retry count on scan errors |
| `OnAccessDenyOnError` | Whether to deny access on scan error (only relevant in AUTH mode) |
| `LocalSocket` | Path to clamd Unix socket (preferred on macOS) |
| `TCPAddr` / `TCPSocket` | Alternative TCP connection to clamd |

## Build Requirements

- **macOS 10.15+**: ESF is only available on Catalina and later
- **CMake flag**: `HAVE_MACOS_ESF` is defined automatically when building on Apple (see `CMakeLists.txt` line 42)
- **EndpointSecurity framework**: Linked via `find_library(ENDPOINT_SECURITY_LIB EndpointSecurity)`
- **Code signing**: Binary MUST be signed with `com.apple.developer.endpoint-security.client` entitlement or `es_new_client()` returns `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`
- **Root required**: ESF clients must run as root
- **Full Disk Access**: The terminal/app running clamonacc needs FDA in System Settings > Privacy

## Gotchas

1. **Self-muting is critical**: `es_mute_process()` prevents clamonacc from triggering events on files it opens. Without it, scanning loops occur.
2. **Inverted path muting**: ESF uses inverted muting -- `es_mute_path()` with inversion means "only deliver events for these paths." Without at least one `OnAccessIncludePath`, setup fails.
3. **NOTIFY vs AUTH mode**: Currently NOTIFY-only. AUTH mode requires responding to every event within ~3-4 seconds or macOS will SIGKILL the process. The response scaffolding exists in `thread.c` but `event_data->es_msg` is always NULL in NOTIFY mode.
4. **Dedup cache**: A 4096-slot hash table with 3-second cooldown prevents duplicate scans for the same file. Hash collisions silently overwrite entries.
5. **Scan lock**: `onas_scan_lock` in `thread.c` serializes all clamd socket communication. This is a bottleneck -- only one scan at a time despite the thread pool.
6. **Main thread just sleeps**: `onas_esf_eloop()` is an infinite `sleep(10)` loop. ESF callbacks run on Apple's internal GCD dispatch queue.
7. **Process name filtering**: The handler skips events where the instigator process basename is "clamd" or "clamonacc". This is a string comparison, not PID-based.
8. **fanotif/ and inotif/ are dead code on macOS**: Gated by `HAVE_SYS_FANOTIFY_H` which is never defined on macOS. Don't modify them for macOS work.
9. **clamd must be running**: clamonacc is a thin client -- it does not load signature databases. All scanning happens in clamd via the socket protocol.
