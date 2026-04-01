# Implementation Plan: AUTH Mode Real-Time Protection

## Current State

- ESF subscribes to `ES_EVENT_TYPE_NOTIFY_OPEN` (fire-and-forget) in `esf_interface.c:321`
- `g_auth_mode` declared but never set to true
- AUTH scaffolding exists: handler retains messages, `thread.c` calls `es_respond_auth_result` when `es_msg != NULL`
- `onas_scan_lock` serializes ALL scans (thread pool is effectively single-threaded)
- No clean-file cache — every file open triggers a full clamd scan
- Scan mode is CONTSCAN by default; FILDES only via `--fdpass` CLI flag

---

## Phase 1: Remove Scan Lock Bottleneck

**Prerequisite for everything else — makes the thread pool actually parallel.**

| File | Change |
|---|---|
| `clamonacc/scan/thread.c` | Remove `onas_scan_lock` mutex and lock/unlock wrapping `onas_client_scan()`. Each worker already creates its own curl connection — no shared state requires serialization. |

**Risk**: Low. Verify under load that clamd handles concurrent Unix socket connections (it does — clamd is multi-threaded).

---

## Phase 2: Clean-File Cache (by stat metadata)

**Biggest performance win — cache hits respond in sub-millisecond, making AUTH feasible.**

| File | Change |
|---|---|
| `clamonacc/scan/hash_cache.c` (new) | Hash table keyed by `(device, inode, mtime, size)` — NOT content hash (too slow). Fixed-size (65536 slots), sharded locks (16 mutexes) for concurrency. TTL expiry (default 5min), full flush on signature DB reload. |
| `clamonacc/scan/hash_cache.h` (new) | Expose `cache_lookup(dev, ino, mtime, size)` → HIT_CLEAN/HIT_INFECTED/MISS and `cache_insert(dev, ino, mtime, size, verdict)`. |
| `clamonacc/esf/esf_interface.c` | After path filtering, `stat()` + `cache_lookup()`. On HIT_CLEAN → instant ALLOW. On HIT_INFECTED → instant DENY. |
| `clamonacc/scan/thread.c` | After scan completes, `cache_insert()` with verdict. |
| `clamonacc/CMakeLists.txt` | Add `scan/hash_cache.c` to source list. |

**Risk**: TOCTOU mitigated by stat key (mtime+size). AUTH holds file open. TTL expiry handles sig updates.

---

## Phase 3: Switch to AUTH Mode

**The actual prevention — block malicious file opens.**

| File | Change |
|---|---|
| `clamonacc/esf/esf_interface.c` | Subscribe to `ES_EVENT_TYPE_AUTH_OPEN` instead of `NOTIFY_OPEN` (conditional on `OnAccessPrevention` config). Set `g_auth_mode = true`. Add load-shedding: if queue depth > 100, auto-ALLOW to prevent SIGKILL. Set `enqueue_time` via `clock_gettime()` before queueing. |
| `clamonacc/scan/thread.h` | Add `struct timespec enqueue_time` to `onas_scan_event`. |
| `clamonacc/scan/thread.c` | Before scanning, check if >2.5s elapsed since enqueue. If so, respond ALLOW (deadline safety) and log warning. |

**Risk**: HIGH — ESF SIGKILLs on slow scan. Mitigated by deadline enforcement + load shedding + cache from Phase 2.

---

## Phase 4: FILDES Mode (can parallel with Phase 2)

**Avoids clamd re-opening by path — saves syscall + prevents recursive ESF events.**

| File | Change |
|---|---|
| `clamonacc/client/client.c` | Auto-enable `scantype = FILDES` when ESF is active + local socket, instead of requiring `--fdpass` flag. |
| `clamonacc/client/socket.c` | Verify each thread opens its own socket (not sharing via `onas_set_sock_only_once`), or change to per-scan connections. |

**Risk**: Medium. Socket isolation must be verified — shared socket would re-serialize scans.

---

## Phase 5: Configuration & UX

| File | Change |
|---|---|
| `clamonacc/clamonacc.c` | Read `OnAccessPrevention` config option. Log mode at startup: "AUTH (prevention)" vs "NOTIFY (detection-only)". |
| `clamonacc/esf/esf_interface.c` | Log warnings when too many deadline-forced ALLOWs occur. |

---

## Execution Order

| Phase | Depends On | Risk |
|---|---|---|
| 1 — Remove scan lock | None | Low |
| 2 — Hash cache | None | Medium |
| 4 — FILDES | None | Medium |
| 3 — AUTH switch | Phase 1 + 2 | **High** |
| 5 — Config/UX | Phase 3 | Low |

Phases 1, 2, and 4 are independent and can be developed in parallel.

---

## Key Risks & Mitigations

| Risk | Mitigation |
|---|---|
| ESF SIGKILLs on slow scan (>3-4s) | Deadline enforcement (2.5s auto-ALLOW) + load shedding (queue > 100) |
| Cache TOCTOU (file changes after cache hit) | Key includes mtime+size; AUTH holds file open; TTL expiry |
| Removing scan lock causes issues | Each call creates own curl/socket; clamd handles concurrency |
| FILDES shared socket re-serializes | Per-scan socket connections |
| Queue flood cascading deadline misses | Auto-ALLOW when queue depth exceeds threshold |
