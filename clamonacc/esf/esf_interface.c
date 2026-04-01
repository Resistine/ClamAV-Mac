/*
 *  Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Petr Resistine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#if defined(__APPLE__)

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <EndpointSecurity/EndpointSecurity.h>

// libclamav
#include "clamav.h"
#include "others.h"

// common
#include "output.h"
#include "optparser.h"

#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/task_info.h>
#include <mach/kern_return.h>

// clamonacc
#include "clamonacc.h"
#include "esf_interface.h"

// Queue headers
#include "scan/onas_queue.h"
#include "scan/thread.h"
#include "scan/hash_cache.h"
#include "misc/utils.h"

static struct onas_context *g_esf_ctx = NULL;
es_client_t *g_client = NULL;
static bool g_auth_mode = false;

/* Concurrent GCD queue for post-AUTH-response async work (scan queueing).
 * In AUTH mode the ESF handler must return ASAP after responding so the
 * serial ESF dispatch queue can deliver the next event.  All post-response
 * work (dedup, path checks, memory alloc, scan queue insertion) is
 * dispatched here instead of running inline. */
static dispatch_queue_t g_async_scan_queue = NULL;

/* Load shedding: auto-ALLOW AUTH events when queue is too deep */
#define ESF_QUEUE_DEPTH_LIMIT 100
#include <stdatomic.h>
atomic_int g_pending_scans = 0;

/* --- Dedup cache: suppress duplicate ESF events for the same path --- */
#define DEDUP_SLOTS 4096
#define DEDUP_COOLDOWN_SEC 3

struct dedup_entry {
    char *path;
    time_t timestamp;
};

static struct dedup_entry g_dedup[DEDUP_SLOTS];
static pthread_mutex_t g_dedup_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned int dedup_hash(const char *s)
{
    unsigned int h = 5381;
    while (*s)
        h = ((h << 5) + h) ^ (unsigned char)*s++;
    return h % DEDUP_SLOTS;
}

/* Returns true if the path was seen recently and should be skipped. */
static bool onas_esf_dedup_check(const char *path)
{
    unsigned int idx = dedup_hash(path);
    time_t now       = time(NULL);
    bool skip        = false;

    pthread_mutex_lock(&g_dedup_lock);

    struct dedup_entry *e = &g_dedup[idx];
    if (e->path && strcmp(e->path, path) == 0 &&
        (now - e->timestamp) < DEDUP_COOLDOWN_SEC) {
        skip = true;
    } else {
        free(e->path);
        e->path = strdup(path);
        if (e->path) {
            e->timestamp = now;
        } else {
            e->timestamp = 0;
            logg(LOGG_ERROR, "ClamESF: strdup failed in dedup cache (OOM)\n");
        }
    }

    pthread_mutex_unlock(&g_dedup_lock);
    return skip;
}

static bool onas_esf_is_excluded_path(const char *path)
{
    const struct optstruct *pt;

    if (!g_esf_ctx || !g_esf_ctx->clamdopts || !path)
        return false;

    pt = optget(g_esf_ctx->clamdopts, "OnAccessExcludePath");
    while (pt) {
        if (pt->strarg && strncmp(path, pt->strarg, strlen(pt->strarg)) == 0)
            return true;
        pt = pt->nextarg;
    }

    return false;
}

/* Respond ALLOW to an AUTH event so ESF doesn't SIGKILL us on timeout. */
static void onas_esf_auth_allow(const es_message_t *message)
{
    es_respond_auth_result(g_client, message, ES_AUTH_RESULT_ALLOW, true);
}

/* Post-response async work: dedup, path filtering, scan queue insertion.
 * Called either inline (NOTIFY mode) or on a GCD concurrent queue
 * (AUTH mode) so the ESF serial dispatch queue stays unblocked.
 * Owns `path_copy` and must free it. `proc_copy` may be NULL. */
static void onas_esf_queue_scan(char *path_copy, char *proc_copy,
                                bool is_auth)
{
    struct onas_scan_event *event_data = NULL;

    logg(LOGG_DEBUG, "ClamESF: handler — auth=%d path=%s\n",
         is_auth, path_copy ? path_copy : "(null)");

    /* Skip events caused by clamd or clamonacc to avoid scan loops. */
    if (proc_copy) {
        const char *basename = strrchr(proc_copy, '/');
        basename = basename ? basename + 1 : proc_copy;
        if (strcmp(basename, "clamd") == 0 ||
            strcmp(basename, "clamonacc") == 0) {
            goto out;
        }
    }

    if (!path_copy || onas_esf_is_excluded_path(path_copy))
        goto out;

    if (onas_esf_dedup_check(path_copy))
        goto out;

    /* Load shedding: if too many scans pending, skip queueing entirely */
    if (atomic_load(&g_pending_scans) > ESF_QUEUE_DEPTH_LIMIT) {
        logg(LOGG_WARNING,
             "ClamESF: load shedding — skipping scan for %s "
             "(queue depth > %d)\n",
             path_copy, ESF_QUEUE_DEPTH_LIMIT);
        goto out;
    }

    event_data = calloc(1, sizeof(struct onas_scan_event));
    if (NULL == event_data) {
        logg(LOGG_ERROR,
             "ClamESF: could not allocate memory for event data struct\n");
        goto out;
    }

    if (CL_SUCCESS != onas_map_context_info_to_event_data(g_esf_ctx,
                                                           &event_data)) {
        logg(LOGG_ERROR, "ClamESF: failed to map context info\n");
        free(event_data);
        goto out;
    }

    event_data->bool_opts |= ONAS_SCTH_B_ESF;
    event_data->bool_opts |= ONAS_SCTH_B_SCAN;
    event_data->bool_opts |= ONAS_SCTH_B_FILE;

    event_data->es_msg = NULL;
    memset(&event_data->enqueue_time, 0, sizeof(event_data->enqueue_time));
    atomic_fetch_add(&g_pending_scans, 1);

    /* Transfer ownership of path_copy to the event */
    event_data->pathname = path_copy;
    path_copy = NULL;  /* prevent free in out: */

    if (CL_SUCCESS != onas_queue_event(event_data)) {
        logg(LOGG_ERROR, "ClamESF: failed to queue event\n");
        atomic_fetch_sub(&g_pending_scans, 1);
        free(event_data->pathname);
        free(event_data);
        goto out;
    }

    logg(LOGG_DEBUG, "ClamESF: queued async scan for: %s\n",
         event_data->pathname);

out:
    free(path_copy);
    free(proc_copy);
}

static void onas_esf_handler(es_client_t *client __attribute__((unused)),
                             const es_message_t *message)
{
    bool is_auth = (message->event_type == ES_EVENT_TYPE_AUTH_OPEN);

    if (message->event_type != ES_EVENT_TYPE_NOTIFY_OPEN &&
        message->event_type != ES_EVENT_TYPE_AUTH_OPEN) {
        return;
    }

    const es_file_t *target = message->event.open.file;

    /* AUTH FAST PATH — respond immediately, then dispatch async work.
     *
     * ESF delivers AUTH events on a serial queue.  Each message has a
     * ~3-4 s deadline; if we don't call es_respond_auth_result before
     * the deadline the kernel SIGKILLs us.  The handler must also
     * *return* quickly so the serial queue can deliver the next event.
     *
     * Strategy: respond ALLOW/DENY immediately (only a cache lookup
     * gates the decision), copy the path, dispatch everything else to
     * a concurrent GCD queue, and return. */
    if (is_auth) {
        bool denied = false;

        if (target) {
            /* Non-blocking: if the shard is contended (scan worker
             * inserting), we get MISS and fall through to ALLOW.
             * The file will be scanned async and denied on next open. */
            onas_cache_result_t cres = onas_cache_lookup_nonblocking(
                target->stat.st_dev, target->stat.st_ino,
                target->stat.st_mtime, target->stat.st_size);
            if (cres == ONAS_CACHE_HIT_INFECTED) {
                es_respond_auth_result(g_client, message,
                                       ES_AUTH_RESULT_DENY, false);
                denied = true;
            }
        }

        if (!denied) {
            onas_esf_auth_allow(message);
        }

        /* AUTH response sent — copy what we need, then dispatch async.
         * The es_message_t is only valid for the duration of this
         * callback, so we must copy the path and process name now. */
        const char *file_path = target ? target->path.data : NULL;
        char *path_copy = file_path ? strdup(file_path) : NULL;
        char *proc_copy = NULL;
        if (message->process && message->process->executable)
            proc_copy = strdup(message->process->executable->path.data);

        if (denied) {
            /* Log on the async queue to avoid blocking ESF serial queue
             * with the global logg_mutex + file I/O. */
            dispatch_async(g_async_scan_queue, ^{
                logg(LOGG_WARNING, "ClamESF: AUTH DENY (cached): %s\n",
                     path_copy ? path_copy : "(null)");
                free(path_copy);
                free(proc_copy);
            });
            return;
        }

        /* Dispatch post-response work off the ESF serial queue */
        dispatch_async(g_async_scan_queue, ^{
            onas_esf_queue_scan(path_copy, proc_copy, true);
        });
        return;
    }

    /* --- NOTIFY mode: no deadline, run inline --- */
    const char *file_path = target ? target->path.data : NULL;

    /* NOTIFY-mode cache check (skip known-clean files) */
    if (target) {
        const struct stat *fst = &target->stat;
        onas_cache_result_t cres = onas_cache_lookup(
            fst->st_dev, fst->st_ino, fst->st_mtime, fst->st_size);
        if (cres == ONAS_CACHE_HIT_CLEAN)
            return;
        if (cres == ONAS_CACHE_HIT_INFECTED) {
            logg(LOGG_WARNING, "ClamESF: cached INFECTED: %s\n",
                 file_path ? file_path : "(null)");
            return;
        }
    }

    char *path_copy = file_path ? strdup(file_path) : NULL;
    char *proc_copy = NULL;
    if (message->process && message->process->executable)
        proc_copy = strdup(message->process->executable->path.data);

    onas_esf_queue_scan(path_copy, proc_copy, false);
}

cl_error_t onas_setup_esf(struct onas_context **ctx)
{
    es_new_client_result_t result;

    if (!ctx || !*ctx) {
        logg(LOGG_ERROR, "ClamESF: unable to start clamonacc. (bad context)\n");
        return CL_EARG;
    }

    g_esf_ctx = *ctx;

    /* Create the concurrent queue used to offload post-AUTH work */
    if (!g_async_scan_queue) {
        g_async_scan_queue = dispatch_queue_create(
            "com.resistine.clamonacc.async-scan",
            DISPATCH_QUEUE_CONCURRENT);
    }

    logg(LOGG_INFO, "ClamESF: Initializing Endpoint Security Framework client...\n");

    result = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *m) {
        onas_esf_handler(c, m);
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        logg(LOGG_ERROR, "ClamESF: Failed to create new ES client. Result code: %d\n", result);
        if (result == ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED) {
            logg(LOGG_ERROR, "ClamESF: Application lacks the 'com.apple.developer.endpoint-security.client' entitlement.\n");
        }
        return CL_EARG;
    }

    /* Mute ClamAV's own process to avoid scanning files we open.
     * This must happen BEFORE subscribing to avoid a startup event storm. */
    {
        mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
        audit_token_t token;
        kern_return_t kr = task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                                     (task_info_t)&token, &count);
        if (kr == KERN_SUCCESS) {
            if (es_mute_process(g_client, &token) != ES_RETURN_SUCCESS) {
                logg(LOGG_WARNING,
                     "ClamESF: Failed to mute own process. "
                     "Recursive scanning loops possible!\n");
            }
        } else {
            logg(LOGG_WARNING,
                 "ClamESF: Failed to get own audit token. Cannot mute self.\n");
        }
    }

    /* Note: clamd is NOT muted at the ESF level because we can't easily
     * obtain its audit_token_t.  Instead, onas_esf_queue_scan() checks
     * the instigator process name and skips events from clamd/clamonacc.
     * In AUTH mode, the handler still responds ALLOW instantly for these
     * events (no deadline risk), and the async queue drops them. */

    /* Set up inverted target path muting so the kernel only delivers events
     * for files under OnAccessIncludePath directories.  Without this, every
     * file-open on the entire system hits our handler and we can't respond
     * within the ESF deadline (~3-4 s), causing a SIGKILL. */
    if (es_unmute_all_target_paths(g_client) != ES_RETURN_SUCCESS) {
        logg(LOGG_ERROR, "ClamESF: Failed to unmute all target paths before inversion.\n");
        es_delete_client(g_client);
        g_client = NULL;
        return CL_EARG;
    }

    if (es_invert_muting(g_client, ES_MUTE_INVERSION_TYPE_TARGET_PATH) != ES_RETURN_SUCCESS) {
        logg(LOGG_ERROR, "ClamESF: Failed to invert target path muting.\n");
        es_delete_client(g_client);
        g_client = NULL;
        return CL_EARG;
    }

    /* Register each OnAccessIncludePath as a muted (= selected, due to
     * inversion) target path prefix. */
    const struct optstruct *pt = optget(g_esf_ctx->clamdopts, "OnAccessIncludePath");
    int path_count = 0;
    while (pt) {
        if (pt->strarg) {
            if (es_mute_path(g_client, pt->strarg, ES_MUTE_PATH_TYPE_TARGET_PREFIX) == ES_RETURN_SUCCESS) {
                logg(LOGG_INFO, "ClamESF: Monitoring path: %s\n", pt->strarg);
                path_count++;
            } else {
                logg(LOGG_WARNING, "ClamESF: Failed to add monitored path: %s\n", pt->strarg);
            }
        }
        pt = pt->nextarg;
    }

    if (path_count == 0) {
        logg(LOGG_ERROR, "ClamESF: No OnAccessIncludePath configured — nothing to monitor.\n");
        es_delete_client(g_client);
        g_client = NULL;
        return CL_EARG;
    }

    /* Choose AUTH (prevention) or NOTIFY (detection-only) based on config */
    if (optget(g_esf_ctx->clamdopts, "OnAccessPrevention")->enabled) {
        g_auth_mode = true;
        es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_OPEN };
        if (es_subscribe(g_client, events, 1) != ES_RETURN_SUCCESS) {
            logg(LOGG_ERROR, "ClamESF: Failed to subscribe to AUTH_OPEN events.\n");
            es_delete_client(g_client);
            g_client = NULL;
            return CL_EARG;
        }
        logg(LOGG_INFO, "ClamESF: AUTH mode (prevention) — known malware will be BLOCKED on open, new files scanned async.\n");
    } else {
        es_event_type_t events[] = { ES_EVENT_TYPE_NOTIFY_OPEN };
        if (es_subscribe(g_client, events, 1) != ES_RETURN_SUCCESS) {
            logg(LOGG_ERROR, "ClamESF: Failed to subscribe to NOTIFY_OPEN events.\n");
            es_delete_client(g_client);
            g_client = NULL;
            return CL_EARG;
        }
        logg(LOGG_INFO, "ClamESF: NOTIFY mode (detection-only) — malicious files will be logged, not blocked.\n");
    }

    logg(LOGG_INFO, "ClamESF: Client created and subscribed successfully (%d paths monitored).\n", path_count);

    return CL_SUCCESS;
}

void onas_teardown_esf(void)
{
    if (g_client) {
        logg(LOGG_INFO, "ClamESF: Tearing down ESF client (unsubscribe + delete)...\n");
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
        g_client = NULL;
        logg(LOGG_INFO, "ClamESF: ESF client destroyed.\n");
    }

    if (g_async_scan_queue) {
        /* Barrier ensures all queued blocks complete before release */
        dispatch_barrier_sync(g_async_scan_queue, ^{});
        dispatch_release(g_async_scan_queue);
        g_async_scan_queue = NULL;
    }
}

int onas_esf_eloop(struct onas_context **ctx)
{
    (void)ctx;
    logg(LOGG_INFO, "ClamESF: Starting ESF generic loop...\n");
    
    /* 
     * ESF callbacks run on a dispatch queue managed by the framework.
     * We just need to keep the main thread alive. 
     * In the future we might want to use a cond var or signal to exit cleanly.
     */
    while (1) {
        sleep(10);
    }
    
    /* Cleanup (unreachable in this loop but good practice) */
    if (g_client) {
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
    }
    
    return 0;
}

#endif /* __APPLE__ */
