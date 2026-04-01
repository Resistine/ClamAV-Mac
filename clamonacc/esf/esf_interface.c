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

static void onas_esf_handler(es_client_t *client __attribute__((unused)), const es_message_t *message)
{
    struct onas_scan_event *event_data = NULL;
    bool is_auth = (message->event_type == ES_EVENT_TYPE_AUTH_OPEN);

    if (message->event_type != ES_EVENT_TYPE_NOTIFY_OPEN &&
        message->event_type != ES_EVENT_TYPE_AUTH_OPEN) {
        logg(LOGG_DEBUG, "ClamESF: ignoring unexpected event type %d\n", message->event_type);
        if (message->action_type == ES_ACTION_TYPE_AUTH)
            onas_esf_auth_allow(message);
        return;
    }

    /* Skip events caused by clamd or clamonacc to avoid scan loops.
     * The process info is in message->process (the instigator).
     * Note: executable is _Nullable per Apple docs (Jetsam, early boot, etc.) */
    const char *proc_name = NULL;
    if (message->process && message->process->executable) {
        proc_name = message->process->executable->path.data;
    }
    if (proc_name) {
        const char *basename = strrchr(proc_name, '/');
        basename = basename ? basename + 1 : proc_name;
        if (strcmp(basename, "clamd") == 0 || strcmp(basename, "clamonacc") == 0) {
            if (is_auth) onas_esf_auth_allow(message);
            return;
        }
    }

    /* Fast-path: skip files under OnAccessExcludePath.
     * Include-path filtering is already handled at the kernel level via
     * inverted target path muting set up in onas_setup_esf(). */
    const char *file_path = NULL;
    if (message->event.open.file) {
        file_path = message->event.open.file->path.data;
    }
    if (!file_path || onas_esf_is_excluded_path(file_path)) {
        if (is_auth) onas_esf_auth_allow(message);
        return;
    }

    /* Skip if we already queued a scan for this exact path recently */
    if (onas_esf_dedup_check(file_path)) {
        if (is_auth) onas_esf_auth_allow(message);
        return;
    }

    /* Fast-path: check scan result cache by stat metadata */
    {
        STATBUF sb;
        if (CLAMSTAT(file_path, &sb) == 0) {
            onas_cache_result_t cres = onas_cache_lookup(sb.st_dev, sb.st_ino, sb.st_mtime, sb.st_size);
            if (cres == ONAS_CACHE_HIT_CLEAN) {
                if (is_auth) onas_esf_auth_allow(message);
                return;
            }
            if (cres == ONAS_CACHE_HIT_INFECTED) {
                if (is_auth) {
                    es_respond_auth_result(g_client, message, ES_AUTH_RESULT_DENY, false);
                } else {
                    logg(LOGG_WARNING, "ClamESF: cached INFECTED: %s\n", file_path);
                }
                return;
            }
        }
    }

    /* Load shedding: if too many scans pending, auto-ALLOW to prevent SIGKILL */
    if (is_auth && atomic_load(&g_pending_scans) > ESF_QUEUE_DEPTH_LIMIT) {
        logg(LOGG_WARNING, "ClamESF: load shedding — auto-ALLOW for %s (queue depth > %d)\n",
             file_path, ESF_QUEUE_DEPTH_LIMIT);
        onas_esf_auth_allow(message);
        return;
    }

    event_data = calloc(1, sizeof(struct onas_scan_event));
    if (NULL == event_data) {
        logg(LOGG_ERROR, "ClamESF: could not allocate memory for event data struct\n");
        if (is_auth) onas_esf_auth_allow(message);
        return;
    }

    /* Map context info to event data */
    if (CL_SUCCESS != onas_map_context_info_to_event_data(g_esf_ctx, &event_data)) {
        logg(LOGG_ERROR, "ClamESF: failed to map context info\n");
        free(event_data);
        if (is_auth) onas_esf_auth_allow(message);
        return;
    }

    event_data->bool_opts |= ONAS_SCTH_B_ESF;
    event_data->bool_opts |= ONAS_SCTH_B_SCAN;
    event_data->bool_opts |= ONAS_SCTH_B_FILE;

    if (is_auth) {
        /* AUTH mode: retain the ESF message so the scan worker can respond
         * with ALLOW or DENY after scanning completes.  The worker thread
         * calls es_respond_auth_result() and es_release_message(). */
        es_retain_message(message);
        event_data->es_msg = (void *)message;
        clock_gettime(CLOCK_MONOTONIC, &event_data->enqueue_time);
        atomic_fetch_add(&g_pending_scans, 1);
    } else {
        event_data->es_msg = NULL;
        memset(&event_data->enqueue_time, 0, sizeof(event_data->enqueue_time));
    }

    // Copy the path for logging/logic convenience
    if (message->event.open.file->path.data && message->event.open.file->path.length > 0) {
        event_data->pathname = strdup(message->event.open.file->path.data);
    } else {
         event_data->pathname = strdup("unknown definition");
    }

    if (!event_data->pathname) {
        logg(LOGG_ERROR, "ClamESF: OOM duplicating path\n");
        if (is_auth) {
            onas_esf_auth_allow(message);
            es_release_message(message);
        }
        free(event_data);
        return;
    }

    /* Queue the event for async scanning */
    if (CL_SUCCESS != onas_queue_event(event_data)) {
        logg(LOGG_ERROR, "ClamESF: failed to queue event\n");
        if (is_auth) {
            onas_esf_auth_allow(message);
            es_release_message(message);
        }
        free(event_data->pathname);
        free(event_data);
        return;
    }

    logg(LOGG_DEBUG, "ClamESF: Queued %s scan for: %s\n",
         is_auth ? "AUTH" : "NOTIFY", file_path);
}

cl_error_t onas_setup_esf(struct onas_context **ctx)
{
    es_new_client_result_t result;

    if (!ctx || !*ctx) {
        logg(LOGG_ERROR, "ClamESF: unable to start clamonacc. (bad context)\n");
        return CL_EARG;
    }

    g_esf_ctx = *ctx;

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

    // Mute ClamAV's own process to avoid scanning files we open.
    // This must happen BEFORE subscribing to avoid a startup event storm.
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    audit_token_t token;
    kern_return_t kr = task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &count);
    if (kr == KERN_SUCCESS) {
        if (es_mute_process(g_client, &token) != ES_RETURN_SUCCESS) {
             logg(LOGG_WARNING, "ClamESF: Failed to mute own process. Recursive scanning loops possible!\n");
        }
    } else {
        logg(LOGG_WARNING, "ClamESF: Failed to get own audit token. Cannot mute self.\n");
    }

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
        logg(LOGG_INFO, "ClamESF: AUTH mode (prevention) — malicious file opens will be BLOCKED.\n");
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
