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
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <EndpointSecurity/EndpointSecurity.h>

// libclamav
#include "clamav.h"

// common
#include "output.h"

#include <mach/mach.h>
#include <mach/message.h>
#include <mach/task_info.h>
#include <mach/kern_return.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>

// clamonacc
#include "clamonacc.h"
#include "esf_interface.h"

// Queue headers
#include "scan/onas_queue.h"
#include "scan/thread.h"
#include "misc/utils.h"

static struct onas_context *g_esf_ctx = NULL;
es_client_t *g_client = NULL;
static dispatch_queue_t g_esf_workq = NULL;

struct esf_open_work_item {
    char *pathname;
};

static void onas_esf_work_item_free(struct esf_open_work_item *wi)
{
    if (!wi) {
        return;
    }
    free(wi->pathname);
    free(wi);
}

static void onas_esf_handler(es_client_t *client, const es_message_t *message)
{
    struct esf_open_work_item *wi = NULL;

    // Check if this is an AUTH event that requires a response
    // AUTH events have action_type == ES_ACTION_TYPE_AUTH
    if (message->action_type == ES_ACTION_TYPE_AUTH) {
        // This is an AUTH event - we must respond
        if (message->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
            /*
             * CRITICAL: AUTH events have a strict deadline. We must respond immediately
             * to avoid ESF killing our client.
             *
             * We currently run scans asynchronously, so we ALLOW the open and then enqueue
             * the file path for scanning. If malware is detected, we can alert/quarantine
             * but cannot retroactively block this open.
             */
            // AUTH_OPEN must use es_respond_flags_result (see ESTypes.h).
            // Use UINT32_MAX to allow regardless of requested flags.
            (void)es_respond_flags_result(client, message, UINT32_MAX, true);
        } else {
            // Other AUTH event types - respond immediately with ALLOW
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, true);
            return;
        }
    } else {
        // NOTIFY events don't require responses - just ignore (and do not log here; logging can block).
        return;
    }
    
    // Only AUTH_OPEN events reach here

    /*
     * IMPORTANT: Keep this callback as close to constant-time as possible.
     * Even if we respond immediately for the current message, doing extra work here can
     * backlog subsequent AUTH messages in this callback queue and cause deadline misses.
     *
     * So we only copy the path and dispatch the rest of the work asynchronously.
     */
    if (!g_esf_workq) {
        // Should not happen, but fail open by doing nothing else.
        return;
    }

    wi = calloc(1, sizeof(*wi));
    if (!wi) {
        return;
    }

    if (message->event.open.file->path.data && message->event.open.file->path.length > 0) {
        // es_string_token_t is not guaranteed to be NUL-terminated.
        wi->pathname = strndup(message->event.open.file->path.data, message->event.open.file->path.length);
    } else {
        wi->pathname = strdup("unknown definition");
    }

    if (!wi->pathname) {
        onas_esf_work_item_free(wi);
        return;
    }

    dispatch_async(g_esf_workq, ^{
        struct onas_scan_event *event_data = NULL;

        event_data = calloc(1, sizeof(struct onas_scan_event));
        if (NULL == event_data) {
            onas_esf_work_item_free(wi);
            return;
        }

        /* Map context info to event data */
        if (CL_SUCCESS != onas_map_context_info_to_event_data(g_esf_ctx, &event_data)) {
            free(event_data);
            onas_esf_work_item_free(wi);
            return;
        }

        event_data->bool_opts |= ONAS_SCTH_B_ESF;
        event_data->es_msg = NULL;
        event_data->pathname = wi->pathname;
        wi->pathname = NULL;

        /* Queue the event for async scanning */
        if (CL_SUCCESS != onas_queue_event(event_data)) {
            free(event_data->pathname);
            free(event_data);
            onas_esf_work_item_free(wi);
            return;
        }

        onas_esf_work_item_free(wi);
    });

    /* 
     * TODO: Check for exclusions here (e.g. don't scan our own files).
     * For now, we rely on ESF mute_process which should be done in setup.
     */
}

cl_error_t onas_setup_esf(struct onas_context **ctx)
{
    es_new_client_result_t result;

    if (!ctx || !*ctx) {
        logg(LOGG_ERROR, "ClamESF: unable to start clamonacc. (bad context)\n");
        return CL_EARG;
    }

    g_esf_ctx = *ctx;
    if (!g_esf_workq) {
        g_esf_workq = dispatch_queue_create("org.clamav.clamonacc.esf.work", DISPATCH_QUEUE_SERIAL);
    }
    if (!g_esf_workq) {
        logg(LOGG_ERROR, "ClamESF: Failed to create work queue.\n");
        return CL_EARG;
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

    // Subscribe to AUTH events for file open
    es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_OPEN };
    if (es_subscribe(g_client, events, 1) != ES_RETURN_SUCCESS) {
        logg(LOGG_ERROR, "ClamESF: Failed to subscribe to AUTH_OPEN events.\n");
        es_delete_client(g_client);
        g_client = NULL;
        return CL_EARG;
    }
    
    // Mute ClamAV's own process to avoid scanning files we open
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

    logg(LOGG_INFO, "ClamESF: Client created and subscribed successfully.\n");
    
    return CL_SUCCESS;
}

int onas_esf_eloop(struct onas_context **ctx)
{
    (void)ctx;
    logg(LOGG_INFO, "ClamESF: Starting ESF generic loop...\n");
    
    /* 
     * ESF callbacks run on a dispatch queue managed by the framework.
     * Use dispatch_main() to service libdispatch queues reliably.
     */
    logg(LOGG_INFO, "ClamESF: Running dispatch_main() to service ESF callbacks...\n");
    dispatch_main();
    
    /* Cleanup (unreachable unless run loop stops) */
    if (g_client) {
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
    }
    
    return 0;
}

#endif /* __APPLE__ */
