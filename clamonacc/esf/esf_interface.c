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
#include <EndpointSecurity/EndpointSecurity.h>

// libclamav
#include "clamav.h"

// common
#include "output.h"

// Queue headers
#include "scan/onas_queue.h"
#include "scan/thread.h"
#include "misc/utils.h"

static struct onas_context *g_esf_ctx = NULL;
es_client_t *g_client = NULL;

static void onas_esf_handler(es_client_t *client, const es_message_t *message)
{
    struct onas_scan_event *event_data = NULL;
    
    // We only care about AUTH_OPEN events for now
    if (message->event_type != ES_EVENT_TYPE_AUTH_OPEN) {
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    /* 
     * TODO: Check for exclusions here (e.g. don't scan our own files).
     * For now, we rely on ESF mute_process which should be done in setup.
     */

    event_data = calloc(1, sizeof(struct onas_scan_event));
    if (NULL == event_data) {
        logg(LOGG_ERROR, "ClamESF: could not allocate memory for event data struct\n");
        // Fail open if we can't allocate
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    /* Map context info to event data */
    if (CL_SUCCESS != onas_map_context_info_to_event_data(g_esf_ctx, &event_data)) {
        logg(LOGG_ERROR, "ClamESF: failed to map context info\n");
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        free(event_data);
        return;
    }

    event_data->bool_opts |= ONAS_SCTH_B_ESF;
    
    // We must retain the message because we are processing it asynchronously
    es_retain_message(message);
    event_data->es_msg = (void *)message;
    
    // Copy the path for logging/logic convenience
    if (message->event.open.file->path.data && message->event.open.file->path.length > 0) {
        event_data->pathname = cli_safer_strdup(message->event.open.file->path.data);
    } else {
         event_data->pathname = cli_safer_strdup("unknown definition");
    }

    /* Queue the event */
    if (CL_SUCCESS != onas_queue_event(event_data)) {
        logg(LOGG_ERROR, "ClamESF: failed to queue event\n");
        es_release_message(message);
        free(event_data->pathname);
        free(event_data);
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        return;
    }
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

    // Subscribe to AUTH events for file open
    es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_OPEN };
    if (es_subscribe(g_client, events, 1) != ES_RETURN_SUCCESS) {
        logg(LOGG_ERROR, "ClamESF: Failed to subscribe to AUTH_OPEN events.\n");
        es_delete_client(g_client);
        g_client = NULL;
        return CL_EARG;
    }
    
    // Mute ClamAV's own process to avoid scanning files we open
    if (es_mute_process(g_client, getpid()) != ES_RETURN_SUCCESS) {
         logg(LOGG_WARNING, "ClamESF: Failed to mute own process. Recursive scanning loops possible!\n");
    }

    logg(LOGG_INFO, "ClamESF: Client created and subscribed successfully.\n");
    
    return CL_SUCCESS;
}

int onas_esf_eloop(struct onas_context **ctx)
{
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
