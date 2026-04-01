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

#ifndef __ONAS_ESF_H
#define __ONAS_ESF_H

#include "clamonacc.h"

// Check for ESF availability (macOS 10.15+)
#if defined(__APPLE__)
#include <EndpointSecurity/EndpointSecurity.h>

extern es_client_t *g_client;

/* Forward declaration in case we need it elsewhere */
struct onas_context;

/* 
 * Setup ESF client.
 * Returns CL_SUCCESS on success, error code otherwise.
 */
cl_error_t onas_setup_esf(struct onas_context **ctx);

/*
 * Start the ESF event loop.
 * In current architecture, this might just block or dispatch.
 */
int onas_esf_eloop(struct onas_context **ctx);

/*
 * Tear down the ESF client.
 * Must be called FIRST in shutdown — before canceling threads — so that
 * pending AUTH events are drained and the ESF deadline SIGKILL is avoided.
 */
void onas_teardown_esf(void);

#endif /* __APPLE__ */

#endif /* __ONAS_ESF_H */
