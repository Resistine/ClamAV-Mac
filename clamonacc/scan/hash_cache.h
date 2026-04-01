/*
 *  Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#ifndef __ONAS_HASH_CACHE_H
#define __ONAS_HASH_CACHE_H

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>

typedef enum {
    ONAS_CACHE_MISS     = 0,
    ONAS_CACHE_HIT_CLEAN,
    ONAS_CACHE_HIT_INFECTED
} onas_cache_result_t;

typedef enum {
    ONAS_VERDICT_CLEAN    = 0,
    ONAS_VERDICT_INFECTED = 1
} onas_verdict_t;

/**
 * Initialize the scan result cache. Call once at startup.
 */
void onas_cache_init(void);

/**
 * Destroy the cache and free all memory.
 */
void onas_cache_destroy(void);

/**
 * Look up a file by stat metadata.
 * Returns HIT_CLEAN, HIT_INFECTED, or MISS.
 */
onas_cache_result_t onas_cache_lookup(dev_t dev, ino_t ino, time_t mtime, off_t size);

/**
 * Insert or update a cache entry after scanning.
 */
void onas_cache_insert(dev_t dev, ino_t ino, time_t mtime, off_t size, onas_verdict_t verdict);

/**
 * Flush all entries (e.g. after signature DB reload).
 */
void onas_cache_flush(void);

#endif
