/*
 *  Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "hash_cache.h"

#define CACHE_SLOTS   65536
#define CACHE_SHARDS  16
#define CACHE_TTL_SEC 300 /* 5 minutes */

struct cache_entry {
    dev_t   dev;
    ino_t   ino;
    time_t  mtime;
    off_t   size;
    uint8_t verdict;  /* onas_verdict_t */
    time_t  insert_time;
    uint8_t occupied;
};

static struct cache_entry  g_cache[CACHE_SLOTS];
static pthread_mutex_t     g_shard_locks[CACHE_SHARDS];

static unsigned int cache_hash(dev_t dev, ino_t ino, time_t mtime, off_t size)
{
    /* FNV-1a style mixing of the key fields */
    uint64_t h = 14695981039346656037ULL;
    h ^= (uint64_t)dev;   h *= 1099511628211ULL;
    h ^= (uint64_t)ino;   h *= 1099511628211ULL;
    h ^= (uint64_t)mtime; h *= 1099511628211ULL;
    h ^= (uint64_t)size;  h *= 1099511628211ULL;
    return (unsigned int)(h % CACHE_SLOTS);
}

static inline unsigned int shard_for_slot(unsigned int slot)
{
    return slot / (CACHE_SLOTS / CACHE_SHARDS);
}

void onas_cache_init(void)
{
    int i;
    memset(g_cache, 0, sizeof(g_cache));
    for (i = 0; i < CACHE_SHARDS; i++) {
        pthread_mutex_init(&g_shard_locks[i], NULL);
    }
}

void onas_cache_destroy(void)
{
    int i;
    for (i = 0; i < CACHE_SHARDS; i++) {
        pthread_mutex_destroy(&g_shard_locks[i]);
    }
}

onas_cache_result_t onas_cache_lookup(dev_t dev, ino_t ino, time_t mtime, off_t size)
{
    unsigned int slot  = cache_hash(dev, ino, mtime, size);
    unsigned int shard = shard_for_slot(slot);
    onas_cache_result_t result = ONAS_CACHE_MISS;

    pthread_mutex_lock(&g_shard_locks[shard]);

    struct cache_entry *e = &g_cache[slot];
    if (e->occupied &&
        e->dev == dev && e->ino == ino &&
        e->mtime == mtime && e->size == size) {

        time_t now = time(NULL);
        if ((now - e->insert_time) < CACHE_TTL_SEC) {
            result = (e->verdict == ONAS_VERDICT_INFECTED)
                         ? ONAS_CACHE_HIT_INFECTED
                         : ONAS_CACHE_HIT_CLEAN;
        } else {
            e->occupied = 0; /* expired */
        }
    }

    pthread_mutex_unlock(&g_shard_locks[shard]);
    return result;
}

void onas_cache_insert(dev_t dev, ino_t ino, time_t mtime, off_t size, onas_verdict_t verdict)
{
    unsigned int slot  = cache_hash(dev, ino, mtime, size);
    unsigned int shard = shard_for_slot(slot);

    pthread_mutex_lock(&g_shard_locks[shard]);

    struct cache_entry *e = &g_cache[slot];
    e->dev         = dev;
    e->ino         = ino;
    e->mtime       = mtime;
    e->size        = size;
    e->verdict     = (uint8_t)verdict;
    e->insert_time = time(NULL);
    e->occupied    = 1;

    pthread_mutex_unlock(&g_shard_locks[shard]);
}

void onas_cache_flush(void)
{
    int i;
    for (i = 0; i < CACHE_SHARDS; i++) {
        pthread_mutex_lock(&g_shard_locks[i]);
    }

    memset(g_cache, 0, sizeof(g_cache));

    for (i = CACHE_SHARDS - 1; i >= 0; i--) {
        pthread_mutex_unlock(&g_shard_locks[i]);
    }
}
