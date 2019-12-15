#ifndef FILESYS_CAHCE_H
#define FILESYS_CACHE_H

#include "devices/block.h"

void cache_init (void);
struct cache_entry* cache_alloc_and_lock (block_sector_t sector, bool exclusive);
void cache_unlock (struct cache_entry *ce, bool exclusive);
void* cache_get_data (struct cache_entry* ce, bool zero);
void cache_dealloc (block_sector_t sector);
void cache_mark_dirty (struct cache_entry *ce);
void cache_flush (void);
void cache_readahead_add (block_sector_t sector);
#endif