#ifndef FILESYS_CAHCE_H
#define FILESYS_CACHE_H

#include "devices/block.h"

void cache_init(void);
struct cache_line *cache_allocate(block_sector_t sector, bool exclusive);
void cache_wake(struct cache_line *line, bool exclusive);
void cache_set_dirty(struct cache_line *line);
void *cache_get_data(struct cache_line *line);
void *cache_get_zero(struct cache_line *line);
void cache_free(block_sector_t sector);
void cache_clear(void);
void add_to_prepare(block_sector_t sector);
#endif