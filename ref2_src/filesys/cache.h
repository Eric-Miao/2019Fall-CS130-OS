#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "off_t.h"

void cache_init(void);
void cache_flush_all(void);
void cache_read(block_sector_t sector, void *buffer);
void cache_read_at(block_sector_t sector, void *buffer, off_t size, off_t offset);
void cache_write(block_sector_t sector, const void *buffer);
void cache_write_at(block_sector_t sector, const void *buffer, off_t size, off_t offset);
void cache_read_ahead_put(block_sector_t sector);

#endif /* filesys/cache.h */

