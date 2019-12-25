#ifndef FILESYS_CAHCE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "devices/timer.h"
#include "filesys/filesys.h"

struct cache_line
{
    uint8_t data[BLOCK_SECTOR_SIZE]; /*data in this cache line*/
    block_sector_t sector;           /*the sector that cache line has*/
    int waiters;                     /*number of users that is waiting for reading/writing from/to this cache line*/
    int indicator;                   /*indicator that shows whether cache line is exclusive or not*/
    struct lock cache_line_lock;     /*lock to protect data in cache line*/
    struct lock bool_lock;           /*lock to protect all bool indicator variables*/
    struct condition waiting_queue;  /*readers/writers wating in this condition variable to avoid racing*/
    bool accessed;                   /*whether the cache line is accessed (for eviction)*/
    bool dirty;                      /*whether the cache line is modified*/
    bool used;                       /*whether the cache line is used*/
};

/*readhead element*/
struct ahead
{
    block_sector_t sector; /*read head sector*/
    struct list_elem elem; /*store it in the list*/
};

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