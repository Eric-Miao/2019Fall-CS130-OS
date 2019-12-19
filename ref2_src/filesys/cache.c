#include "filesys/cache.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "devices/block.h"
#include "devices/timer.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys.h"

#define CACHE_SIZE 64
#define CACHE_WRITE_INTV (1 * TIMER_FREQ)

static struct lock cache_lock;
static struct list ahead_queue;
static struct lock ahead_lock;
static struct condition ahead_cond;

struct ahead_entry {
    block_sector_t sector;
    struct list_elem elem;
};

struct cache_entry {
    uint8_t buffer[BLOCK_SECTOR_SIZE];
    block_sector_t sector;
    struct lock lock;
    bool valid;
    bool dirty;
    bool accessed;
};

static struct cache_entry cache[CACHE_SIZE];

static struct cache_entry *cache_find(block_sector_t sector);
static struct cache_entry *cache_evict(void);
static void cache_write_behind(void *aux UNUSED);
static void cache_read_ahead(void *aux UNUSED);

void cache_init(void) {
    size_t i;
    for (i = 0; i < CACHE_SIZE; ++i) {
        lock_init(&cache[i].lock);
        cache[i].valid = false;
    }
    lock_init(&cache_lock);
    list_init(&ahead_queue);
    lock_init(&ahead_lock);
    cond_init(&ahead_cond);
    thread_create("write_behind", PRI_DEFAULT, cache_write_behind, NULL);
    thread_create("read_ahead", PRI_DEFAULT, cache_read_ahead, NULL);
}

void cache_flush_all(void) {
    size_t i;
    for (i = 0; i < CACHE_SIZE; ++ i) {
        struct cache_entry *ce = cache + i;
        lock_acquire(&ce->lock);
        if (ce->valid && ce->dirty) {
            block_write(fs_device, ce->sector, ce->buffer);
            ce->dirty = false;
        }
        lock_release(&ce->lock);
    }
}

static struct cache_entry *cache_find(block_sector_t sector) {
    size_t i;
    for (i = 0; i < CACHE_SIZE; ++ i) {
        struct cache_entry *ce = cache + i;
        lock_acquire(&ce->lock);
        if (ce->valid && ce->sector == sector) {
            return ce;
        }
        lock_release(&ce->lock);
    }
    return NULL;
}

void cache_read(block_sector_t sector, void *buffer) {
    cache_read_at(sector, buffer, BLOCK_SECTOR_SIZE, 0);
}

void cache_read_at(block_sector_t sector, void *buffer,
        off_t size, off_t offset) {
    lock_acquire(&cache_lock);
    struct cache_entry *ce = cache_find(sector);
    if (!ce) {
        // miss!
        ce = cache_evict();
        lock_release(&cache_lock);
        ASSERT(ce);
        ce->sector = sector;
        ce->dirty = false;
        block_read(fs_device, sector, ce->buffer);
    } else {
        lock_release(&cache_lock);
    }
    if (buffer) {
        memcpy(buffer, ce->buffer + offset, (size_t) size);
    }
    ce->accessed = true;
    lock_release(&ce->lock);
}

static struct cache_entry *cache_evict(void) {
    size_t hand = 0;
    while (true) {
        struct cache_entry *ce = cache + hand;
        bool succ = lock_try_acquire(&ce->lock);
        if (!succ) {
            hand = (hand + 1) % CACHE_SIZE;
            continue;
        }
        if (!ce->valid) {
            ce->valid = true;
            return ce;
        }
        if (ce->accessed) {
            ce->accessed = false;
        }
        else {
            // evict him! lol
            if (ce->dirty) {
                block_write(fs_device, ce->sector, ce->buffer);
                ce->dirty = false;
            }
            return ce;
        }
        lock_release(&ce->lock);
        hand = (hand + 1) % CACHE_SIZE;
    }
    NOT_REACHED();
}

void cache_write(block_sector_t sector, const void *buffer) {
    cache_write_at(sector, buffer, BLOCK_SECTOR_SIZE, 0);
}

void cache_write_at(block_sector_t sector, const void *buffer,
        off_t size, off_t offset) {
    ASSERT(buffer);
    lock_acquire(&cache_lock);
    struct cache_entry *ce = cache_find(sector);
    if (!ce) {
        // miss!
        ce = cache_evict();
        lock_release(&cache_lock);
        ASSERT(ce);
        ce->sector = sector;
        ce->dirty = false;
        if (size != BLOCK_SECTOR_SIZE)
            block_read(fs_device, sector, ce->buffer);
    } else {
        lock_release(&cache_lock);
    }
    memcpy(ce->buffer + offset, buffer, (size_t) size);
    ce->accessed = true;
    ce->dirty = true;
    lock_release(&ce->lock);
}

static void cache_write_behind(void *aux UNUSED) {
    while (true) {
        timer_sleep(CACHE_WRITE_INTV);
        cache_flush_all();
    }
    NOT_REACHED();
}

static void cache_read_ahead(void *aux UNUSED) {
    while (true) {
        lock_acquire(&ahead_lock);
        while (list_empty(&ahead_queue))
            cond_wait(&ahead_cond, &ahead_lock);
        struct ahead_entry *ae = list_entry(list_pop_front(&ahead_queue),
                struct ahead_entry, elem);
        lock_release(&ahead_lock);
        block_sector_t sector = ae->sector;
        free(ae);
        cache_read(sector, NULL);
    }
    NOT_REACHED();
}

void cache_read_ahead_put(block_sector_t sector) {
    lock_acquire(&ahead_lock);
    struct ahead_entry *ae = malloc(sizeof(struct ahead_entry));
    ae->sector = sector;
    list_push_back(&ahead_queue, &ae->elem);
    cond_signal(&ahead_cond, &ahead_lock);
    lock_release(&ahead_lock);
}
