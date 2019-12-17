#include <string.h>
#include <stdbool.h>
#include <debug.h>
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "devices/timer.h"
#include "filesys/filesys.h"
#include "filesys/cache.h"
#define MAX_CACHE 64

struct cache_line
{
    uint8_t data[BLOCK_SECTOR_SIZE]; /*data in this cache line*/
    block_sector_t sector;           /*the sector that cache line has*/
    int waiters;                     /*number of users that is waiting for reading/writing from/to this cache line*/
    int indicator;                   /*indicator that shows whether cache line is exclusive or not*/
    struct lock cache_line_lock;     /*lock to protect data in cache line*/
    struct lock bool_lock;           /*lock to protect all indicator variables*/
    struct condition waiting_queue;  /*readers/writers wating in this condition variable to avoid racing*/
    bool accessed;                   /*whether the cache line is accessed (for eviction)*/
    bool dirty;                      /*whether the cache line is modified*/
    bool used;                       /*whether the cache line is used*/
};

/*create the cache*/
struct cache_line cache[MAX_CACHE];

/*lock on cache prevents from racing when going through*/
struct lock cache_lock;

/*init the cache*/
void cache_init()
{
    /*init each cache line*/
    struct cache_line *line;
    int i = 0;
    for (; i < MAX_CACHE; i++)
    {
        line = &cache[i];
        line->sector = (block_sector_t)-1;
        line->waiters = 0;
        line->indicator = 0;
        lock_init(&line->cache_line_lock);
        lock_init(&line->bool_lock);
        cond_init(&line->waiting_queue, &line->cache_line_lock);
        line->accessed = false;
        line->dirty = false;
        line->used = false;
    }
    /*init cache lock*/
    lock_init(&cache_lock);
    /* Create cache flush daemon. */
    /*thread_create("cache_flush_daemon", PRI_DEFAULT, cache_flush_daemon, NULL);*/

    /* Init read ahead daemon */
    /*list_init(&readahead_list);
    lock_init(&readahead_lock);
    cond_init(&need_readahead);
    thread_create("cache_readahead_daemon", PRI_DEFAULT, cache_readahead_daemon, NULL);*/
}

/* Allocate a cache line with given sector area*/
struct cache_line *cache_allocate(block_sector_t sector, bool exclusive)
{
    struct cache_line *line;
    int i = 0;
    lock_acquire(&cache_lock);
    /*check if the sector is assigned to a cache line*/
    for (; i < MAX_CACHE; i++)
    {
        line = &cache[i];
        lock_acquire(&line->cache_line_lock);
        if (line->sector != sector)
        {
            lock_release(&line->cache_line_lock);
            continue;
        }
        /*release the cache lock if we find a cache line with given sector assgned*/
        lock_release(&cache_lock);
        /*put exclusive readers/writers into waiting queue*/
        line->waiters++;
        ASSERT(lock_held_by_current_thread(line->cache_line_lock));
        /*make it exclusive or not*/
        if (exclusive)
        {
            while (line->indicator != 0)
            {
                cond_wait(&line->wating_queue, line->cache_line_lock);
            }
            line->indicator = -1;
        }
        else
        {
            while (line->indicator < 0)
            {
                cond_wait(&line->wating_queue, line->cache_line_lock);
            }
            line->indicator++;
        }
        /*decrease waiters indicator after waiting*/
        line->waiters--;
        ASSERT(line->sector == sector);
        lock_release(&line->cache_line_lock);
        return line;
    }

    /*find an empty cache line and assign it to sector*/
    for (i = 0; i < MAX_CACHE; i++)
    {
        line = &cache[i];
        lock_acquire(&line->cache_line_lock);
        /*skip the cache lines have been assigned*/
        if (line->sector != (block_sector_t)-1)
        {
            lock_release(&line->cache_line_lock);
            continue;
        }
        lock_release(&cache_lock);
        /*assign the sector to it and reinitialize its status*/
        line->sector = sector;
        line->waiters = 0;
        line->accessed = false;
        line->dirty = false;
        line->used = false;
        /*set its indicator according to the exclusive given*/
        ASSERT(lock_held_by_current_thread(&line->cache_line_lock));
        if (exclusive)
        {
            ASSERT(line->indicator);
            line->indicator = -1;
        }
        else
        {
            ASSERT(line->indicator >= 0);
            line->indicator++;
        }
        /*get the cache line and return*/
        ASSERT(line->waiters == 0);
        lock_release(&line->cache_line_lock);
        return line;
    }
    int index = 0;
    /*Use clock algorithm to evict*/
    for (i = 0; i < MAX_CACHE * 2; i++)
    {
        if (index >= MAX_CACHE)
        {
            index = 0;
        }

        line = &cache[index];
        /*skip the locked cache line*/
        if (!lock_try_acquire(&line->cache_line_lock))
        {
            continue;
        }
        /*skip the non-exclusive cache line*/
        else if (line->indicator)
        {
            lock_release(&line->cache_line_lock);
            continue;
        }
        /*take the exclusive cache out of the waiting queue*/
        else if (!line->indicator)
        {
            line->indicator = -1;
        }
        /*skip the cache line being waited and wake up its waiters*/
        else if (line->waiters != 0)
        {
            ASSERT(lock_held_by_current_thread(&line->cache_line_lock));
            /*set cache line exclusive*/
            line->indicator = 0;
            /*wake up all waiting reader and writer*/
            cond_broadcast(&line->waiting_queue, &line->cache_line_lock);
            lock_release(&line->cache_line_lock);
            continue;
        }
        else if (line->accessed)
        {
            /*second chance*/
            line->accessed = false;
            ASSERT(lock_held_by_current_thread(&line->cache_line_lock));
            /*set cache line exclusive*/
            line->indicator = 0;
            /*wake up all waiting reader and writer*/
            cond_broadcast(&line->waiting_queue, &line->cache_line_lock);
            lock_release(&line->cache_line_lock);
            continue;
        }

        /*release the cache lock after going through*/
        lock_release(&cache_lock);
        /*write the dirty cache line back*/
        if (line->used && line->dirty)
        {
            lock_release(&line->cache_line_lock);
            block_write(fs_device, line->sector, line->data);
            /*set cache line clear after writing and regain its lock*/
            line->dirty = false;
            lock_acquire(&line->cache_line_lock);
        }

        /*evict the cache line if there is no waiter*/
        if (line->waiters == 0)
        {
            line->sector = (block_sector_t)-1;
        }

        ASSERT(lock_held_by_current_thread(&line->cache_line_lock));
        /*set cache line exclusive*/
        line->indicator = 0;
        /*wake up all waiting reader and writer*/
        cond_broadcast(&line->waiting_queue, &line->cache_line_lock);
        lock_release(&line->cache_line_lock);
        /*regain the cache lock*/
        lock_acquire(cache_lock);
        /*try to find an empty cache line and assign it to sector after eviction*/
        for (i = 0; i < MAX_CACHE; i++)
        {
            line = &cache[i];
            lock_acquire(&line->cache_line_lock);
            /*skip the cache lines have been assigned*/
            if (line->sector != (block_sector_t)-1)
            {
                lock_release(&line->cache_line_lock);
                continue;
            }
            lock_release(&cache_lock);
            /*assign the sector to it and reinitialize its status*/
            line->sector = sector;
            line->waiters = 0;
            line->accessed = false;
            line->dirty = false;
            line->used = false;
            /*set its indicator according to the exclusive given*/
            ASSERT(lock_held_by_current_thread(&line->cache_line_lock));
            if (exclusive)
            {
                ASSERT(line->indicator);
                line->indicator = -1;
            }
            else
            {
                ASSERT(line->indicator >= 0);
                line->indicator++;
            }
            /*get the cache line and return*/
            ASSERT(line->waiters == 0);
            lock_release(&line->cache_line_lock);
            return line;
        }
        index++;
    }
    /*try to allocate again after a while to avoid the allocation failure
    caused by asynchronization buecause of different CPU performance*/
    lock_release(&cache_lock);
    timer_msleep(100);
    cache_allocate(sector, exclusive);
}

/*wake up the readers/writers in the waiting queue*/
void cache_wake(struct cache_line *line, bool exclusive)
{
    lock_acquire(&line->cache_line_lock);
    ASSERT(lock_held_by_current_thread(&line->cache_line_lock));
    /*wake up all waiters after a exclusive process is finished*/
    if (exclusive)
    {
        line->indicator = 0;
        cond_broadcast(&line->waiting_queue, &line->cache_line_lock);
    }
    else
    {
        line->indicator--;
        if (line->indicator == 0)
        {
            cond_signal(&line->waiting_queue, &line->cache_line_lock);
        }
    }
    lock_release(&line->cache_line_lock);
}

/*set the cache line to be dirty*/
void cache_set_dirty(struct cache_line *line)
{
	ASSERT(line->used);
	line->dirty = true;
}

/*fill the cache line with data from disk*/
void *cache_get_data(struct cache_line *line)
{
    /*acquire bool lock first to avoid racing*/
    lock_acquire(&line->bool_lock);
    /*if cache has no data yet then read from disk*/
    if (!line->used)
    {
        block_read(fs_device, line->sector, line->data);
        line->dirty = false;
        line->used = true;
    }
    lock_release(&line->bool_lock);
    line->accessed = true;
    return line->data;
}

/*fill the cache with zeros*/
void *cache_get_zero(struct cache_line *line)
{
    /* The caller should hold write lock. */
    memset(line->data, 0, BLOCK_SECTOR_SIZE);
    line->accessed = true;
    line->dirty = true;
    line->used = true;
    return line->data;
}

/*free the cache with given sector*/
void cache_free(block_sector_t sector)
{
    int i = 0;
    struct cache_line *line;
    lock_acquire(&cache_lock);
    for (; i < MAX_CACHE; i++)
    {
        line = &cache[i];
        lock_acquire(&line->cache_line_lock);
        if (line->sector == sector)
        {
            lock_release(&cache_lock);
            ASSERT(lock_held_by_current_thread(&line->cache_line_lock));
            /*the cache line should be exclusive when freeing*/
            ASSERT(line->indicator);
            /*put all user into waiting queue*/
            line->indicator = -1;
            ASSERT(line->waiters == 0);
            /*no need to write back since sector will be free then*/
            line->sector = (block_sector_t) -1;
            /*set cache line exclusive after freeing and clear the waiting queue*/
            line->indicator = 0;
            cond_broadcast(&line->waiting_queue,line->cache_line_lock);
            lock_release(&line->cache_line_lock);
            return;
        }
        lock_release(&line->cache_line_lock);
    }
    lock_release(&cache_lock);
}

/*clear the dirty cache line*/
void cache_clear()
{
	struct cache_line *line;
	block_sector_t sector;
	int i = 0;
	for (; i < MAX_CACHE; i++)
	{
		line = &cache[i];
		lock_acquire(&line->cache_line_lock);
		sector = line->sector;
        /*skip empty cache lines*/
		if (sector == (block_sector_t) -1)
		{
			lock_release(&line->cache_line_lock);
			continue;
		}
		lock_release(&line->cache_line_lock);
        /*we should make it exclusive*/
		line = cache_allocate(sector, true);
		if (line->used && line->dirty)
		{
			/*write back if dirty. */
			block_write(fs_device, line->sector, line->data);
			line->dirty = false;
		}
        /*wake up all waiters after clearing*/
		cache_wake(line, true);
	}
}