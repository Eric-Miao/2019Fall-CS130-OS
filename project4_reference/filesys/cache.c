#include <string.h>
#include <stdbool.h>
#include <debug.h>
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "devices/timer.h"
#include "filesys/filesys.h"
#include "filesys/cache.h"

struct cache_entry
{
	/* The number of sector cached. */
	/* (block_sector_t) -1 means this cache slot is empty. */
	block_sector_t sector; 

	/* Used for clock algorithm .*/
	bool accessed;

	/* Whether the cache slot has been modified. */
	/* Indicate write back when cache flush or cache eviction .*/
	bool dirty;

	/* Whether this cache slot has data. */
	/* Notice that the cache slot may have an valid sector number 
	but has no data in it, which means the slot hasn't read data
	from the disk .*/
	bool has_data;

	/* Number of read/write waiters for this cache slot. */
	/* Used in cache eviction. When evction, we won't evict slots
	that have read/write waiters. */ 
	int waiters;

	/* Data cached */
	/* Protected by shared_lock sl */
	uint8_t data[BLOCK_SECTOR_SIZE];

	/* Lock for preventing race. */
	/* Also used in shared lock .*/
	struct lock l;

	/* Read/write lock */
	/* See thread/synch.c for details */
	struct shared_lock sl;

	/* Data lock, only used to protect has_data. */
	struct lock has_data_lock;
};

#define CACHE_SIZE 64
struct cache_entry cache[CACHE_SIZE]; /* Cache .*/

/* Protect clock hand .*/
struct lock cache_lock;

/* Hand for clock algorithm */
int hand;

/* Data struct used in readahead */
struct readahead_s
{
	struct list_elem elem; /* Elem for list */
	block_sector_t sector; /* Sector to be read ahead */
};

/* List of sectors to be read ahead */
static struct list readahead_list;
/* Global lock that protects readahead_list */
static struct lock readahead_lock;
/* Signed when a new sector is added to the empty readahead list */
static struct condition need_readahead;

static void cache_readahead_daemon (void *aux UNUSED);
static void cache_flush_daemon (void *aux UNUSED);

/* Init cache */
void cache_init (void)
{	
	/* Init cache slots */
	struct cache_entry *ce;
	int i;
  for (i = 0; i < CACHE_SIZE; i++) 
  {
  	ce = &cache[i];
  	ce->sector = (block_sector_t) -1;
  	lock_init (&ce->l);
  	shared_lock_init (&ce->sl, &ce->l);
  	lock_init (&ce->has_data_lock);
  	ce->accessed = false;
  	ce->dirty = false;
  	ce->has_data = false;
  	ce->waiters = 0;
  }

  lock_init (&cache_lock);
  hand = -1;

  /* Create cache flush daemon. */
  thread_create ("cache_flush_daemon", PRI_MIN, cache_flush_daemon, NULL);

  /* Init read ahead daemon */
  list_init (&readahead_list);
  lock_init (&readahead_lock);
  cond_init (&need_readahead);
  thread_create ("cache_readahead_daemon", PRI_MIN, cache_readahead_daemon, NULL);
}

/* Allocate a cache slot for given "sector" and lock it. */
/* If the "sector" is in cache, lock it and return */
/* If the "sector" isn't in cache, find an empty slot and 
give it to the sector. If there's no empty slot, evict one
and try allocating again */
/* The returned cache slot must be locked. Lock means a read lock
or a write lock. If "exclusive" is false, then the caller wants a read lock.
Multiple threads can hold read lock at the same time and read the cache
slot. If "exclusive" is true, the caller wants a write lock. Only one
thread can hold write lock at the same time, preventing race from other
readers/writers. */
struct cache_entry* 
cache_alloc_and_lock (block_sector_t sector, bool exclusive)
{	
	struct cache_entry *ce;
	int i;

begin:
	/* Acquire global lock first .*/
	lock_acquire (&cache_lock);
	/* Sector may have been cached, check it .*/ 
	for (i = 0 ; i < CACHE_SIZE ; i++)
	{	
		ce = &cache[i];
		lock_acquire (&ce->l);
		if (ce->sector != sector)
		{	
			lock_release (&ce->l);
			continue;
		}

		/* No longer need the global lock 
		for we hold lock l. */
		lock_release (&cache_lock);

		/* Acquire read/write lock. */
		ce->waiters++;
		shared_lock_acquire (&ce->sl, exclusive);
		ce->waiters--;

		ASSERT (ce->sector == sector);

		lock_release (&ce->l);
		return ce;
	}

	/* Try to find an empty slot. */
	for (i = 0 ; i < CACHE_SIZE ; i++)
	{	
		ce = &cache[i];
		lock_acquire (&ce->l);
		if (ce->sector != (block_sector_t) -1)
		{	
			lock_release (&ce->l);
			continue;
		}

		/* No longer need the global lock 
		for we hold lock l. */
		lock_release (&cache_lock);

		ce->sector = sector;
		ce->accessed = false;
  	ce->dirty = false;
  	ce->has_data = false;
  	ce->waiters = 0;

  	/* We can get the read/write lock immediately since
  	the slot has just been allocated and we hold lock l. */
		ASSERT (shared_lock_try_acquire (&ce->sl, exclusive));
		/* We hold lock l now, so no one can wait for this slot. */
		ASSERT (ce->waiters == 0);
		lock_release (&ce->l);
		return ce;
	}

	/* Try to evict one slot. */
	for (i = 0; i < CACHE_SIZE * 2; i++)
	{	
		if (++hand >= CACHE_SIZE)
			hand = 0;

		ce = &cache[hand];
		if(!lock_try_acquire (&ce->l))
			continue;
		/* Try to acquire an exclusive lock on this slot. */
		else if (!shared_lock_try_acquire (&ce->sl, true))
		{	
			lock_release (&ce->l);
			continue;
		}
		/* We don't evict this slot if it has waiters. */
		else if (ce->waiters != 0)
		{	
			shared_lock_release (&ce->sl, true);
			lock_release (&ce->l);
			continue;
		}
		else if (ce->accessed)
		{	
			/* Clock algorithm. */
			ce->accessed = false;
			shared_lock_release (&ce->sl, true);
			lock_release (&ce->l);
			continue;
		}

		/* No longer need the global lock 
		for we hold lock l. */
		lock_release (&cache_lock);

		/* Write back if the slot is dirty. */
		if (ce->has_data && ce->dirty) 
    {	
    	lock_release (&ce->l);
    	block_write (fs_device, ce->sector, ce->data);
    	ce->dirty = false;
    	lock_acquire (&ce->l);
    }

    /* During writing back, someone may start waiting 
    for this slot since we released the lock l. If so, 
    give the slot to the waiter. */
    if (ce->waiters == 0)
    {	
    	/* If no waiters, evict the slot. */
    	ce->sector = (block_sector_t) -1;
    }

    shared_lock_release (&ce->sl, true);
    lock_release (&ce->l);

    /* Try again. */
    goto begin;
  }

  /* Wait for a while and then try again. */
  lock_release (&cache_lock);
  timer_msleep (100);
  goto begin;
}

/* Release the read/write lock of the cache slot. */ 
void 
cache_unlock (struct cache_entry* ce, bool exclusive)
{	
	lock_acquire (&ce->l);
	shared_lock_release (&ce->sl, exclusive);
	lock_release (&ce->l);
}

/* Return the data pointer of the cache slot. */
/* If "zero" is true, zero out the cache slot and return the pointer. */
/* If "zero" is false, first check whether the slot has data. If it doesn't
have data, read data from the disk. If it already has data, directly return
the pointer. */ 
/* The caller must have an read/write lock on the slot. */
void* 
cache_get_data (struct cache_entry* ce, bool zero)
{	
	if (zero)
	{	
		/* The caller should hold write lock. */
		memset (ce->data, 0, BLOCK_SECTOR_SIZE);
		ce->dirty = true;
		ce->has_data = true;
	}
	else
  {	
  	/* The caller should hold read lock. */

  	/* Need to acquire has_data_lock first, because
  	a read lock can't protect "has_data" and "dirty". */
  	lock_acquire (&ce->has_data_lock);
  	if (!ce->has_data)
  	{ 
  		block_read (fs_device, ce->sector, ce->data);
  		ce->dirty = false;
  		ce->has_data = true;
  	} 
  	lock_release (&ce->has_data_lock);
  }

  ce->accessed = true;
  return ce->data;
}

/* Find the cache slot of the given "sector" and
evict it immediately. No need to write back even if
the slot is dirty. This is because "free_map_release" 
will be called after this function, and thus the sector
in disk will be deallocated. */
void
cache_dealloc (block_sector_t sector) 
{
  int i;
  struct cache_entry *ce;
  
  lock_acquire (&cache_lock);
  for (i = 0; i < CACHE_SIZE; i++)
  {
  	ce = &cache[i];
  	lock_acquire (&ce->l);
  	if (ce->sector == sector) 
  	{
  		lock_release (&cache_lock);
			
			/* No one should have hold read/write lock
			on this slot, or wait for it. */
			ASSERT (shared_lock_try_acquire (&ce->sl, true))
			ASSERT (ce->waiters == 0)
			ce->sector = (block_sector_t) -1;
			shared_lock_release (&ce->sl, true);
			
			lock_release (&ce->l);
			return;
    }
    lock_release (&ce->l);
  }
  lock_release (&cache_lock);
}

/* Set the cache slot to be dirty */
void 
cache_mark_dirty (struct cache_entry *ce)
{	
	ASSERT (ce->has_data);
	ce->dirty = true;
}

/* Flush dirty cache slot to disk */
void
cache_flush (void) 
{
  struct cache_entry *ce;
  block_sector_t sector;
  int i;
  
  for (i = 0; i < CACHE_SIZE; i++)
  {
  	ce = &cache[i];
  	lock_acquire (&ce->l);
    sector = ce->sector;

    if (sector == (block_sector_t) -1)
    {
    	lock_release (&ce->l);
    	continue;
    }

   	lock_release (&ce->l);
    ce = cache_alloc_and_lock (sector, true);
    if (ce->has_data && ce->dirty) 
    {	
    	/* Need to write back if dirty. */
    	block_write (fs_device, ce->sector, ce->data);
    	ce->dirty = false; 
    }
    cache_unlock (ce, true);
  }
}

/* Add sector to the read ahead list */
void
cache_readahead_add (block_sector_t sector) 
{
  struct readahead_s *ras = malloc (sizeof *ras);
  if (ras == NULL)
    return;
 	ras->sector = sector;

  lock_acquire (&readahead_lock); 
  list_push_back (&readahead_list, &ras->elem);
  cond_signal (&need_readahead, &readahead_lock);
  lock_release (&readahead_lock);
}

static void 
cache_flush_daemon (void *aux UNUSED)
{	
	while (true)
	{	
		timer_msleep (20 * 1000);
		cache_flush ();
	}
}

static void
cache_readahead_daemon (void *aux UNUSED) 
{
  while (true) 
  {	
    lock_acquire (&readahead_lock);
    /* Wait for non-empty. */
    while (list_empty (&readahead_list)) 
    	cond_wait (&need_readahead, &readahead_lock);
    ASSERT (!list_empty (&readahead_list));

    /* Do read ahead. */
    struct readahead_s *ras = list_entry (list_pop_front (&readahead_list),
                             struct readahead_s, elem);
    lock_release (&readahead_lock);

    struct cache_entry *ce = cache_alloc_and_lock (ras->sector, false);
    cache_get_data (ce, false);
    cache_unlock (ce, false);
    free (ras);
  }
}