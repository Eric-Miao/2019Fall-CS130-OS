#include <bitmap.h>
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/swap.h"

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)
#define SWAP_FREE false
#define SWAP_USED true

struct block *swap_device;
struct bitmap *swap_table; /* swap table is a bitmap. */
struct lock swap_table_lock;

/* Init swap table. */
void
swap_table_init (void)
{ 
  swap_table = NULL;
  /* First get the swap device. */
  swap_device = block_get_role (BLOCK_SWAP);
  if (swap_device == NULL)
    return;
  else
    swap_table = bitmap_create (block_size (swap_device)); 
  
  if (swap_table == NULL)
    PANIC ("Can't Create Swap Table !");

  lock_init (&swap_table_lock);
}

/* Allocate a swap slot. */
block_sector_t
swap_alloc (uint8_t *addr)
{
  ASSERT (swap_table != NULL);
  lock_acquire (&swap_table_lock);
  size_t sector_id = bitmap_scan_and_flip (swap_table, 0, SECTORS_PER_PAGE, SWAP_FREE);
  lock_release (&swap_table_lock);
  if (sector_id == BITMAP_ERROR)
    return (block_sector_t) -1;
  int i;
  for (i = 0 ; i < SECTORS_PER_PAGE ; i++)
  {
    block_write (swap_device, (block_sector_t)(i + sector_id), 
      addr + i * BLOCK_SECTOR_SIZE);
  }

  return (block_sector_t) sector_id;
}

/* Get the page back to addr and clear the swap slot. */
void 
swap_free (uint8_t *addr, block_sector_t sector_id)
{
  ASSERT (swap_table != NULL);
  int i;
  for (i = 0 ; i < SECTORS_PER_PAGE ; i++)
  {
    block_read (swap_device, (block_sector_t)(i + sector_id), 
      addr + i * BLOCK_SECTOR_SIZE);
  }

  swap_clear (sector_id);

  return;
}

/* Delete the swap slot in swap table. */
void
swap_clear (block_sector_t sector_id)
{ 
  ASSERT (swap_table != NULL);
  lock_acquire (&swap_table_lock);
  bitmap_set_multiple (swap_table, (size_t) sector_id, SECTORS_PER_PAGE, SWAP_FREE);
  lock_release (&swap_table_lock);

  return;
}
