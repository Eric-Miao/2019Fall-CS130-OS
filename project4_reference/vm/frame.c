#include "devices/timer.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "filesys/file.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

/* The frame table. */
struct frame_table_entry* frame_table;
int frame_cnt;

/* Global lock for frame table. 
   Protect clock hand. */
struct lock frame_table_lock;

/* Hand for clock algorithm .*/
int hand; 

/* Init frame table .*/
void
frame_table_init (void)
{
  frame_table = malloc (sizeof (struct frame_table_entry) * init_ram_pages);
  if (frame_table == NULL)
    PANIC ("Can't init frame table");

  frame_cnt = 0;
  uint8_t* k_addr;
  struct frame_table_entry *fte;
  while ((k_addr = palloc_get_page (PAL_USER)))
  {
    fte = &frame_table[frame_cnt++];
    lock_init (&fte->l);
    fte->k_addr = k_addr;
    fte->spe = NULL;
  }
	lock_init (&frame_table_lock);
  hand = -1;
}

/* Try to allocate a frame for page. */
/* Immediately lock it after allocation. */
/* If no frame avaliable, try to evict one .*/
/* Return NULL on failure. */
struct frame_table_entry *
frame_alloc_and_lock (struct spt_entry *spe)
{
	/* At most try 3 times .*/
  int try_num;
  for (try_num = 0 ; try_num < 3 ; try_num++)
  {
    /* First try to get free frame. */
    int i;
    struct frame_table_entry *fte;
    /* First try to get free frame. */
    for (i = 0; i < frame_cnt; i++)
    {
      fte = &frame_table[i];
      if (!lock_try_acquire (&fte->l))
        continue;
      if (fte->spe == NULL) 
        {
          fte->spe = spe;
          return fte;
        } 
      lock_release (&fte->l);
    }

    /* If we don't have free frame, try to evict. */
    struct spt_entry *spe_tmp = NULL;

    /* Acquire global lock first tp protect clock hand. */ 
    lock_acquire (&frame_table_lock);

    /* Each time we scan frame table table twice. */
    for (i = 0 ; i < 2 * frame_cnt ; i++) 
    {
      if(++hand == frame_cnt)
        hand = 0;

      /* Get a frame from the frame table. */
      fte = &frame_table[hand];

      /* Must lock the frame first to prevent race. */
      /* If failed, other page is modifying it, we 
        continue to find next frame. */
      if (!lock_try_acquire (&fte->l))
        continue;
      
      /* This frame may have been freed, double check. */ 
      if (fte->spe == NULL) 
      {
        fte->spe = spe;
        lock_release (&frame_table_lock);
        return fte;
      } 
        
      spe_tmp = fte->spe;

      /* Check accessed bit. */
      if (pagedir_is_accessed (spe_tmp->t->pagedir, spe_tmp->u_addr))
      {
        /* If it has been accessed recently, clear the access bit. */
        pagedir_set_accessed (spe_tmp->t->pagedir, spe_tmp->u_addr, false);
        lock_release (&fte->l);
        continue;
      }
            
      /* Try to evict this frame. */

      /* No longer need the global lock .*/
      lock_release (&frame_table_lock);
      
      bool success; 
      block_sector_t sector_id = (block_sector_t) -1;

      /* Must first set the page to be not present in page table
        before checking the dirty bit.
        This will prevent a race that another process is dirtying the
        process. After setting not present, other processes wanting
        to dirty this page will fault and load again. When they try to 
        load again, since they can't get the frame lock, they must wait 
        for this process to end evicting, thus preventing the race. */
      pagedir_clear_page (spe_tmp->t->pagedir, spe_tmp->u_addr);

      /* Write frame back to file/swap if necessary. */
      if (spe_tmp->file != NULL) 
      {
        /* Check dirty bit. */
        if (pagedir_is_dirty (spe_tmp->t->pagedir, spe_tmp->u_addr)) 
        {
          if (spe_tmp->type == VM_EXECUTABLE_TYPE)
          {
            /* Modified excutable file page will be written to swap. */
            success = (sector_id = swap_alloc (fte->k_addr)) != (block_sector_t) -1;
          }
          else
          {
            /* Modified mmap file page will be written to file. */
            success = file_write_at (spe_tmp->file, fte->k_addr, spe_tmp->file_bytes,
              spe_tmp->ofs) == (int) spe_tmp->file_bytes;
          }
        }
        else
        {
          /* Clean page, return directly. */
          success = true;
        }
      }
      else
      {
        /* Stack page, write it to swap. */
        success = (sector_id = swap_alloc (fte->k_addr)) != (block_sector_t) -1;
      }

      if (success) 
      {
        /* Evict successful. */
        spe_tmp->fte = NULL;
        spe_tmp->sector_id = sector_id;
        fte->spe = spe;
        return fte;
      }
      else
      {
        /* Can't evict this frame, try another one. */
        lock_release (&fte->l);
        lock_acquire (&frame_table_lock);
      }
    }
    lock_release (&frame_table_lock);
    timer_msleep (100);
  }
	return NULL;
}

/* Free a frame. */
/* Must hold this frame's lock before calling this function. */
void 
frame_release_and_free (struct frame_table_entry *fte)
{	
  ASSERT (lock_held_by_current_thread (&fte->l));
  
  fte->spe = NULL;
  lock_release (&fte->l);
  return;
}
