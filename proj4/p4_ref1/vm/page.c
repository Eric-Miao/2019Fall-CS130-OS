#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

static unsigned spt_hash_func (const struct hash_elem *e, void *aux UNUSED);
static bool spt_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static void spt_destroy_func (struct hash_elem *e, void *aux UNUSED);

static unsigned 
spt_hash_func (const struct hash_elem *e,
			       void *aux UNUSED)
{
  struct spt_entry *spe = hash_entry(e, struct spt_entry, elem);
  return hash_int((int) spe->u_addr);

}

static bool 
spt_less_func (const struct hash_elem *a,
			   const struct hash_elem *b,
			   void *aux UNUSED)
{
  struct spt_entry *spe_a = hash_entry(a, struct spt_entry, elem);
  struct spt_entry *spe_b = hash_entry(b, struct spt_entry, elem);
  return spe_a->u_addr < spe_b->u_addr;
}

/* Used for hash_destroy function. */
/* Destroy a page in supplemental page table. */ 
static void 
spt_destroy_func (struct hash_elem *e, void *aux UNUSED) 
{
  struct spt_entry *spe = hash_entry (e, struct spt_entry, elem);
  
  //printf(" hhe%x \n",(int)spe->fte);
  /* Must get lock of frame first. */
  spt_lock_frame (spe);

  /* If the frame is not NULL, free it. */
  if (spe->fte)
    frame_release_and_free (spe->fte);

  /* If frame is in swap, clear the corresponding swap slot. */
  if (spe->sector_id != (block_sector_t) -1)
    swap_clear (spe->sector_id);

  free(spe);
}

/* Init the supplemental page table .*/ 
bool
spt_init (struct hash *spt_table)
{
  return hash_init (spt_table, spt_hash_func, spt_less_func, NULL);
}

/* Destroy the supplemental page table .*/
/* Called when process exits .*/ 
void 
spt_destroy (struct hash *spt_table)
{
  hash_destroy(spt_table, spt_destroy_func);
}

/* Lock the page's frame. */
/* If the page has no frame, just return. */
/* After locking, the frame table entry of 
   the frame won't change until unlock. */
void
spt_lock_frame (struct spt_entry *spe)
{ 
  struct frame_table_entry *fte = spe->fte;
  if (fte)
  { 
    lock_acquire (&fte->l);
    /* A frame can be asynchronously evicted, double check. */
    if(fte != spe->fte)
    { 
      lock_release (&fte->l);
      ASSERT (spe->fte == NULL); 
    } 
  } 
}

/* Add a supplemental table entry. */
/* Return true if succssful, false on failure .*/ 
bool 
spt_add (int type, uint8_t *upage, bool writable, ...)
{ 
  
  /* Allocate a supplemental table entry and set values. */
  struct spt_entry *spe = malloc (sizeof (struct spt_entry));
  if (spe == NULL)
    return false;

  spe->type = type;
  spe->u_addr = (uint8_t*) pg_round_down (upage);
  spe->writable = writable;
  spe->fte = NULL;
  spe->sector_id = (block_sector_t) -1;
  spe->t = thread_current ();

  if (type == VM_EXECUTABLE_TYPE || type == VM_MMAP_TYPE)
  { 
    /* For executable/mmap file, set file information. */
    va_list ap;
    va_start (ap, writable);
    spe->file = (struct file *) va_arg (ap, struct file *);
    spe->ofs = (int32_t) va_arg (ap, int32_t);
    spe->file_bytes = (uint32_t) va_arg (ap, uint32_t);
    va_end (ap);
  }
  else if (type == VM_STACK_TYPE)
  { 
    spe->file = NULL;
    spe->ofs = 0;
    spe->file_bytes = 0;
  }
  else
  {
    PANIC ("Unknow VM_TYPE !");
  }

  /* Try to insert the entry into the table. */

  if (hash_insert (&spe->t->spt_table, &spe->elem) == NULL)
    return true;
  else
  { 
    free (spe);
    return false;
  }

}

/* Get an entry from the supplemental page table. */
/* Return NULL if not found. */
struct spt_entry* spt_get(void *upage)
{
  struct thread *t = thread_current ();
  struct spt_entry spe;
  spe.u_addr = pg_round_down (upage);
  struct hash_elem *e = hash_find (&t->spt_table, &spe.elem);
  return e != NULL ? hash_entry (e, struct spt_entry, elem) : NULL;
 }

/* Called by the page fault handler. */
/* Load the physical frame. */ 
/* Return true if succssful, false on failure .*/ 		  
bool 
spt_load_page (void *upage)
{
  ASSERT (pg_ofs (upage) == 0); /* Upage must be aligned .*/
  struct spt_entry *spe = spt_get (upage);
  if (spe == NULL)
    return false;

  struct frame_table_entry *fte;

  /* First check whether the page is being evciting. */
  spt_lock_frame (spe);
  if(spe->fte == NULL)
  {
    /* Allocate a frame, immediately lock it. */
    fte = frame_alloc_and_lock (spe);
    if (fte == NULL)
      return false;
  }
  else
    fte = spe->fte;

  /* For executable file, a page may be evicted to swap
     if it has been modified (i.e. the dirty bit is 1). After we
     re-get this frame from the swap, it must be set dirty, so 
     that it will be written to swap when being evicted again.
     Another solution is to set the page to VM_STACK_TYPE after
     first re-getting it from the swap. */ 
  bool need_to_set_dirty = false;
  
  /* load the frame. */
  if(spe->sector_id != (block_sector_t) -1)
  { 
    /* Load this page from swap. */ 
    swap_free (fte->k_addr, spe->sector_id);
    spe->sector_id = (block_sector_t) -1;
    
    /* The page need to be set dirty .*/
    if(spe->type == VM_EXECUTABLE_TYPE)
      need_to_set_dirty = true;
  }
  else if (spe->file != NULL)
  {
    /* Load this page from file. */  
    if (file_read_at (spe->file, fte->k_addr, spe->file_bytes, spe->ofs) 
      != (int) spe->file_bytes)
    {
      frame_release_and_free (fte);
	    return false; 
    }
    memset (fte->k_addr + spe->file_bytes, 0, PGSIZE - spe->file_bytes);
  }
  else
    memset (fte->k_addr, 0, PGSIZE);

  /* Set the virtual-to-physical mapping . */
  if (!install_page (spe->u_addr, fte->k_addr, spe->writable)) 
  {
    frame_release_and_free (fte);
    return false; 
  }

  /* Set the page to be dirty if necessary .*/
  if (need_to_set_dirty)
    pagedir_set_dirty (spe->t->pagedir, spe->u_addr, true);

  spe->fte = fte;
  lock_release (&spe->fte->l);
  ASSERT (!(spe->type == VM_MMAP_TYPE && spe->file_bytes == 0));
  return true;
}
