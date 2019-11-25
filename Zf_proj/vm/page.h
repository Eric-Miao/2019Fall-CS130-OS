#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/synch.h"

/* virtual page struct*/
struct page 
  {
    void *addr;                 /* user virtual address. */
    bool writable;             /* read only or read and write */
    bool swapable;               /* true to write to swap. */
    struct thread *onwer;      /* thread using that page */
    struct frame *frame;        /* the frame related to this page */
    struct hash_elem pte;      /* to store in table */
    struct file *file;          /* file in page */
    block_sector_t swap_sector;       /* sector of swap area, -1 if no swap area */
    off_t offset;          /* offset of file */
    off_t bytes;           /* read (write) bytes */
  };

void page_table_free(void);
void page_eviction(void *addr);
struct page *page_allocate (void *addr, bool writabel);
struct page *page_search(const void *address);
bool page_in(struct page *p);
bool page_out (struct page *p);
bool page_accessed_recently(struct page *p);
bool page_lock(const void *addr, bool write);
void page_unlock(const void *addr);
hash_hash_func page_number;
hash_less_func page_less;
#endif