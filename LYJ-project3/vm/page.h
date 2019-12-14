#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/synch.h"

struct page{
  
  void *addr;                 //virtual address
  bool read_only;             //read only page
  struct thread *thread;      //owned by which thread

  struct hash_elem hash_elem; //

  struct frame * frame;       //Page frame

  block_sector_t sector;      //Starting sector

  bool private;               //write back to file or swap

  struct file *file;          //the file

  off_t file_offset;          //offset
  off_t file_bytes;           //for read and write
};


struct page *page_allocate (void *, bool read_only);
void page_deallocate (void *vaddr);
bool try_page (void *fault_addr);
bool page_evict (struct page *);
bool page_accessed_recently (struct page *);
void page_exit (void);
bool page_lock (const void *, bool will_write);
void page_unlock (const void *);

hash_hash_func page_hash;
hash_less_func page_less;


#endif /* vm/page.h */
