#include "vm/page.h"
#include <stdio.h>
#include <string.h>
#include "vm/frame.h"
#include "vm/swap.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

/* Maximum size of process stack, in bytes. */
/* Right now it is 1 megabyte. */
#define MAX_STA (1024 * 1024)

//destroy a page in page table.
static void destroy_page(struct hash_elem *elem, void *aux UNUSED){
  struct page *p = hash_entry(elem,struct page, hash_elem);
  frame_lock(p);
  if(p->frame){
    frame_free(p->frame);
  }
  free(p);
}

//Destroy the page table if there is one
void page_exit(void){
  struct hash *h = thread_current()->pages;
  if(h != NULL){
    hash_destroy(h,destroy_page);
  }
}

//Looking for the corresbonding page for the address.
//allocate if needed
static struct page* page_for_addr(const void *addr){
  if(addr < PHYS_BASE ){
    struct page p;
    struct hash_elem *e;

    p.addr = (void *) pg_round_down(addr);
    e=hash_find(thread_current()->pages, &p.hash_elem);
    if(e!=NULL){
      return hash_entry(e,struct page,hash_elem);
    }
    if((p.addr > PHYS_BASE - MAX_STA) && ((void *)thread_current()->user_esp - 32 <= addr)){
      return page_allocate(p.addr,false);
    }
  }
  return NULL;
}

// Try to lock and page in a frame
static bool do_page_in(struct page *p){
  p->frame = frame_alloc_lock(p);
  if(p->frame ==NULL){
    return false;
  }
  if(p->sector !=(block_sector_t)-1){
    swap_in(p);
  }else if(p->file != NULL){
    off_t read_bytes =file_read_at(p->file,p->frame->base,p->file_bytes,p->file_offset);
    off_t zero_bytes =PGSIZE - read_bytes;
    memset(p->frame->base +read_bytes,0,zero_bytes);
  }else{
    memset(p->frame->base,0,PGSIZE);
  }
  return true;
}

//To page in
bool try_page(void *fault_addr){
  struct page *p;
  bool success;

  if(thread_current()->pages == NULL){
    return false;
  }

  p=page_for_addr(fault_addr);
  if(p==NULL){
    return false;
  }

  frame_lock(p);
  if(p->frame ==NULL){
    if(!do_page_in(p)){
      return false;
    }
  }
  success = pagedir_set_page (thread_current ()->pagedir, p->addr, p->frame->base, !p->read_only);
  frame_unlock(p->frame);

  return success;
}

//To page out
bool page_evict (struct page *p){
  bool dirty;
  bool ok =false;

  pagedir_clear_page(p->thread->pagedir, (void *) p->addr);

  dirty = pagedir_is_dirty (p->thread->pagedir, (const void *) p->addr);
  if(!dirty){
    ok =true;
  }
  if(p->file ==NULL){
    ok =swap_out(p);
  }else{
    if(dirty){
      if(p->private){
        ok=swap_out(p);
      }else{
        ok = file_write_at(p->file, (const void *) p->frame->base, p->file_bytes, p->file_offset);
      }
    }
  }
  if(ok){
    p->frame =NULL;
  }
  return ok;
}
//return wheter the p is accessed recently
bool page_accessed_recently(struct page *p){
  bool was_accessed;

  was_accessed = pagedir_is_accessed (p->thread->pagedir, p->addr);
  if(was_accessed){
    pagedir_set_accessed (p->thread->pagedir, p->addr, false);
  }
  return was_accessed;
}

//do the mapping for the given vitual vaddr to page table
struct page* page_allocate(void *vaddr, bool read_only){
  struct thread *t = thread_current();
  struct page *p =malloc(sizeof *p);
  //printf("%s\n","r" );
  if(p!=NULL){
    p->addr = pg_round_down (vaddr);
    p->read_only = read_only;
    p->private = !read_only;
    p->frame = NULL;
    p->sector = (block_sector_t) -1;
    p->file = NULL;
    p->file_offset = 0;
    p->file_bytes = 0;
    p->thread = thread_current ();
    //printf("%s\n","s" );
    if(hash_insert(t->pages,&p->hash_elem) != NULL){
      //printf("%s\n","w" );
      free(p);
      p = NULL;
    }
    //printf("%s\n","c" );
  }
  return p;
}

// evict and remove from page table
void page_deallocate (void *vaddr){
  struct page *p = page_for_addr (vaddr);
  ASSERT (p != NULL);
  frame_lock (p);
  if (p->frame){
    struct frame *f = p->frame;
    if (p->file && !p->private){
      page_evict (p);
    }
    frame_free (f);
  }
  hash_delete (thread_current ()->pages, &p->hash_elem);
  free (p);
}

//the hash function
unsigned page_hash (const struct hash_elem *e, void *aux UNUSED){
  const struct page *p = hash_entry (e, struct page, hash_elem);
  return ((uintptr_t) p->addr) >> PGBITS;
}

//the compare function for two page's address
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED){
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);
  return a->addr < b->addr;
}

//lock page into memory
bool page_lock (const void *addr, bool will_write){
  struct page *p = page_for_addr (addr);
  if (p == NULL || (p->read_only && will_write)){
    return false;
  }

  frame_lock (p);
  if (p->frame == NULL){
    return (do_page_in(p) && pagedir_set_page(thread_current()->pagedir, p->addr,p->frame->base, !p->read_only));
  }else{
    return true;
  }
}

//unlock page from memory
void page_unlock (const void *addr){
  struct page *p = page_for_addr (addr);
  frame_unlock (p->frame);
}
