#include <stdio.h>
#include <string.h>
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

/*allocate a page and add it into page table*/
struct page *page_allocate(void *addr, bool writable)
{
    struct thread *curr = thread_current();
    /*malloc memory for new page*/
    struct page *new_page = malloc(sizeof *new_page);
    /*init the new page if succeed*/
    if (new_page != NULL)
    {
        /*round down the address to the neareat page boundary*/
        new_page->addr = pg_round_down(addr);
        /*record the writable status true on read only*/
        new_page->writable = writable;
        /*record the swapable status false if read only*/
        new_page->swapable = !writable;
        /*there is no frame allocated yet*/
        new_page->frame = NULL;
        /*there is no initial swap area*/
        new_page->sector = (block_sector_t)-1;
        /*no initial file*/
        new_page->file = NULL;
        new_page->file_offset = 0;
        new_page->file_bytes = 0;
        /*record the process using this page*/
        new_page->thread = curr;
        /*search and insert new page into page table*/
        if (hash_insert(curr->page_table, &new_page->pte) != NULL)
        {
            /*if it is already in page table then free the newly created one*/
            free(new_page);
            new_page = NULL;
        }
    }
    return new_page;
}

/*free a page*/
static void page_free(struct hash_elem *elem, void *aux UNUSED)
{
    struct page *p = hash_entry(elem, struct page, pte);
    frame_lock(p);
    /*if it is allocated a frame then free it*/
    if (p->frame != NULL)
    {
        frame_free(p->frame);
    }
    free(p);
}

/*free page table owned by current process*/
void page_table_free()
{
    struct thread *curr = thread_current();
    struct hash *table = curr->page_table;
    /*if the current process has a page table free it*/
    if (table != NULL)
    {
        /*go through the table and free every pages in it*/
        hash_destroy(table, page_free);
    }
}

/*search for page by given address*/
static struct page *page_search(const void *address)
{
    if (address < PHYS_BASE)
    {
        struct page p;
        p.addr = (void *)pg_round_down(address);
        struct thread *curr = thread_current();
        struct hash_elem *key = hash_find(curr->page_table, p.pte);
        if (key != NULL)
        {
            struct page *target = hash_entry(key, struct page, pte);
            return target;
        }
        if ((p.addr > PHYS_BASE - STACK_MAX) && ((void *)thread_current()->user_esp - 32 < address))
        {
            return page_allocate(p.addr, false);
        }
    }

    return NULL;
}

/* lock the page to the frame and identify its write status */
bool page_lock(const void *addr, bool write)
{
    /*search for page by address given*/
    struct page *p = page_search(addr);
    /*if there is no such page return false*/
    if (p == NULL)
    {
        return false;
    }
    /*if trying to write to a read only page then return false*/
    if (p->writabel && write)
    {
        return false;
    }
    frame_lock(p);
    /*if no frame is allocated to current page yet*/
    if (p->frame == NULL)
    {
        struct thread *curr = thread_current();
        /*allocate a frame to the page*/
        bool success_alloc = page_in(p);
        /*map the page to newly allocated frame */
        bool success_map = pagedir_set_page(curr->pagedir, p->addr, p->frame->ker_base, !p->writable);
        if (success_alloc && success_map)
        {
            return true;
        }
        return false;
    }
    /*successfully locked*/
    else
    {
        return true;
    }
}

/* unlock the page locked to frame */
void page_unlock(const void *addr)
{
    struct page *p = page_for_addr(addr);
    ASSERT(p != NULL);
    frame_unlock(p->frame);
}

/* if page has been accessed recently return true */
bool page_accessed_recently(struct page *p)
{
    /*make sure it has a related locked frame*/
    ASSERT(p->frame != NULL);
    ASSERT(lock_held_by_current_thread(&p->frame->lock));
    /*check if it is recently accessed*/
    bool accessed = pagedir_is_accessed(p->thread->pagedir, p->addr);
    if (accessed)
    {
        /*if it is recently accessed set it to not accessed recently after checking */
        pagedir_set_accessed(p->thread->pagedir, p->addr, false);
    }
    return accessed;
}

/*allocte the frame and fill in page*/
static bool page_in(struct page *p)
{
    /* Get a frame for the page. */
    p->frame = frame_alloc(p);
    if (p->frame == NULL)
    {
        p->frame = frame_evict(p);
        if (p->frame == NULL)
        {
            return false;
        }
    }
    /* there is data stored in the swap area */
    if (p->sector != (block_sector_t)-1)
    {
        /* read the data in swap area out and write into page */
        swap_disk_outto_page(p)
    }
    /*if there is file to write*/
    else if (p->file != NULL)
    {
        /* get data from file. */
        off_t read = file_read_at(p->file, p->frame->ker_base, p->bytes, p->offset);
        /*calculate the blank space left*/
        off_t blank = PGSIZE - read;
        /*fill the blank space with zero*/
        memset(p->frame->ker_base + read, 0, blank);
        /*can not read all the bytes of the file
          However, confuse why printing*/
        if (read != p->bytes)
        {
            printf("bytes read (%" PROTd ") != bytes requested (%" PROTd ")\n",
                   read_bytes, p->file_bytes);
        }
    }
    else
    {
        /* fill the page with zero */
        memset(p->frame->base, 0, PGSIZE);
    }
    return true;
}