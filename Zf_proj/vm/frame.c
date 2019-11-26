#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/pte.h"
#include "vm/frame.h"
#include "vm/page.h"

/* Use list to implement frame table, nodes as entries. */
static struct list frame_table;

/* Lock for accessing the frame table */
static struct lock frame_table_lock;

/* The loop indicator for eviction clock. */
static size_t clock_loop;

/* Initialize the whole frame system. */
void *
frame_init()
{
    list_init(&frame_table);
    lock_init(&frame_table_lock);

    void *phys_mem = palloc_get_page(PAL_USER);
    while (phys_mem != NULL)
    {
        struct frame *new_frame = malloc(sizeof(struct frame));
        new_frame->ker_base = phys_mem;
        new_frame->page = NULL;
        lock_init(&new_frame->frame_lock);
        list_push_back(&frame_table, &new_frame->fte);
        ASSERT(!list_empty(&frame_table));
        phys_mem = palloc_get_page(PAL_USER);
        ASSERT(!list_empty(&frame_table));
    }
    ASSERT(!list_empty(&frame_table));
}

bool 
frame_free(struct frame *f)
{
    ASSERT(lock_held_by_current_thread(&f->frame_lock));

    f->page = NULL;
    frame_unlock(f);
}

bool 
frame_lock(struct frame *f)
{
    if (f != NULL)
    {
        lock_acquire(&f->frame_lock);
        if(f != f->page->frame)
        {
            ASSERT (f->page->frame == NULL);
            lock_release(&f->frame_lock);
        }
    }
}

bool 
frame_unlock(struct frame *f)
{
    ASSERT(lock_held_by_current_thread(&f->frame_lock));
    lock_release(&f->frame_lock);
}

/* Use the clock policy to choose a frame to evict.
   The hand is the right now pointer. 
   Go through the list twice. 
   For the first time, find a frame to evict. 
   For the second time, locate the free frame and return.
   Evict the frame whose page is not recently accessed. 
   IF evict fails return NULL;*/
static struct frame*
frame_evict(struct page *p)
{
    struct list_elem *e;
    struct list *l = &frame_table;
    clock_loop = 1;

    for (e = list_begin(l); (e != list_end(l) || clock_loop < 3); e = list_next(e))
    {
        /* When reach the tail, start from the head again and loop ++. */
        if (e == list_end(l))
        {
            clock_loop ++;
            e = list_begin(l);
        }

        struct frame *f = list_entry(e, struct frame, fte);
        if (!lock_try_acquire(&f->frame_lock))
            continue;
            
        if (f->page == NULL)
        {
            f->page = p;
            lock_release(&frame_table_lock);
            /* The page is mine now, no need to release the lock. */
            return f;
        }

        /*  If the page has recently accessed, clean the access bit and continue. 
            IMPORTANT: CLEAR THE ACCESS BIT IN PAGE P AFTER I CHECK.*/
        if (page_accessed_recently(p))
        {
            lock_release(&f->frame_lock);
            continue;
        }

        /* If the page is not NULL | not recently accessed  
            try to evivt it and return the frame if success.
            Otherwise return NULL */
        if (page_out(p))
        {
            lock_release(&frame_table_lock);
            /* The page is mine now, no need to release the lock. */
            f->page = p;
            return f;
        }
        /* page out fail */
        else
        {
            lock_release(&frame_table_lock);
            lock_release(&f->frame_lock);
            return NULL;
        }
    }
    lock_release(&frame_table_lock);
    return NULL;
}

/* ACTUALLY, I think this implementation is kind of silly because it travels the 
    frame table to determine if the frame is owned by the current thread.
    Rather than go through the process's page table to see what frame he gets,
    and choose from them.
    Or use another method to show if the frame is owned by the process.
    Just suggestions. */
struct frame*
frame_allocate(struct page *p)
{
    lock_acquire(&frame_table_lock);
    
    struct list_elem *e;
    struct list *l = &frame_table;
    for (e = list_front(l); e != list_end(l); e = list_next(e))
    {
        struct frame *f = list_entry(e, struct frame, fte);
        /* If the current thread doesn't have the lock of this frame
            This means the this frame doesn't belong to the current process,
            just go on to check the next frame. */
        if (!lock_try_acquire(&f->frame_lock))
            continue;
        
        if (f->page == NULL)
        {
            f->page = p;
            lock_release(&frame_table_lock);
            return f;            
        }
        lock_release(&f->frame_lock);
    }
    
    /*  If reach here, no free frame currently, start to evict. 
        For now, just panic. evict shall be on at last.*/
    /*PANIC("no enough frames to allocate.");*/
    return frame_evict(p);
}
