#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/pte.h"
#include "vm/frame.h"

/* Use list to implement frame table, nodes as entries. */
static struct list frame_table;

/* Lock for accessing the frame table */
static struct lock frame_table_lock;

/* The hand for eviction clock. */
static size_t clock_hand;

/* Initialize the whole frame system. */
void 
frame_init()
{
    list_init(&frame_table);
    lock_init(&frame_table_lock);

    void *phys_mem = palloc_get_page(PAL_USER);
    while (phys_mem != NULL)
    {
        struct frame *new_frame = malloc(sizeof(stuct frame));
        new_frame->ker_base = phys_mem;
        new_frame->page = NULL;
        lock_init(new_frame->frame_lock);
        list_push_back(&frame_table, &new_frame->frame_elem);
        phys_mem = palloc_get_page(PAL_USER);
    }
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

struct frame*
frame_allocate(struct page * p)
{
    lock_acquire(&frame_table_lock);
    
    struct list_elem *e;
    struct list *l = &frame_table;

    for (e = list_begin(l); e != list_end(l); e = list_next(e))
    {
        struct frame *f = list_entry(e, struct frame, fte);
        if (!lock_try_acquire(&f->frame_lock))
            continue;
        if (f->page == NULL)
        {
            f->page = page;
            lock_release(&frame_table_lock);
            return f;            
        }
        lock_release(&f->frame_lock);
    }

    /* If reach here, no free frame currently, start to evict. */
}
