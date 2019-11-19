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
void frame_init()
{
    list_init (&frame_table);
    lock_init (&frame_table_lock);

    void* phys_mem = palloc_get_page(PAL_USER);
    while (phys_mem != NULL)
    {
        struct frame *new_frame = malloc(sizeof(stuct frame));
        new_frame->ker_base = phys_mem;
        new_frame->page = NULL;
        lock_init (new_frame->frame_lock);
        list_push_back (&frame_table, &new_frame->frame_elem);
        phys_mem = palloc_get_page(PAL_USER);
    }
}