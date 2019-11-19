#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"
#include "vm/pages.h"

#include <stdbool.h>
struct frame
{
    struct lock frame_lock;     /* The lock ensures critical section. */
    void* ker_base;                 /* Kernel virtual page. */
    struct page *page;          /* The page this frame assigned to. */
    struct list_elem fte        /* Frame table entry. */
};

void* frame_init(void);
struct frame* frame_allocate (struct page *);
bool frame_free (struct frame *);
bool frame_lock (struct frame*);
bool frame_unlook (struct frame*);