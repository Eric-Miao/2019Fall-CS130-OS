#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdint.h>
#include <debug.h>
#include <list.h>
#include "threads/palloc.h"
#include "threads/synch.h"
#include "vm/page.h"

struct frame_table_entry {
    void *frame;
    struct thread *owner;
    struct sup_page_table_entry *sup;
    struct list_elem elem;
    struct list_elem elem_owner;
};

struct frame_table {
    struct list table;
    struct lock lock;
};

void frame_table_init(void);
struct frame_table_entry *frame_get_page(enum palloc_flags flags,
        struct sup_page_table_entry *se);
void frame_free_page(struct frame_table_entry *fe);

#endif /* vm/frame.h */
