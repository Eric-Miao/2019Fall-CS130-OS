#include "vm/frame.h"
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/swap.h"

struct frame_table frame_table;

static void *frame_evict(enum palloc_flags flags);

void frame_table_init(void) {
    list_init(&frame_table.table);
    lock_init(&frame_table.lock);
}

struct frame_table_entry *frame_get_page(enum palloc_flags flags,
        struct sup_page_table_entry *se) {
    ASSERT(se);
    ASSERT(flags & PAL_USER);

    lock_acquire(&frame_table.lock);
    void *frame = palloc_get_page(flags);
    if (!frame)
        frame = frame_evict(flags);
    lock_release(&frame_table.lock);
    if (!frame) {
        return NULL;
    }

    struct frame_table_entry *fe = malloc(sizeof(struct frame_table_entry));
    if (!fe) {
        palloc_free_page(frame);
        return NULL;
    }

    struct thread *cur = thread_current();
    fe->frame = frame;
    fe->owner = cur;
    fe->sup = se;
    se->frame = fe;
    lock_acquire(&frame_table.lock);
    list_push_back(&frame_table.table, &fe->elem);
    list_push_back(&cur->frame_table, &fe->elem_owner);
    lock_release(&frame_table.lock);

    return fe;
}

void frame_free_page(struct frame_table_entry *fe) {
    lock_acquire(&frame_table.lock);
    list_remove(&fe->elem);
    list_remove(&fe->elem_owner);
    lock_release(&frame_table.lock);
    palloc_free_page(fe->frame);
    free(fe);
}

static void *frame_evict(enum palloc_flags flags) {
    struct list_elem *e = list_begin(&frame_table.table);

    while (true) {
        struct frame_table_entry *fe = list_entry(e, struct frame_table_entry, elem);
        ASSERT(fe);
        struct sup_page_table_entry *se = fe->sup;
        ASSERT(se);

        lock_acquire(&se->lock);
        if (!se->pin) {
            struct thread *t = fe->owner;
            if (pagedir_is_accessed(t->pagedir, se->user_vaddr))
                pagedir_set_accessed(t->pagedir, se->user_vaddr, false);
            else {
                if (se->flags & SUP_MMAP) {
                    if (pagedir_is_dirty(t->pagedir, se->user_vaddr)) {
                        file_write_at(se->file, fe->frame, (off_t) se->read_bytes, se->offset);
                    }
                    pagedir_clear_page(t->pagedir, se->user_vaddr);
                } else {
                    if (se->flags & SUP_SEG)
                        se->flags = SUP_SWAP;
                    pagedir_clear_page(t->pagedir, se->user_vaddr);
                    se->swap_index = swap_out(fe->frame);
                }

                list_remove(&fe->elem);
                list_remove(&fe->elem_owner);
                void *page = fe->frame;
                free(fe);
                if (flags & PAL_ZERO)
                    memset(page, 0, PGSIZE);
                se->frame = NULL;
                lock_release(&se->lock);
                return page;
            }
        }
        lock_release(&se->lock);
        e = list_next(e);
        if (e == list_end(&frame_table.table)) {
            e = list_begin(&frame_table.table);
        }
    }
    NOT_REACHED();
}
