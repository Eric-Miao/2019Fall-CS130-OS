#include "vm/page.h"
#include <string.h>
#include "filesys/file.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/swap.h"

static unsigned sup_page_table_hash_func(const struct hash_elem *e, void *aux UNUSED) {
    struct sup_page_table_entry *s = hash_entry(e, struct sup_page_table_entry, elem);
    return (unsigned) s->user_vaddr;
}

static bool sup_page_table_less_func(const struct hash_elem *a,
        const struct hash_elem *b, void *aux UNUSED) {
    struct sup_page_table_entry *sa = hash_entry(a, struct sup_page_table_entry, elem);
    struct sup_page_table_entry *sb = hash_entry(b, struct sup_page_table_entry, elem);
    return sa->user_vaddr < sb->user_vaddr;
}

void sup_page_table_init(struct hash *s) {
    hash_init(s, sup_page_table_hash_func, sup_page_table_less_func, NULL);
}

static unsigned mmap_table_hash_func(const struct hash_elem *e, void *aux UNUSED) {
    struct mmap_entry *s = hash_entry(e, struct mmap_entry, elem);
    return (unsigned) s->mid;
}

static bool mmap_table_less_func(const struct hash_elem *a,
                                 const struct hash_elem *b, void *aux UNUSED) {
    struct mmap_entry *ma = hash_entry(a, struct mmap_entry, elem);
    struct mmap_entry *mb = hash_entry(b, struct mmap_entry, elem);
    return ma->mid < mb->mid;
}

void mmap_table_init(struct hash *m) {
    hash_init(m, mmap_table_hash_func, mmap_table_less_func, NULL);
}

struct sup_page_table_entry *sup_page_table_find(struct hash *s, void *user_vaddr) {
    struct sup_page_table_entry t;
    t.user_vaddr = user_vaddr;
    struct hash_elem *e = hash_find(s, &t.elem);
    return e ? hash_entry(e, struct sup_page_table_entry, elem) : NULL;
}

void sup_page_table_entry_free(struct hash_elem *e, void *aux UNUSED) {
    free(hash_entry(e, struct sup_page_table_entry, elem));
}

void mmap_entry_free(struct hash_elem *e, void *aux UNUSED) {
    munmap_entry(hash_entry(e, struct mmap_entry, elem));
}

bool stack_growth(void *upage) {
    ASSERT(!pg_ofs(upage));

    struct sup_page_table_entry *se = malloc(sizeof(struct sup_page_table_entry));
    if (!se)
        return false;
    se->user_vaddr = upage;
    se->flags = SUP_SWAP;
    se->writable = true;
    se->pin = false;
    se->frame = NULL;
    lock_init(&se->lock);

    struct frame_table_entry *fe = frame_get_page (PAL_USER | PAL_ZERO, se);
    if (!fe) {
        free(se);
        return false;
    }
    void *kpage = fe->frame;

    if (!install_page (upage, kpage, true)) {
        free(se);
        frame_free_page(fe);
        return false;
    }
    if (hash_insert(&thread_current()->sup_page_table, &se->elem)) {
        free(se);
        frame_free_page(fe);
        return false;
    }

    return true;
}

bool load_swap(struct sup_page_table_entry *se, void *upage) {
    ASSERT(se);
    ASSERT(!pg_ofs(upage));

    struct frame_table_entry *fe = frame_get_page(PAL_USER, se);
    if (!fe)
        return false;
    void *kpage = fe->frame;
    if (!install_page(upage, kpage, se->writable)) {
        frame_free_page(fe);
        return false;
    }

    swap_in(kpage, se->swap_index);
    return true;
}

bool load_file(struct sup_page_table_entry *se, void *upage) {
    ASSERT(se);
    ASSERT(!pg_ofs(upage));

    /* Get a page of memory. */
    struct frame_table_entry *fe = frame_get_page(PAL_USER, se);
    if (!fe)
        return false;
    void *kpage = fe->frame;

    /* Load this page. */
    if (se->read_bytes > 0) {
        off_t ofs = file_read_at(se->file, kpage, (off_t) se->read_bytes, se->offset);
        if (ofs != (int) se->read_bytes) {
            frame_free_page(fe);
            return false;
        }
    }
    memset(kpage + se->read_bytes, 0, PGSIZE - se->read_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, se->writable)) {
        frame_free_page(fe);
        return false;
    }

    return true;
}

bool load_lazy(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
        uint32_t zero_bytes, bool writable, uint32_t flags) {
    struct thread *cur = thread_current();
    while (read_bytes > 0 || zero_bytes > 0) {
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;
        struct sup_page_table_entry *se = malloc(sizeof(struct sup_page_table_entry));
        if (!se) {
            return false;
        }
        se->user_vaddr = upage;
        se->flags = flags;
        se->file = file;
        se->offset = ofs;
        // printf("------add -spt_entry->se->offset-----%d-\n", se->offset );
        // printf("------add -spt_entry->user_vaddrt-----%d-\n", se->user_vaddr );

        se->read_bytes = page_read_bytes;
        se->writable = writable;
        se->pin = false;
        se->frame = NULL;
        lock_init(&se->lock);
        if (hash_insert(&cur->sup_page_table, &se->elem)) {
            free(se);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
        ofs += PGSIZE;
    }

    return true;
}
