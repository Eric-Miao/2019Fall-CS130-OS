#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include <hash.h>
#include <user/syscall.h>
#include "filesys/off_t.h"
#include "threads/synch.h"

#define SUP_MMAP 0x1
#define SUP_SWAP 0x2
#define SUP_SEG  0x4

struct sup_page_table_entry {
    void *user_vaddr;
    uint32_t flags;
    struct file *file;
    off_t offset;
    size_t read_bytes;
    bool writable;
    bool pin;
    size_t swap_index;
    struct frame_table_entry *frame;
    struct lock lock;
    struct hash_elem elem;
};

struct mmap_entry {
    mapid_t mid;
    size_t num_pages;
    void *user_vaddr;
    struct file *file;
    struct hash_elem elem;
};

void sup_page_table_init(struct hash *s);
void mmap_table_init(struct hash *m);
void sup_page_table_entry_free(struct hash_elem *e, void *aux UNUSED);
void mmap_entry_free(struct hash_elem *e, void *aux UNUSED);
struct sup_page_table_entry *sup_page_table_find(struct hash *s, void *user_vaddr);
bool stack_growth(void *upage);
bool load_swap(struct sup_page_table_entry *se, void *upage);
bool load_file(struct sup_page_table_entry *se, void *upage);
bool load_lazy(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
               uint32_t zero_bytes, bool writable, uint32_t flags);

#endif /* vm/page.h */
