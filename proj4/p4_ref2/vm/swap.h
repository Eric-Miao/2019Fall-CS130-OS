#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#define SECTORS_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

struct swap_table {
    struct block *block;
    struct bitmap *bitmap;
    struct lock lock;
};

void swap_table_init(void);
size_t swap_out(const void *frame);
void swap_in(void *frame, size_t index);

#endif /* vm/swap.h */
