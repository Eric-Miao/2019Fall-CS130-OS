#include "vm/swap.h"
#include <bitmap.h>
#include <stdio.h>
#include "devices/block.h"

struct swap_table swap_table;

void swap_table_init(void) {
    lock_init(&swap_table.lock);
    swap_table.block = block_get_role(BLOCK_SWAP);
    if (!swap_table.block)
        PANIC("swap table block init failed");
    swap_table.bitmap = bitmap_create(block_size(swap_table.block) / SECTORS_PAGE);
    if (!swap_table.bitmap)
        PANIC("swap table bitmap init failed");
    bitmap_set_all(swap_table.bitmap, false);
}

size_t swap_out(const void *frame) {
    lock_acquire(&swap_table.lock);
    size_t index = bitmap_scan_and_flip(swap_table.bitmap, 0, 1, false);
    if (index == BITMAP_ERROR)
        PANIC("swap is full");
    size_t i;
    for (i = 0; i < SECTORS_PAGE; ++i) {
        block_write(swap_table.block, (block_sector_t) (index * SECTORS_PAGE + i),
                frame + i * BLOCK_SECTOR_SIZE);
    }
    lock_release(&swap_table.lock);
    return index;
}

void swap_in(void *frame, size_t index) {
    lock_acquire(&swap_table.lock);
    ASSERT(bitmap_test(swap_table.bitmap, index));
    size_t i;
    for (i = 0; i < SECTORS_PAGE; ++i) {
        block_read(swap_table.block, (block_sector_t) (index * SECTORS_PAGE + i),
                    frame + i * BLOCK_SECTOR_SIZE);
    }
    bitmap_set(swap_table.bitmap, index, false);
    lock_release(&swap_table.lock);
}
