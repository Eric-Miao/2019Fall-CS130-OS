#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"

void swap_table_init (void);
block_sector_t swap_alloc (uint8_t *addr);
void swap_free (uint8_t *addr, block_sector_t sector_id);
void swap_clear (block_sector_t sector_id);

#endif