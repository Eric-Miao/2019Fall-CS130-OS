#ifndef VM_SWAP_H
#define VM_SWAP_H 1
#include <stdbool.h>

struct page;

void swap_init(void);
bool swap_disk_into_page(struct page *);
bool swap_page_outto_disk(struct page *);

bool is_valid_swap(struct page *, bool);
#endif /* vm/swap.h */
