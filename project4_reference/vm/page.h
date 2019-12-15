#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <list.h>
#include <hash.h>
#include "devices/block.h"
#include "threads/thread.h"

#define VM_EXECUTABLE_TYPE 1 /* Type for executable file. */
#define VM_MMAP_TYPE 2 /* Type for mmap file. */
#define VM_STACK_TYPE 3 /* Type for stack page. */

struct spt_entry
{
	int type;						/* Page type. */
	uint8_t *u_addr;    /* User Virtual Address. */
	bool writable;			/* Is page writable? */
	
	/* The frame this page refers to. */
	/* If frame hasn't been loaded, fte is NULL. */
	struct frame_table_entry *fte;

	struct thread *t;   /* Owner thread. */
	struct hash_elem elem; /* Elem used for hash table. */

	/* File information, for both executable file and mmap file. */
	struct file *file;
	int32_t ofs;
	uint32_t file_bytes;

	/* Swap information. */
	/* If the frame is not in swap, sector_id = (block_sector_t) -1. */
	block_sector_t sector_id;

};

bool spt_init(struct hash *spt_table);
void spt_destroy(struct hash *spt_table);
bool spt_add (int type, uint8_t *upage, bool writable, ...);
struct spt_entry* spt_get(void *upage);
bool spt_load_page(void *upage);
void spt_lock_frame (struct spt_entry *spe);

#endif
