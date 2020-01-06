#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/synch.h"

struct frame_table_entry
{
	uint8_t *k_addr;			/* Kernel virtual address .*/
	
	/* mapped page. */
	/* Will be NULL if no user virtual 
		 address is mapped to this frame. */
	struct spt_entry *spe;

	/* Used for synchronization. */
	/* see spt_lock_frame function in page.c */
	struct lock l;
};

void frame_table_init (void);
struct frame_table_entry* frame_alloc_and_lock (struct spt_entry *spe);
void frame_release_and_free (struct frame_table_entry *fte);

#endif