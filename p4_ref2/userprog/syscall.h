#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <user/syscall.h>
#include "threads/vaddr.h"
#include "vm/page.h"

#define BUFFER_TRUNK 4096
#define STACK_LIMIT (PHYS_BASE - 8 * 0x100000)

void syscall_init (void);
void _exit (int status) NO_RETURN;
void munmap_entry(struct mmap_entry *me);

#endif /* userprog/syscall.h */
