#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>

void syscall_init (void);

/* Keep consistency of variable type name. */
typedef int pid_t;

struct loaded_file * search_file(int );

#endif /* userprog/syscall.h */
