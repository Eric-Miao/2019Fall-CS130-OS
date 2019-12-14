#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"

typedef int pid_t;
void syscall_init(void);
void halt(void);
void exit(int status);
int exec(const char *file);
int wait(pid_t PID);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

void is_buffer_valid(void *buffer, unsigned size);
#endif /* userprog/syscall.h */
