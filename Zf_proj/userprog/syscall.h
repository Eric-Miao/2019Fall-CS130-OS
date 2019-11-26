#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include <stdio.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "devices/input.h"
#include "lib/kernel/list.h"

/*struct that stores map information and file pointer*/
struct map
{
  int mapid;             /*map id*/
  size_t page_count;     /*amount of pages*/
  uint8_t *index;        /*begin position of map memory*/
  struct file *file;     /*file address*/
  struct list_elem elem; /*convenient for storing*/
};

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
void munmap(int mapid);
int mmap(int fd, void *addr);
void is_buffer_valid(void *buffer, unsigned size);
void unmap(struct map *m);
#endif /* userprog/syscall.h */
