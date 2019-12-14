#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"
#include "threads/interrupt.h"

void syscall_init (void);
void syscall_exit (void);
int close_f(struct thread * t,int fd,int close_all);
void my_sys_halt(struct intr_frame *f);
void my_sys_exit(struct intr_frame *f);
void my_sys_exec(struct intr_frame *f);
void my_sys_wait(struct intr_frame *f);
void my_sys_create(struct intr_frame *f);
void my_sys_remove(struct intr_frame *f);
void my_sys_open(struct intr_frame *f);
void my_sys_filesize(struct intr_frame *f);
void my_sys_read(struct intr_frame *f);
void my_sys_write(struct intr_frame *f);
void my_sys_seek(struct intr_frame *f);
void my_sys_tell(struct intr_frame *f);
void my_sys_close(struct intr_frame *f);
void my_sys_mmap(struct intr_frame *f);
void my_sys_munmap(struct intr_frame *f);
struct file *getfile(struct thread *th,int fd);
void unusual_exit(int status);
#endif /* userprog/syscall.h */
