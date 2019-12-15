#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
typedef int tid_t;

/* struct used for keeping track of process information
   in a thread */
struct process_info {
  tid_t tid;
  struct list_elem elem;  /* List elem for parent's children list. */
  int exit_status;
  struct thread *parent; /* Parent of this thread. */
  struct semaphore exit_sema; /* semaphore that tells the parent that the process is done */
  struct lock wait_l;
  bool waited;/* indicate whether the process is waited by its parent */
};

/* Struct used for managing files that a process has. */
struct process_file{
  struct file *file;
  struct dir *dir;
  int fd;
  struct list_elem elem;
};

/* Message that includes process information which are needed 
  for creating process and passing arguments. */
struct exec_msg
{ 
  char *fn_copy;
  char *prog_name;
  struct semaphore load_sema; /*semaphore to indicate that process has finished loading */
  bool load_complete;
  struct dir *working_dir;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t child_tid);
void process_exit (void);
void process_activate (void);
bool install_page(void *upage, void *kpage, bool writable);
#endif /* userprog/process.h */
