#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

typedef int tid_t;

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* self-defined struct to store the PCB of a process. */
struct PCB
{
  int tid;                            /* This is actually the same tid */
  bool beingwaited;                   /* Signal of me whether being waited. */
  struct list *child_process;         /* The child threads I called */
  struct semaphore *exit_sema;        /* The exit semaphore used for wait. */
  struct semaphore *exec_sema;        /* The exec semaphore used for exec. */
  struct list_elem pcb_elem;          /* Use for added into child_process. */
  struct thread *parent;              /* Parent thread execuated me */


};

/* self_defined func for proj2. */
void pcb_init (struct PCB *);
#endif /* userprog/process.h */
