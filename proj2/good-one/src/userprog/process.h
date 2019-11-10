#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

int GetRetFromSonsList(struct thread *, tid_t);
void record_ret(struct thread *, int, int );

#endif /* userprog/process.h */
