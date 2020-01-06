#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/vaddr.h"

#define PATHNAME_MAX 1024
#define CMDLINE_MAX PGSIZE

tid_t process_execute (const char *cmd_line);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void get_file_name(const char *cmd_line, const char *delimiters, char *prog_name);
bool install_page (void *upage, void *kpage, bool writable);

#endif /* userprog/process.h */
