#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <hash.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"
#include "filesys/directory.h"
#include "filesys/file.h"

/* States in a thread's life cycle. */
enum thread_status
{
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* NEW: Thread nice values. */
#define NICE_MIN (-20)                  /* Lowest nice. */
#define NICE_INIT 0                     /* Default nice. */
#define NICE_MAX 20                     /* Highest nice. */
#define RECENT_CPU_INIT 0

struct file_opened {
    struct file *file;
    int fd;
    bool closed;
};

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
{
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    int priority_origin;                /* NEW: Original priority. */
    int priority_donated;               /* NEW: Donated priority. */
    int nice;                           /* NEW */
    int64_t recent_cpu;                 /* NEW */
    int64_t wakeup;                     /* NEW: Wakeup time. */

    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */
    struct list_elem sleepelem;

    bool syscall;                       /* NEW: In a syscall or not. */
    struct lock *lock_waiting;          /* NEW: The lock waiting on. */
    struct list locks;                  /* NEW: The locks holding. */

#ifdef USERPROG
    void *esp;
    struct dir *cwd;
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    struct list frame_table;
    struct hash sup_page_table;
    struct hash mmap_table;
    int num_files;                      /* NEW: Number of files opened. */
    int num_mmap;
    int max_num_files;                  /* NEW */
    int exit_code;
    struct file_opened *files;          /* NEW: Files opened. */
    struct child_status *cs;
    struct list children;
    struct lock children_lock;
    struct file *file_executing;
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
};

struct child_status {
    struct semaphore sema_wait;
    struct list_elem elem;
    struct lock ref_lock;
    tid_t tid;
    int exit_code;
    bool waited;
    bool parent_ref;
    bool child_ref;
};

struct load_aux {
    struct semaphore sema;
    struct child_status *cs;
    struct thread *parent;
    char *file_name;
    char *cmd_line;
    bool success;
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);
void thread_cwd_init (void);

void thread_tick (void);
void thread_sleep(int64_t wakeup);
void thread_wakeup(void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
typedef void thread_action_func_wo_aux (struct thread *t);
void thread_foreach (thread_action_func *, void *);
void thread_foreach_wo_aux (thread_action_func_wo_aux *);

int thread_get_priority (void);
void thread_set_priority (int);
void thread_priority_restore(void);
void thread_priority_donate(struct thread *t, int new_priority);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void thread_update_load_avg(void);
void thread_update_recent_cpu(struct thread *t);
void thread_update_adv_priority(struct thread *t);

#endif /* threads/thread.h */
