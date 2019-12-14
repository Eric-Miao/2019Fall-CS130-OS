#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include <hash.h>
#include "fixed_point.h"
#include "../filesys/file.h" //Krasus
#include "synch.h"

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

/*Used to save the information of files in a list*/
struct file_point
{
  int fd; //the file descriptors for this file
  struct list_elem elem; //to use the list
  struct file *ff;       //The file
};

/*Used to save the information of sons in a list*/
struct son_list_elem
{
  int tid;                //thread id of the thread
  int end_status;         //The status to return to parent when exit. Store in parent's thread
  struct list_elem elem;  //To use list
};
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Owned by process.c. */
    int exit_code;                      /* Exit code. */
    struct wait_status *wait_status;    /* This process's completion status. */
    struct list children;               /* Completion status of children. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

    /* Alarm clock. */
    int64_t wakeup_time;                /* Time to wake this thread up. */
    struct list_elem timer_elem;        /* Element in timer_wait_list. */
    struct semaphore timer_sema;        /* Semaphore. */

    /* Owned by userprog/process.c. */
    struct file *bin_file;              /* The binary executable. */

    /* Owned by syscall.c. */
    struct list fds;                    /* List of file descriptors. */
    int next_handle;                    /* Next handle value. */

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */


    //My
    uint32_t *pagedir;                  /* Page directory. */
    void *user_esp;
    struct list mappings;
    struct hash *pages;

    //Project2
    struct list list_of_files;             //A list to contain 
    int fd_max;                            //To deffer the fd for each file
    struct file *file_for_this_thread;     //store the file of 


    struct semaphore wait_done,start_wait; //One is for the thread to wait son
                                           //to get in, and another is to wait
                                           //for son to exit
    int num_of_sons;          //number of sons
    struct thread *parent;    //Krasus  parent thread
    int number_of_file;       //number of files opened
    bool waited_by_parent;    //whether waited by the parent or not
    bool save_data_to_parent; //Has saved the data to parent or not
    struct list list_of_sons; //A list to contain the status from children

    int own_priority;                   /* The priority before donation*/
    struct list Owned_locks;            /* The block in the */
    struct lock *lock_to_wait;          /* The lock waitinf to release*/
    fixed_t recent_cpu;                 /* Recent cpu */
    int nice;                           /* Niceness */

    int64_t left_blocked_time;          /* The time that this thread left to be blocked */
    int end_status;                     /*The exit status to print*/
  };

/* Tracks the completion of a process.
   Reference held by both the parent, in its `children' list,
   and by the child, in its `wait_status' pointer. */
struct wait_status
  {
    struct list_elem elem;              /* `children' list element. */
    struct lock lock;                   /* Protects ref_cnt. */
    tid_t tid;                          /* Child thread id. */
    int exit_code;                      /* Child exit code, if dead. */
    struct semaphore dead;              /* 1=child alive, 0=child dead. */
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
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
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);
void thread_block_check(struct thread *t, void *aux UNUSED);
bool thread_priority_compare(const struct list_elem *x, const struct list_elem *y, void *aux UNUSED);
bool lock_priority_compare(const struct list_elem *x, const struct list_elem *y,void *aux UNUSED);
void thread_updating_priority(struct thread *t);
void thread_lock_attachment(struct lock *lock);
bool cond_priority_compare(const struct list_elem *x, const struct list_elem *y,void *aux UNUSED);
void thread_updating_recent_cpu(void);
void thread_updating_load_avg_recent_cpu(void);
void thread_mlfps_updating_priority(struct thread *t);
void thread_updating_recent_cpu_and_priority(struct thread *t, void *aux UNUSED);

struct thread* get_thread(tid_t tid);


#endif /* threads/thread.h */
