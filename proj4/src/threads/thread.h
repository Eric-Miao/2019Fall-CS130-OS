#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "synch.h"
#include "filesys/file.h"
#include "filesys/directory.h"

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

#ifndef FLOAT_H
#define FLOAT_H

/* Definitions of floting point caculation. */
typedef int fixed_t;
/* 16 LSB */
#define SHIFT_BIT 16
/* Convert */
#define I_COV_F(A) ((fixed_t)(A << SHIFT_BIT))
/* Add */
#define ADD(A, B) (A + B)
/* Add float with int */
#define ADD_INT(A, B) (A + (B << SHIFT_BIT))
/* Substract */
#define SUB(A, B) (A - B)
/* Substract int with float */
#define SUB_INT(A, B) (A - (B << SHIFT_BIT))
/* Multiply */
#define MUL(A, B) (A * B)
/* Divid */
#define DIV(A, B) (A / B)
/* Multiply two float */
#define MUL_F(A, B) ((fixed_t)(((int64_t)A) * B >> SHIFT_BIT))
/* Divide two float */
#define DIV_F(A, B) ((fixed_t)((((int64_t)A) << SHIFT_BIT) / B))
/* Get int of float */
#define F_INT(A) (A >> SHIFT_BIT)
/* Get rounded int of float */
#define F_ROUND(A) (A >= 0 ? ((A + (1 << (SHIFT_BIT - 1))) >> SHIFT_BIT) \
                            : ((A - (1 << (SHIFT_BIT - 1))) >> SHIFT_BIT))

#endif /* thread/float.h */
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
    int original_priority;              /* A parmater that record the thread's priority before any donation*/
    int nice;
    struct list_elem allelem;           /* List element for all threads list. */
    struct list locks;                  /*locks that thread possess*/
    struct lock *stuck_lock;            /*stuck lock that thread needs*/
    /*For dealing with busy waiting problem we add a guard as sleeping time signal*/
    int64_t guard;
    fixed_t recent_cpu;
    struct dir *directory;              /*the current working directory of thread*/
    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    int curr_fd;                         /*store the current file descriptor*/
    int exitcode;                       /*save the threads exit code*/
    int is_waiting;                      /*to see if current thread is waiting*/ 
    int success;                         /*thread is successfully loaded or not*/
    struct file *FILE;                   /*store the current open file*/
    struct list file_des;               /*list of file descriptor of thread*/
    struct list children;               /*list store the children of current thread*/
    struct list f_list;                   /*also store the file*/
    struct thread *parent;              /*the parent of current thread*/
    struct list_elem children_elem;     /*store the element in children list*/
    struct semaphore waiting_parent;  /*put parent to sleep when waiting for children*/
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/*struct to store the info of terminated child thread*/
struct last_words
{
  int tid;
  int code;
  struct list_elem ele;
  int running;                  /*termination status*/
};
/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);
void thread_directory_init(void);

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
void thread_wake_up(struct thread *current, void *aux UNUSED);
void thread_foreach (thread_action_func *, void *);
/*Compare the threads' priority return True if second elements' priority is less*/
bool is_priority_less(const struct list_elem *first, const struct list_elem *second, void *aux UNUSED);
bool lock_is_priority_less(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
void donation(struct thread *target);
void priority_update(struct thread *t);
void mlfqs_recent_cpu_increasement(void);
void mlfqs_update_priority(struct thread *t);
void mlfqs_update_cpu(void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

#endif /* threads/thread.h */
