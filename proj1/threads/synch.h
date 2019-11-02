#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <debug.h>
#include <list.h>
#include <stdint.h>


/* A counting semaphore. */
struct semaphore 
  {
    unsigned value;             /* Current value. */
    struct list waiters;        /* List of waiting threads. */
  };

void sema_init (struct semaphore *, unsigned value);
void sema_down (struct semaphore *);
bool sema_try_down (struct semaphore *);
void sema_up (struct semaphore *);
void sema_self_test (void);

/* Lock. */
struct lock 
  {
    struct thread *holder;      /* Thread holding lock (for debugging). */
    struct semaphore semaphore; /* Binary semaphore controlling access. */

    /* self-defined properties*/
    struct list_elem elem;      /* List elem to add in the holding list. */
    int lock_priority;          /* Max Priority of the lock */
  };

void lock_init (struct lock *);
void lock_acquire (struct lock *);
bool lock_try_acquire (struct lock *);
void lock_release (struct lock *);
bool lock_held_by_current_thread (const struct lock *);
void lock_release_thread_update (struct lock *);

/* Condition variable. */
struct condition 
  {
    struct list waiters;        /* List of waiting threads. */
  };

void cond_init (struct condition *);
void cond_wait (struct condition *, struct lock *);
void cond_signal (struct condition *, struct lock *);
void cond_broadcast (struct condition *, struct lock *);

/* Self-defined functions below. */
void lock_and_holder_update_acquire (struct lock *);
bool lock_holder_donate (struct lock *, struct thread *);
void lock_holder_donate_nested (struct thread *);
void lock_release_thread_update (struct lock *lock);

bool thread_priority_compare_less(const struct list_elem *a, 
                              const struct list_elem *b, void *aux);
bool thread_ticks_compare_less(const struct list_elem *a, 
                              const struct list_elem *b, void *aux);
bool lock_priority_compare_less(const struct list_elem *a, 
                              const struct list_elem *b, void *aux);
bool cond_priority_compare_less(const struct list_elem *a, 
                              const struct list_elem *b, void *aux);
/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile ("" : : : "memory")

#endif /* threads/synch.h */
