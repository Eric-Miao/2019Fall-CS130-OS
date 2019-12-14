#ifndef VM_FRAME_H
#define VM_FRAME_H
#include <stdbool.h>
#include "threads/synch.h"

struct frame{
  struct page *page;  //mapped page
  void *base;		  //base address
  struct lock lock;   //prevent race
};

void frame_init(void);

struct frame* frame_alloc_lock(struct page *page);

void frame_lock(struct page *p);

void frame_free(struct frame *f);

void frame_unlock(struct frame *f);

#endif /* vm/frame.h */