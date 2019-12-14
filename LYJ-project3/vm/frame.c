#include "vm/frame.h"
#include <stdio.h>
#include "vm/page.h"
#include "devices/timer.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

static struct frame *frames;
static size_t frame_number;
static struct lock f_lock;
static size_t hand;


//Set up
void frame_init(void){
  void *base;
  lock_init(&f_lock);

  frames = malloc (sizeof *frames * init_ram_pages);

  while((base = palloc_get_page(PAL_USER)) != NULL){
    struct frame * f = &frames[frame_number];
    frame_number++;
    lock_init(&f->lock);
    f->base =base;
    f->page =NULL;
  }

}

//allocate a frame locked for page
static struct frame* try_alloc_lock(struct page *page){
  size_t i;

  lock_acquire(&f_lock);

  //If there exists empty frame
  for(i=0;i<frame_number;i++){
    struct frame *f = &frames[i];
    if(!lock_try_acquire(&f->lock)){
      continue;
    }
    if(f->page ==NULL){
      f->page=page;
      lock_release(&f_lock);
      return f;
    }
    lock_release(&f->lock);
  }

  //Evict one 
  for(i=0;i<frame_number *2;i++){

    //Look for a frame to evict
    struct frame *f = &frames[hand];
    hand++;
    if(hand>=frame_number){
      hand=0;
    }
    if(!lock_try_acquire(&f->lock)){
      continue;
    }
    if(f->page == NULL){
      f->page = page;
      lock_release(&f_lock);
      return f;
    }
    if(page_accessed_recently(f->page)){
      lock_release(&f->lock);
      continue;
    }

    lock_release(&f_lock);

    //Evict the slected frame
    if(!page_evict(f->page)){
      lock_release(&f->lock);
      return NULL;
    }

    f->page=page;
    return f;
  }

  lock_release(&f_lock);
  return NULL;
}

//try several runs to allocate frame for page
struct frame* frame_alloc_lock(struct page *page){
  size_t try;

  for (try = 0;try<3;try++){
    struct frame *f= try_alloc_lock(page);
    if(f!=NULL){
      return f;
    }else{
      timer_msleep(1000);
    }
  }
  return NULL;
}

//Lock frame into memory
void frame_lock(struct page *p){
  struct frame *f = p->frame;
  if(f!=NULL){
    lock_acquire(&f->lock);
    if(f != p->frame){
      lock_release(&f->lock);
    }
  }
}

//Free the frame so it can be used by another page
void frame_free(struct frame *f){
  f->page =NULL;
  lock_release(&f->lock);
}

//unlock, which is used to be evicted
void frame_unlock(struct frame *f){
  lock_release(&f->lock);
}