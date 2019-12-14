#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"


static int sys_exit (int status);
static int sys_exec (const char *ufile);
static int sys_wait (tid_t);
static int sys_create (const char *ufile, unsigned initial_size);
static int sys_remove (const char *ufile);
static int sys_open (const char *ufile);
static int sys_filesize (int handle);
static int sys_read (int handle, void *udst_, unsigned size);
static int sys_write (int handle, void *usrc_, unsigned size);
static int sys_seek (int handle, unsigned position);
static int sys_tell (int handle);
static int sys_close (int handle);
static int sys_mmap (int handle, void *addr);
static int sys_munmap (int mapping);

static void syscall_handler (struct intr_frame *);
static void copy_in (void *, const void *, size_t);

static struct lock file_lock;


void unusual_exit(int status){
  thread_current()->end_status=status;
  thread_exit();
}



void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

/* System call handler. */
static void
syscall_handler (struct intr_frame *f)
{

  if(f==NULL){
    unusual_exit(-1);
  }
  if(!is_user_vaddr(f->esp)){
    unusual_exit(-1);
  }
  int Nu = *((int*)(f->esp));
  if (Nu<0 || Nu>21){
    unusual_exit(-1);
  }
  /* Execute the system call,
     and set the return value. */
  switch(Nu){
    case SYS_HALT:my_sys_halt(f);return;
    case SYS_EXIT:my_sys_exit(f);return;
    case SYS_EXEC:my_sys_exec(f);return;
    case SYS_WAIT:my_sys_wait(f);return;
    case SYS_CREATE:my_sys_create(f);return;
    case SYS_REMOVE:my_sys_remove(f);return;
    case SYS_OPEN:my_sys_open(f);return;
    case SYS_FILESIZE:my_sys_filesize(f);return;
    case SYS_READ:my_sys_read(f);return;
    case SYS_WRITE:my_sys_write(f);return;
    case SYS_SEEK:my_sys_seek(f);return;
    case SYS_TELL:my_sys_tell(f);return;
    case SYS_CLOSE:my_sys_close(f);return;
    case SYS_MMAP:my_sys_mmap(f);return;
    case SYS_MUNMAP:my_sys_munmap(f);return;
  }
}


struct mapping{
  struct list_elem elem;  //to add in list
  int fd;                 //file fd
  struct file *file;      //the file
  uint8_t *base;          //the address for the memory
  size_t number;          //number of pages mapped
};

struct mapping * lookup_mapping (int fd){
  struct thread *current_thread = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&current_thread->mappings); e != list_end (&current_thread->mappings);e = list_next (e)){
    struct mapping *m = list_entry (e, struct mapping, elem);
    if (m->fd == fd)
      return m;
  }

  unusual_exit(-1);
}

void unmap(struct mapping *m){
  list_remove(&m->elem);

  for(int i =0;i<m->number;i++){
    if(pagedir_is_dirty(thread_current()->pagedir,((const void *)((m->base) + (PGSIZE *i) )))){
      lock_acquire(&file_lock);
      file_write_at(m->file, (const void*)(m->base+PGSIZE*i),(PGSIZE*m->number),PGSIZE*i);
      lock_release(&file_lock);
    }
  }

  for(int i = 0;i<m->number;i++){
    page_deallocate((void *)((m->base) + (PGSIZE*i)));
  }
}

/*sys_call to shut down*/
void my_sys_halt(struct intr_frame *f){
  shutdown_power_off();
  f->eax=0;
}

/*sys_call to exit*/
void my_sys_exit(struct intr_frame *f){
  if(!is_user_vaddr((int*)f->esp+2)){
    unusual_exit(-1);
  }
  thread_current()->end_status=*((int*)f->esp+1);
  f->eax=0;
  thread_exit();
}

/*sys_call to execute instruction with or without arguments*/
void my_sys_exec(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    unusual_exit(-1);
  }
  tid_t t=-1;
  const char *page=(char*)*((int *)f->esp+1);
  if(page==NULL){
    f->eax=t;
    return;
  }
  char *new_page=(char *)malloc(sizeof(char)*(strlen(page)+1));
  memcpy(new_page,page,strlen(page)+1);

  lock_acquire(&file_lock);
  t=process_execute(new_page);
  lock_release(&file_lock);
  
  free(new_page);
  f->eax=t;
}

/*sys_call to wait for the son to exit and get the end_status of son*/
void my_sys_wait(struct intr_frame *f){
  if(!is_user_vaddr(((int*)f->esp)+2)){
    unusual_exit(-1);
  }
  tid_t t=*((int *)f->esp+1);
  if(t == -1){
    f->eax=-1;
  }else{
    f->eax=process_wait(t);
  }
}

/*sys_call to create a new file*/
void my_sys_create(struct intr_frame *f){
  if(!is_user_vaddr(((int*)f->esp)+6)){
    unusual_exit(-1);
  }
  if((const char*)*((unsigned int *)f->esp+4)==NULL){
    f->eax=-1;
    unusual_exit(-1);
  }
  lock_acquire(&file_lock);
  f->eax=filesys_create((const char *)*((unsigned int *)f->esp+4),*((unsigned int *)f->esp+5));
  lock_release(&file_lock);
}

/*sys_call to remove a file*/
void my_sys_remove(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    unusual_exit(-1);
  }
  char *name=(char *)*((int*)f->esp+1);

  lock_acquire(&file_lock);
  f->eax=filesys_remove(name);
  lock_release(&file_lock);
}

/*sys_call to open a file*/
void my_sys_open(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    unusual_exit(-1);
  }
  struct thread *current=thread_current();
  const char *name=(char *)*((int *)f->esp+1);
  if(name==NULL){
    f->eax=-1;
    unusual_exit(-1);
  }
  //struct file_point *filea=(struct file_point*)malloc(sizeof(struct file_point));
  struct file_point *filea = malloc(sizeof * filea );
  lock_acquire(&file_lock);
  filea->ff=filesys_open(name);
  if(filea->ff==NULL){
    f->eax=-1;
    free(filea);
  }else{
    filea->fd=current->fd_max;
    current->fd_max++;
    f->eax=filea->fd;
    current->number_of_file++;
    list_push_back(&current->list_of_files,&filea->elem);
  }
  lock_release(&file_lock);
}

/*sys_call to return the size of a file*/
void my_sys_filesize(struct intr_frame *f){
  if(!is_user_vaddr(((int*)f->esp)+2)){
    unusual_exit(-1);
  }
  struct thread *current =thread_current();
  int fd=*((int*)f->esp+1);
  struct file* filea=getfile(current,fd);
  if(filea==NULL){
    f->eax=-1;
    return;
  }
  lock_acquire(&file_lock);
  f->eax=file_length(filea);
  lock_release(&file_lock);
}

/*sys_call to read things from a file, and save the content in buffer*/
void my_sys_read(struct intr_frame *f){
  int *esp=(int *)f->esp;
  if(!is_user_vaddr(esp+7)){
    unusual_exit(-1);
  }
  int fd=*(esp+1);
  uint8_t *buffer=(uint8_t*)*(esp+6);
  unsigned size=*(esp+3);

  if(buffer==NULL||!is_user_vaddr(buffer+size)){
    f->eax=-1;
    unusual_exit(-1);
  }
  struct thread *current = thread_current();

  int bytes_read = 0;

  struct file *filea=getfile(current,fd);
  if(filea == NULL){
    unusual_exit(-1);
  }
  while (size > 0){
    size_t page_left = PGSIZE - pg_ofs (buffer);
    size_t read_amt = size < page_left ? size : page_left;
    off_t retval;

    if (fd != STDIN_FILENO){
      if (!page_lock (buffer, true)){
        thread_exit ();
      }
      lock_acquire (&file_lock);
      retval = file_read (filea, buffer, read_amt);
      lock_release (&file_lock);
      page_unlock (buffer);
    }else{
      size_t i;

      for (i = 0; i < read_amt; i++){
        char c = input_getc ();
        if (!page_lock (buffer, true))
          thread_exit ();
        buffer[i] = c;
        page_unlock (buffer);
      }
      bytes_read = read_amt;
    }

    if (retval < 0){
      if (bytes_read == 0)
        bytes_read = -1;
      break;
    }
    bytes_read += retval;
    if (retval != (off_t) read_amt){
      break;
    }
    buffer += retval;
    size -= retval;
  }
  f->eax=bytes_read;
}

/*sys_call to write things in buffer to eax*/
void my_sys_write(struct intr_frame *f){
  int *esp=(int *)f->esp;
  if(!is_user_vaddr(esp+7)){
    unusual_exit(-1);
  }
  int fd=*(esp+1);
  uint8_t *buffer=(uint8_t*)*(esp+6);
  unsigned size=*(esp+3);
  struct thread *current = thread_current();

  int bytes_written = 0;
  struct file *filea=getfile(current,fd);
  if(fd != STDOUT_FILENO){
    if(filea == NULL){
      unusual_exit(-1);
    }
  }
  while (size > 0){
    size_t page_left = PGSIZE - pg_ofs (buffer);
    size_t write_amt = size < page_left ? size : page_left;
    off_t retval;
    if (!page_lock (buffer, false)){
      thread_exit ();
    }
    lock_acquire (&file_lock);
    if (fd == STDOUT_FILENO){
      putbuf ((char *) buffer, write_amt);
      retval = write_amt;
    }else{
      retval = file_write (filea, buffer, write_amt);
    }
    lock_release (&file_lock);
    page_unlock (buffer);
    if (retval < 0){
      if (bytes_written == 0){
        bytes_written = -1;
      }
      break;
    }
    bytes_written += retval;
    if (retval != (off_t) write_amt){
      break;
    }
    buffer += retval;
    size -= retval;
  }
  f->eax=bytes_written;
}

/*sys_call to change the position to execute*/
void my_sys_seek(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+6)){
    unusual_exit(-1);
  }
  int fd=*((int *)f->esp+4);
  struct file *filea=getfile(thread_current(),fd);

  lock_acquire(&file_lock);
  file_seek(filea,*((unsigned int*)f->esp+5));
  lock_release(&file_lock);
}

/*sys_call to find the position to execute in a open file*/
void my_sys_tell(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    unusual_exit(-1);
  }
  int fd=*((int *)f->esp+1);
  struct file *filea=getfile(thread_current(),fd);
  if(filea==NULL){
    f->eax=-1;
    unusual_exit(-1);
  }
  lock_acquire(&file_lock);
  f->eax=file_tell(filea);
  lock_release(&file_lock);
}

/*sys_call to close an open file*/
void my_sys_close(struct intr_frame *f){
  if(!is_user_vaddr(((int*)f->esp)+2)){
    unusual_exit(-1);
  }
  f->eax=close_f(thread_current(),*((int *)f->esp+1),false);
}

/*use a bool to choose close one file or close all file*/
int close_f(struct thread * t,int fd,int close_all){
  struct list_elem *e;
  /*To close all the file that a thread has open when the thread is about to leave*/
  if(close_all){
    while(!list_empty(&t->list_of_files)){
      struct file_point *filea = list_entry(list_pop_front(&t->list_of_files),struct file_point,elem);
      lock_acquire(&file_lock);
      file_close(filea->ff);
      lock_release(&file_lock);
      free(filea);
    }
    t->number_of_file=0;
    return 0;
  }
  /*Find the particular file the thread has open and close it*/
  for (e=list_begin(&t->list_of_files);e!=list_end(&t->list_of_files);e=list_next(e)){
    struct file_point *filea=list_entry(e,struct file_point,elem);
    if(filea->fd==fd){
      list_remove(e);
      t->number_of_file--;
      file_close(filea->ff);
      free(filea);
      return 0;
    }
  }
  return 0;
}

void my_sys_mmap(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+6)){
    unusual_exit(-1);
  }
  int fd=*((int *)f->esp+4);
  void * addr =(const char *)*((unsigned int *)f->esp+5);
  struct file *filea=getfile(thread_current(),fd);

  struct mapping *m=malloc(sizeof *m);
  size_t offset;
  off_t length;
  if (m==NULL || addr ==NULL || pg_ofs(addr) != 0){
    f->eax=-1;
    return;
  }

  m->fd = thread_current()->fd_max;
  thread_current()->fd_max++;
  lock_acquire(&file_lock);
  m->file = file_reopen(filea);
  lock_release(&file_lock);
  if(m->file == NULL){
    free(m);
    f->eax=-1;
    return;//p3 ??????????????????
  }
  m->base = addr;
  m->number = 0;
  list_push_front(&thread_current()->mappings,&m->elem);

  offset=0;
  lock_acquire(&file_lock);
  length = file_length(m->file);
  lock_release(&file_lock);
  while((length)>0){
    struct page *p = page_allocate((uint8_t *)addr + offset,false);
    if(p==NULL){
      unmap(m);
      f->eax=-1;
      return;//p3  ??????????????????
    }
    p->private = false;
    p->file = m->file;
    p->file_offset = offset;
    p->file_bytes = length >= PGSIZE ? PGSIZE : length;
    offset += p->file_bytes;
    length -= p->file_bytes;
    m->number++;
  }
  f->eax=m->fd;
}

void my_sys_munmap(struct intr_frame *f){
  if(!is_user_vaddr(((int*)f->esp)+2)){
    unusual_exit(-1);
  }
  int mapping=*((int*)f->esp+1);
  struct mapping *map=lookup_mapping(mapping);
  unmap(map);
  f->eax=0;
}


/* On thread exit, close all open files and unmap all mappings. */
void
syscall_exit (void)
{
  struct thread *cur = thread_current ();
  struct list_elem *e, *next;

  for (e = list_begin (&cur->list_of_files); e != list_end (&cur->list_of_files); e = next)
    {
      struct file_point *fd = list_entry (e, struct file_point, elem);
      next = list_next (e);
      lock_acquire (&file_lock);
      file_close (fd->ff);
      lock_release (&file_lock);
      free (fd);
    }

  for (e = list_begin (&cur->mappings); e != list_end (&cur->mappings);
       e = next)
    {
      struct mapping *m = list_entry (e, struct mapping, elem);
      next = list_next (e);
      unmap (m);
    }
}


/*Given a thread th and a fd, looking for the file that have the
corresponding fd, then return the file*/
struct file* getfile(struct thread *th,int fd){
  for(struct list_elem *ele=list_begin(&th->list_of_files);ele !=list_end(&th->list_of_files);ele=list_next(ele)){
    struct file_point *filea=list_entry(ele,struct file_point,elem);
    if(filea->fd==fd){
      if(filea->ff != NULL){
        return filea->ff;
      }
    }
  }
  return NULL;
}