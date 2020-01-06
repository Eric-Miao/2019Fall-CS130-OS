#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <stdint.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h" 
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "vm/frame.h"
#include "vm/page.h"

#define STACK_MAX ((void *) (1 << 23)) /* Max stack is 8MB. */
#define LOW_USER_BASE ((void *) 0x08048000)

static void syscall_handler (struct intr_frame *);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static void check_user_read (const uint8_t *vaddr, size_t size);
static void check_user_write (uint8_t *vaddr, size_t size);
static inline void* get_arg (void *sp, int n);
static void check_user_str (const char *str);

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* check all buffer data vaddr points to can be read. */
static void
check_user_read (const uint8_t *vaddr, size_t size)
{	
  if (size <= 0) return;

  /* First check pointer is in user memory space. */
  if ((vaddr + size - 1) >= (const uint8_t *) PHYS_BASE ||
       vaddr <= (const uint8_t *) LOW_USER_BASE || get_user (vaddr) == -1)
    exit (EXIT_ERROR);

  /* Check the first byte of each page. */
  uint32_t page;
  for (page = (uint32_t)vaddr / PGSIZE + 1 ; 
       page <= (uint32_t)(vaddr + size - 1) / PGSIZE ; page++)
  {
    if (get_user ((const uint8_t *)(page * PGSIZE)) == -1)
    {
      exit (EXIT_ERROR);
    }
  }
  return;
}

/* Check all buffer data vaddr points to can be written. */
static void
check_user_write (uint8_t *vaddr, size_t size)
{ 
  if (size <= 0) return;
  /* First check pointer is in user memory space. */
  if ((vaddr + size - 1) >= (uint8_t *) PHYS_BASE ||
       vaddr <= (uint8_t *) LOW_USER_BASE || !(get_user (vaddr) != -1 && put_user (vaddr, get_user (vaddr)) == true))
    exit (EXIT_ERROR);

  /* Check the first byte of each page. */
  uint32_t page;
  for (page = (uint32_t)vaddr / PGSIZE ; 
       page <= (uint32_t)(vaddr + size - 1) / PGSIZE ; page++)
  {
    int result = get_user ((uint8_t *)(page * PGSIZE));
    if (!(result != -1 && put_user ((uint8_t *)(page * PGSIZE), result) == true))
    {
      exit (EXIT_ERROR);
    }
  }
  return;
}

/* Check the string is legal or not .*/ 
static void
check_user_str (const char *str)
{
  int result;
  while (1)
  {
    if( str >= (const char *) PHYS_BASE || str <= (const char *) LOW_USER_BASE || 
    	(result = get_user ((const uint8_t *) str)) == -1)
      exit (EXIT_ERROR);
    else if ((char) result == '\0')
      return;
    str++;
  }
  return;
}

/* Get data from stack. */
static inline void*
get_arg (void *sp, int n)
{ 
  /* Align 4. */
  void *tmp = (uint8_t *)sp + (n << 2);
  check_user_read ((const uint8_t *) tmp, 4);
  return tmp;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
#ifdef VM
  thread_current()->saved_esp = f->esp;
#endif
  void *sp = (void *) f->esp;
  check_user_read (sp, 4); /* First check esp. */
  /* Will check every argument before entering function. */
  switch (* (int *) sp)
  {
    case SYS_HALT:
    {
      halt (); 
      break;
    }
    case SYS_EXIT:
    {
      int status = * (int *) get_arg (sp, 1);
      exit (status);
	    break;
    }
    case SYS_EXEC:
    {
      const char *file = * (const char **) get_arg (sp, 1);
      check_user_str (file);
	    f->eax = (uint32_t) exec (file); 
      break;
    }
    case SYS_WAIT:
    {
      pid_t id = * (pid_t *) get_arg (sp, 1);
      f->eax = (uint32_t) wait(id);
      break;
    }
    case SYS_CREATE:
    {
      const char *file = * (const char **) get_arg (sp, 1);
      check_user_str (file);
      unsigned initial_size = * (unsigned *) get_arg (sp, 2);
      f->eax = create (file, initial_size);
      break;
    }
    case SYS_REMOVE:
    {
      const char *file = * (const char **) get_arg (sp, 1);
      check_user_str (file);
      f->eax = remove (file);
      break;
    }
    case SYS_OPEN:
    {
      const char *file = * (const char **) get_arg (sp, 1);
      check_user_str (file);
      f->eax = open (file);
      break;
    }
    case SYS_FILESIZE:
    {
      int fd = * (int *) get_arg (sp, 1);
      f->eax = filesize (fd);
      break;
    }
    case SYS_READ:
    {
      int fd = * (int *) get_arg (sp, 1);
      uint8_t* buffer = * (uint8_t **) get_arg (sp, 2);
      unsigned length = * (unsigned *) get_arg (sp, 3);
      check_user_write (buffer, (size_t) length);
      f->eax = read (fd, buffer, length);
      break;
    }
    case SYS_WRITE:
    {
      int fd = * (int *) get_arg (sp, 1);
      const uint8_t* buffer =  * (const uint8_t**) get_arg (sp, 2);
      unsigned length = * (unsigned *) get_arg (sp, 3);
      check_user_read (buffer, (size_t) length);
      f->eax = write (fd, buffer, length);
      break;
    }
    case SYS_SEEK:
    {
      int fd = * (int *) get_arg (sp, 1);
      unsigned position = * (unsigned *) get_arg (sp, 2);
      seek (fd, position);
      break;
    }
    case SYS_TELL:
    {
      int fd = * (int *) get_arg (sp, 1);
      f->eax = tell (fd);
      break;
    }
    case SYS_CLOSE:
    {
      int fd = * (int *) get_arg (sp, 1);
      close (fd);
      break;
    }
    case SYS_MMAP:
    {
      int fd = * (int *) get_arg (sp, 1);
      void* addr = * (void **) get_arg (sp, 2);
      f->eax = mmap(fd, addr);
      break;
    }
    case SYS_MUNMAP:
    {
      mapid_t id = * (mapid_t *) get_arg (sp, 1);
      munmap(id);
      break;
    }
    case SYS_CHDIR:
    {
      const char *dir = * (const char **) get_arg (sp, 1);
      check_user_str (dir);
      f->eax = chdir(dir);
      break;
    }
    case SYS_MKDIR:
    {
      const char *dir = * (const char **) get_arg (sp, 1);
      check_user_str (dir);
      f->eax = mkdir(dir);
      break;
    }
    case SYS_READDIR:
    {
      int fd = * (int *) get_arg (sp, 1);
      char *dir = * (char **) get_arg (sp, 2);
      check_user_str (dir);
      f->eax = readdir(fd, dir);
      break;
    }
    case SYS_ISDIR:
    {
      int fd = * (int *) get_arg (sp, 1);
      f->eax = isdir(fd);
      break;
    }
    case SYS_INUMBER:
    {
      int fd = * (int *) get_arg (sp, 1);
      f->eax = inumber(fd);
      break;
    }
  }
}

void 
halt (void)
{
  shutdown_power_off ();
}

void 
exit (int status)
{ 
  thread_current ()->exit_status = status;
  thread_current ()->process->exit_status = status;
  thread_exit (); 
}

pid_t 
exec (const char *file)
{ 
  tid_t id = process_execute (file);
  return (id == TID_ERROR) ? PID_ERROR : id;
}

int 
wait (pid_t pid)
{ 
  return process_wait (pid); 
}

bool 
create (const char *file, unsigned initial_size)
{ 
  int success = filesys_create (file, initial_size, false);
  return success;
}

bool 
remove (const char *file)
{ 
  int success = filesys_remove (file);
  return success;
}

/* add file to the file list of current thread */
static int
add_file (struct file *f)
{
  if (f == NULL)
    return -1;
  struct thread *t = thread_current ();
  struct process_file *pf = malloc (sizeof (struct process_file));
  if (!pf)
    return -1;
  pf->file = f;
  pf->dir = NULL;
  pf->fd = t->fd;
  t->fd++;
  list_push_back (&t->file_list, &pf->elem);
  return pf->fd;
}

/* add directory to the file list of current thread */
static int
add_directory (struct dir *dir)
{
  if (dir == NULL)
    return -1;
  struct thread *t = thread_current ();
  struct process_file *pf = malloc (sizeof (struct process_file));
  if (!pf)
    return -1;
  pf->file = NULL;
  pf->dir = dir;
  pf->fd = t->fd;
  t->fd++;
  list_push_back (&t->file_list, &pf->elem);
  return pf->fd;
}

/* return file based on the given fd */
static struct process_file* 
get_process_file (int fd)
{	
  struct thread *t = thread_current ();
  struct list_elem *e;
  struct process_file *pf;
  for (e = list_begin (&t->file_list); e != list_end (&t->file_list) ; e = list_next (e))
  {
    pf = list_entry (e, struct process_file, elem);
    if (pf->fd == fd)
      return pf;
  }
  return NULL;
}

int 
open (const char *file)
{ 
  int fd;
  struct inode *inode = filesys_open (file);
  if (inode == NULL)
  {
    return -1;
  }
  else
  {
    if (!inode_is_dir(inode))
      fd = add_file(file_open(inode));
    else
      fd = add_directory(dir_open(inode));
  }
  return fd;
}

int 
filesize (int fd)
{ 
  struct process_file *pf = get_process_file (fd);
  if (pf == NULL)
    return -1;
  if (pf->file == NULL)
    return -1;
  int len = file_length (pf->file);
  return len;
}

int 
read (int fd, void *buffer, unsigned length)
{ 
  char* buf = (char *) buffer;
  unsigned i = 0;

  if (fd == STDIN_FILENO)
  {
    for (i = 0; i < length; i++) 
    {
      buf[i] = input_getc();
    }
    return length;
  }
  struct process_file *pf = get_process_file (fd);
  if (pf == NULL)
    return -1;
  if (pf->file == NULL)
    return -1;

  int bytes = file_read(pf->file, buffer, length);
  return bytes;
}

int 
write (int fd, const void *buffer, unsigned length)
{ 
  if (fd == STDOUT_FILENO)
  {
    putbuf (buffer, length);
    return length;
  }

  struct process_file *pf = get_process_file (fd);
  if (pf == NULL)
    return -1;
  if (pf->file == NULL)
    return -1;

  int bytes = file_write(pf->file, buffer, length);
  return bytes;
}

void 
seek (int fd, unsigned position)
{ 
  struct process_file *pf = get_process_file (fd);
  if (pf == NULL)
    return;
  if (pf->file == NULL)
    return;

  file_seek(pf->file, position);
  return;
}

unsigned 
tell (int fd)
{ 
  struct process_file *pf = get_process_file (fd);
  if (pf == NULL)
    return -1;
  if (pf->file == NULL)
    return -1;

  unsigned result = file_tell (pf->file);
  return result;
}

void 
close (int fd)
{ 
  struct thread *t = thread_current();
  struct list_elem *e;
  struct process_file *pf;
  for (e = list_begin (&t->file_list);
       e != list_end (&t->file_list) ; e = list_next (e))
  {
  	pf = list_entry (e, struct process_file, elem);
  	if (pf->fd == fd) 
  	{
      file_close (pf->file);
      dir_close(pf->dir);
      list_remove (&pf->elem);
      free (pf);
      return;
  	}
  }
  return;
}

/* Close all the files that current thread has. */
void 
close_all (void)
{ 
  struct thread *t = thread_current ();
  struct list_elem *e = list_begin (&t->file_list);
  struct list_elem *next;
  struct process_file *pf;

  while(e != list_end (&t->file_list))
  { 
  	next = list_next (e);
  	pf = list_entry (e, struct process_file, elem);
  	file_close (pf->file);
    dir_close(pf->dir);
    list_remove (&pf->elem);
    free (pf);
    e = next;
  }
  
  return;
}

/* Mmap system call. */
mapid_t mmap (int fd, void *addr)
{
  struct process_file *pf = get_process_file (fd);
  if (pf == NULL)
    return -1;
  if (pf->file == NULL)
    return -1;
  struct thread *t = thread_current();
  
  /* Check fd and file pointer .*/
  if (fd == 1 || fd == 0)
    return -1;

  /* Check addr .*/
  if (addr >= (void *) (PHYS_BASE - STACK_MAX) || addr <= (void*) LOW_USER_BASE 
      || ((int)addr) % PGSIZE != 0 || ((int) addr) == 0)
    return -1;

  struct mmap_file *mmap = malloc (sizeof (struct mmap_file));
  if (mmap == NULL)
    return -1;

  /* Obtain a separate and independent reference to the file. */
  mmap->file = file_reopen (pf->file);
  size_t read_bytes = file_length (mmap->file);

  if ((mmap->file == NULL) || read_bytes == 0)
  {
    free (mmap);
    return -1;
  }

  mmap->addr = addr;
  mmap->page_cnt = 0;

  t->map_files++;
  mmap->mapid = t->map_files;
  list_push_back (&t->mmap_list, &mmap->elem);
  
  int32_t ofs = 0;
  while (read_bytes > 0) 
  {
    /* Calculate how to fill this page.
    We will read PAGE_READ_BYTES bytes from FILE
    and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;

    if (spt_add (VM_MMAP_TYPE, addr, true, mmap->file, ofs, page_read_bytes))
    {
      /* Successfully allocate a supplemental page table entry. */
      struct spt_entry *spe = spt_get (addr);
      ASSERT (spe != NULL);
      mmap->page_cnt++;

      /* Advance. */
      read_bytes -= page_read_bytes;
      addr += PGSIZE;
      ofs += page_read_bytes;
    }
    else
    { 
      /* Fail to allocate a supplemental page table entry. */
      /* Must clear all the mmap_file and supplemental page table 
         entry related to this file allocated previously. */ 
      munmap (mmap->mapid);
      return -1;
    }
  }
  
  return mmap->mapid;
}

/* Munmap system call. */ 
void munmap (mapid_t mapping)
{
  struct thread *t = thread_current ();
  struct list_elem *e = list_begin (&t->mmap_list);
  struct list_elem *next;
  struct mmap_file *mmap;

  while(e != list_end (&t->mmap_list))
  { 
    next = list_next (e);
    mmap = list_entry (e, struct mmap_file, elem);
    if (mmap->mapid == mapping)
    {
      list_remove (&mmap->elem);
      while (mmap->page_cnt-- > 0)
      {
        struct spt_entry *spe = spt_get (mmap->addr);
        ASSERT (spe != NULL);
        /* Must acquire frame lock first to avoid race. */
        spt_lock_frame (spe);
        if (spe->fte != NULL)
        {
          pagedir_clear_page (t->pagedir, spe->u_addr);
          if (pagedir_is_dirty (t->pagedir, spe->u_addr))
          {
            /* The page needs to be written back if it has been modified. */ 
            file_write_at (spe->file, spe->fte->k_addr, spe->file_bytes, spe->ofs);
          }
          frame_release_and_free (spe->fte);
        }
        hash_delete (&t->spt_table, &spe->elem);
        free (spe);
        mmap->addr += PGSIZE;
      }
      file_close (mmap->file);
      free (mmap);
      return;
    }
    e = next;
  }

  return;
}

/* Unmap all the mmap the process holds. */
/* Called when process exits. */
void close_all_mmap(void)
{
  struct thread *t = thread_current ();
  struct list_elem *e = list_begin (&t->mmap_list);
  struct list_elem *next;
  struct mmap_file *mmap;

  while(e != list_end (&t->mmap_list))
  { 
    next = list_next (e);
    mmap = list_entry (e, struct mmap_file, elem);
    munmap (mmap->mapid);
    e = next;
  }
  return;
}


bool chdir (const char *dir)
{
  return filesys_chdir(dir);
}

bool mkdir (const char *dir)
{
  return filesys_create(dir, 0, true);
}

bool readdir (int fd, char *name)
{
  struct process_file *pf = get_process_file (fd);
  return dir_readdir(pf->dir, name);
}

bool isdir (int fd)
{
  struct process_file *pf = get_process_file (fd);
  return (pf->dir != NULL);
}

int inumber (int fd)
{
  struct process_file *pf = get_process_file (fd);
  struct inode *inode = NULL;
  if (pf == NULL)
    return -1;
  if (pf->dir != NULL)
  {
    inode = dir_get_inode(pf->dir);
  }
  else
  {
    inode = file_get_inode(pf->file);
  }
  if (inode == NULL)
    return -1;
  return inode_get_inumber(inode);
}
