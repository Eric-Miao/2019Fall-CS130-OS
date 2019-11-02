#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/syscall-nr.h"
#include "lib/kernel/list.h"
#include "lib/kernel/stdio.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "process.h"
#include "pagedir.h"


static void syscall_handler (struct intr_frame *);

/* To keep consistency of variable type. */
typedef int pid_t;

/* implemented syscall*/
static void sys_halt (void);
static void sys_exit (int status);
static pid_t sys_exec (const char *file);
static int sys_wait (pid_t);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned length);
static int sys_write (int fd, const void *buffer, unsigned length);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);

static uint32_t *get_arg (const uint32_t*, int);
static void is_vaddr (const void* );
static struct loaded_file * search_file (int);
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  uint32_t *esp = f->esp;
  uint32_t exit_status;
  uint32_t size;
  uint32_t *command;
  uint32_t *file;
  int int_ret;
  int fd;
  int syscall_no;
  bool bool_ret;
  pid_t pid;

  is_vaddr (esp);

  syscall_no = (int) *esp;

  switch (syscall_no)
  {
    /* Halt the operating system. */
    case SYS_HALT:
      sys_halt ();
      break;
    /* finished */

    /* Terminate this process. */     
    case SYS_EXIT:
      is_vaddr (esp+1);
      sys_exit (*(esp+1));
      break;
    /* finished */

    /* Start another process. */            
    case SYS_EXEC:
      is_vaddr (esp+1);
      is_vaddr (*(esp+1));
      f->eax = sys_exec ((char*)*(esp+1));
      break;
    /* finished */
    
    /* Wait for a child process to die. */      
    case SYS_WAIT:   
      is_vaddr (esp+1);    
      pid = *(esp+1);
      int_ret = sys_wait(pid);
      f->eax = int_ret;
      break;
    /* Create a file. */      
    case SYS_CREATE:      
      is_vaddr (esp+1);
      is_vaddr (*(esp+1));
      is_vaddr (esp+2);
      file = *(esp+1);
      size = *(esp+2);
      bool_ret = sys_create ((char *) file, size);
      f->eax = bool_ret;
      break;
    /* finished */

    /* Delete a file. */   
    case SYS_REMOVE: 
      is_vaddr (esp+1);
      is_vaddr (*(esp+1));
      file = *(esp+1);
      bool_ret = sys_remove ((char *) file);
      f->eax = bool_ret;
      break;
      
    /* Open a file. */                
    case SYS_OPEN:   
      is_vaddr (esp+1);
      is_vaddr (*(esp+1));
      file = *(esp+1);
      int_ret = sys_open ((char *) file);      
      f->eax = int_ret;
      break;
    /* finished */
    
    /* Obtain a file's size. */        
    case SYS_FILESIZE:    
      is_vaddr (esp+1);      
      fd = *(esp+1);
      f->eax = sys_filesize (fd);
      break;         
    /* finished */

    /* Read from a file. */  
    case SYS_READ:    
      is_vaddr (esp+1);      
      is_vaddr (esp+2);
      is_vaddr (*(esp+2));
      is_vaddr (esp+3);

      fd = *(esp+1);
      void* buffer1 = *(esp+2);
      size = *(esp+3);

      int_ret = sys_read (fd, buffer1, size);

      f->eax = int_ret;
      break;
    /* finished */
    
    /* Write to a file. */               
    case SYS_WRITE:            
      is_vaddr (esp+1);      
      is_vaddr (esp+2);
      is_vaddr (*(esp+2));
      is_vaddr (esp+3);

      fd = *(esp+1);
      void* buffer2 = *(esp+2);
      size = *(esp+3);
      int_ret = sys_write (fd, buffer2, size);

      f->eax = int_ret;
      break;

    /* Change position in a file. */      
    case SYS_SEEK:
      is_vaddr (esp+1);      
      is_vaddr (esp+2);
      fd = *(esp+1);
      size = *(esp+2);
      sys_seek (fd, size);
      break;
    /* finished */

    /* Report current position in a file. */                  
    case SYS_TELL:
      is_vaddr (esp+1);      
      fd = *(esp+1);
      f->eax = sys_tell (fd);
      break;         
    /* finished */

    /* Close a file. */                  
    case SYS_CLOSE:  
      is_vaddr (esp+1);      
      fd = *(esp+1);
      sys_close (fd);            
      break;
    /* finished */

    default:
      sys_exit(-1);
      break;
  }
}

/* Terminates Pintos by calling shutdown_power_off().*/
static void 
sys_halt (void)
{
  shutdown_power_off ();
}

/* Terminates the current user program, returning status to the kernel. */
static void 
sys_exit (int status)
{
  /* waiting to set the exit status of current thread. */
  struct thread *cur  = thread_current ();

  cur->exit_status = status;
  thread_exit();
}

static pid_t 
sys_exec (const char *file)
{
  return process_execute (file);
}

static int 
sys_wait (pid_t pid)
{
  return process_wait(pid);
}

static bool 
sys_create (const char *file, unsigned initial_size)
{
  //printf("\n syscall create.\n\n");
  acquire_lock_file ();
  return filesys_create(file, initial_size);
  //printf("\n syscall create2.\n\n");
  release_lock_file ();

}

static bool 
sys_remove (const char *file)
{
  bool ret;
  acquire_lock_file ();
  ret = filesys_remove (file);
  release_lock_file ();
  return ret;
}


static int 
sys_open (const char *file)
{
  acquire_lock_file ();
  struct file *target_file = filesys_open((const char *)file);
  release_lock_file ();
  if (!target_file)
  {
    return -1;
  }

  struct loaded_file *opened_file = (struct loaded_file *)malloc(sizeof(struct loaded_file));
  thread_current()->cur_fd ++;
  opened_file->fd = thread_current()->cur_fd;
  opened_file->file = target_file;
  list_push_back (&thread_current()->file_list,&opened_file->file_elem);
  
  return opened_file->fd;

}

static int 
sys_filesize (int fd)
{
  struct loaded_file *target =NULL;
  int ret;

  if ((fd == 0) || (fd == 1))
    sys_exit (-1);

  target = search_file (fd);
  if (fd == target->fd)
  {
    acquire_lock_file ();
    ret = file_length(target->file);
    release_lock_file ();
  }
  else
    ret = -1;
  return ret;
}

static int 
sys_read (int fd, void *buffer, unsigned length)
{
  struct loaded_file *target =NULL;
  int ret = -1;
  uint8_t *_buffer = buffer;

  if (fd == 0)
  {
    /* Read from Keyboard. */
    for (int i = 0; i < length; i++)
    {
      _buffer [i] = input_getc();
    }
    ret = length;
  }
  else
  {
    target = search_file (fd);
    if (target)
    {
      acquire_lock_file ();
      ret = file_read(target->file, buffer, length);
      release_lock_file ();
    }
    else
      ret = -1;
    }
  return ret;
}

static int 
sys_write (int fd, const void *buffer, unsigned length)
{
  struct loaded_file *target =NULL;
  int ret;

  if (fd == 1)
  {
    /* Write to Console. */
    putbuf(buffer, length);
    ret = length;
  }
  else
  {
    target = search_file (fd);
    if (target)
    {
      acquire_lock_file ();
      ret = file_write(target->file, buffer, length);
      release_lock_file ();
    }
    else
      ret = 0;
  }
  return ret;
}

static void 
sys_seek (int fd, unsigned position)
{
  struct loaded_file *target =NULL;

  if ((fd == 0) || (fd == 1))
    sys_exit (-1);

  target = search_file (fd);
  if(target)  
  {
    acquire_lock_file ();
    file_seek(target->file, position);
    release_lock_file ();
  }    
}

static unsigned 
sys_tell (int fd)
{
  struct loaded_file *target =NULL;
  int ret;

  if ((fd == 0) || (fd == 1))
    sys_exit (-1);

  target = search_file (fd);
  if (target)
  {
    acquire_lock_file ();
    ret = file_tell(target->file);
    release_lock_file ();
  }
  else
    ret = -1;
  return ret;
}

static void 
sys_close (int fd)
{
  struct loaded_file *target =NULL;

  if ((fd == 0) || (fd == 1))
    sys_exit (-1);

  target = search_file (fd);
  if(target)
  {    
    acquire_lock_file ();
    file_close(target->file);
    release_lock_file ();
    list_remove (&target->file_elem);
    free(target);
  }
}

static void
is_vaddr (const void* vaddr)
{
  if (vaddr == NULL)
    sys_exit (-1);
  
  if (!is_user_vaddr (vaddr))
    sys_exit (-1);
  
  if (!is_user_vaddr (vaddr+4))
    sys_exit (-1);

  if (!pagedir_get_page (thread_current ()->pagedir, vaddr))
    sys_exit (-1);
  
  return true;
}

/* Check and return the no.offset argument */
static uint32_t *
get_arg (const uint32_t* p, int offset)
{
  is_vaddr (p);

  p += (offset);

  is_vaddr (p);


  return p;
}

static struct loaded_file * 
search_file (int fd)
{
  struct thread* t = thread_current ();
  struct list *files = &t->file_list;
  struct list_elem *e;
  struct loaded_file *target =NULL;

  for (e = list_begin (files); e != list_end (files); e = list_next (e)){
    target = list_entry (e, struct loaded_file, file_elem);
    if (fd == target->fd)
      return target;
  }
  return false;
}