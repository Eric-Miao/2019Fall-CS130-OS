#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/init.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "vm/page.h"
#include "vm/frame.h"
#define ARGS 3
#define STACK_MAX (1024 * 1024)
static void syscall_handler(struct intr_frame *);

/*lock on accessing the file system*/
struct lock lock_f;
void get_args(struct intr_frame *f, int *args, int num);
/*Struct that combines file with its descriptor and put in current thread's file descriptor list*/
struct file_to_fd
{
  int f_des;               /*file descriptor*/
  struct file *f_addr_ptr; /*file address*/
  struct list_elem f_list; /*fd list of thread*/
};
/*function that get the arguments behind syscall from stack*/
void get_args(struct intr_frame *f, int *args, int num)
{
  int *temp;
  int i = 0;
  for (; i < num; i++)
  {
    temp = (int *)f->esp + i + 1;
    /*check the validity*/
    if (!is_user_vaddr((const void *)temp) || (const void *)temp == NULL || (const void *)temp < (void *)0x08048000)
    {
      exit(-1);
    }
    /*store to the arg array we created before*/
    args[i] = *temp;
  }
}

/*check the validity of given buffer*/
void is_buffer_valid(void *buffer, unsigned size)
{
  char *temp = (char *)buffer;
  unsigned i = 0;
  for (; i < size; i++)
  {
    /*check the validity*/
    if (!is_user_vaddr((const void *)temp) || (const void *)temp == NULL || (const void *)temp < (void *)0x08048000)
    {
      exit(-1);
    }
    temp++;
  }
}

void syscall_init(void)
{
  /*initialize the file system lock*/
  lock_init(&lock_f);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*check "interrupt.h" to see the defination of struct intr_frame*/
static void
syscall_handler(struct intr_frame *f UNUSED)
{
  /*store the arguement after syscall*/
  int args[ARGS];
  /*store the physical page pointer*/
  void *physical_page;
  /*transfer void pointer esp to const void to use is_user_vaddr()*/
  /*check if the user address is valid and not in virtural address space*/
  if (!is_user_vaddr((const void *)f->esp) || !is_user_vaddr((const void *)(f->esp + 1)) || !is_user_vaddr((const void *)(f->esp + 2)) || !is_user_vaddr((const void *)(f->esp + 3)) || (const void *)f->esp == NULL || (const void *)f->esp < (void *)0x08048000)
  {
    /*terminate the program and free its resources */
    exit(-1);
  }
  /*if syscall is halt then call it*/
  if (*(int *)f->esp == SYS_HALT)
  {
    halt();
  }
  /*if syscall is exit*/
  if (*(int *)f->esp == SYS_EXIT)
  {
    /*get the exit status*/
    get_args(f, &args[0], 1);
    /*call exit()*/
    exit(args[0]);
  }
  /*if syscall is exec*/
  if (*(int *)f->esp == SYS_EXEC)
  {
    /*get the command line*/
    get_args(f, &args[0], 1);
    struct thread *curr = thread_current();
    if (!is_user_vaddr((const void *)args[0]) || (const void *)args[0] == NULL || (const void *)args[0] < (void *)0x08048000 || (const void *)args[0] == (void *)0x0804efff)
    {
      /*terminate the program and free its resources */
      exit(-1);
    }

    /*store the return value of API function(exec() for now) in extended accumulator registor*/
    f->eax = exec((const char *)args[0]);
  }
  /*if syscall is wait*/
  if (*(int *)f->esp == SYS_WAIT)
  {
    /*get the PID of the child process that current process is going to wait for*/
    get_args(f, &args[0], 1);
    /*also store return in exa*/
    if ((pid_t)args[0] != -1)
    {
      f->eax = wait((pid_t)args[0]);
    }
    else
    {
      f->eax = -1;
    }
  }
  /*if syscall is create*/
  if (*(int *)f->esp == SYS_CREATE)
  {
    /*get the file name and its size*/
    get_args(f, &args[0], 2);
    /*check if the file buffer is valid*/
    is_buffer_valid((void *)args[0], args[1]);
    struct thread *curr = thread_current();
    /*check if the address is mapped to the physical address*/
    physical_page = pagedir_get_page(curr->pagedir, (const void *)args[0]);
    /*if not then terminate the program and free its resources*/
    if (physical_page == NULL)
    {
      exit(-1);
    }
    /*send physical page pointer back to args*/
    args[0] = (int)physical_page;
    /*store return in exa*/
    f->eax = create((const char *)args[0], (unsigned)args[1]);
  }
  /*if syscall is remove*/
  if (*(int *)f->esp == SYS_REMOVE)
  {
    /*get the name of file to be removed*/
    get_args(f, &args[0], 1);
    struct thread *curr = thread_current();
    /*store in exa*/
    f->eax = remove((const char *)args[0]);
  }
  /*if syscall is open*/
  if (*(int *)f->esp == SYS_OPEN)
  {
    /*get the name of file to be open*/
    get_args(f, &args[0], 1);
    struct thread *curr = thread_current();
    /*check if the address is mapped to the physical address*/
    physical_page = pagedir_get_page(curr->pagedir, (const void *)args[0]);
    /*if not then terminate the program and free its resources*/
    if (physical_page == NULL)
    {
      exit(-1);
    }
    /*store in exa*/
    f->eax = open((const char *)args[0]);
  }
  /*if syscall is filesize*/
  if (*(int *)f->esp == SYS_FILESIZE)
  {
    /*get the file descriptor(fd)*/
    get_args(f, &args[0], 1);
    /*store in exa*/
    f->eax = filesize(args[0]);
  }
  /*if syscall is read*/
  if (*(int *)f->esp == SYS_READ)
  {
    /*get file descriptor,buffer and buffer size*/
    get_args(f, &args[0], 3);
    /*check if the file buffer is valid*/
    is_buffer_valid((void *)args[1], args[2]);
    struct thread *curr = thread_current();
    /*check if the address is mapped to the physical address*/
    /*store in exa*/
    f->eax = read(args[0], (void *)args[1], (unsigned)args[2]);
  }
  /*if syscall is write*/
  if (*(int *)f->esp == SYS_WRITE)
  {
    /*get file descriptor,buffer and buffer size*/
    get_args(f, &args[0], 3);
    /*check if the file buffer is valid*/
    is_buffer_valid((void *)args[1], args[2]);
    struct thread *curr = thread_current();
    /*check if the address is mapped to the physical address*/
    /*send physical page pointer back to args*/
    /*store in exa*/
    f->eax = write(args[0], (const void *)args[1], (unsigned)args[2]);
  }
  /*if syscall is seek*/
  if (*(int *)f->esp == SYS_SEEK)
  {
    /*get file descriptor and position*/
    get_args(f, &args[0], 2);
    /*call seek()*/
    seek(args[0], (unsigned)args[1]);
  }
  /*if syscall is tell*/
  if (*(int *)f->esp == SYS_TELL)
  {
    /*get file descriptor*/
    get_args(f, &args[0], 1);
    /*store in exa*/
    f->eax = tell(args[0]);
  }
  /*if syscall is close*/
  if (*(int *)f->esp == SYS_CLOSE)
  {
    /*get file descriptor*/
    get_args(f, &args[0], 1);
    /*call close()*/
    close(args[0]);
  }
  if (*(int *)f->esp == SYS_MMAP)
  {
    /*get file descriptor and address*/
    int *temp;
    int i = 0;
    for (; i < 2; i++)
    {
      temp = (int *)f->esp + i + 1;
      /*check the validity*/
      /*store to the arg array we created before*/
      args[i] = *temp;
    }
    /*call mmap()*/
    f->eax = mmap(args[0], (void *)args[1]);
  }
  if (*(int *)f->esp == SYS_MUNMAP)
  {
    /*get map id*/
    get_args(f, &args[0], 1);
    /*call munmap()*/
    munmap(args[0]);
  }
  /*if it is an invalid system call*/
  if (*(int *)f->esp != SYS_HALT && *(int *)f->esp != SYS_EXIT && *(int *)f->esp != SYS_EXEC && *(int *)f->esp != SYS_WRITE && *(int *)f->esp != SYS_READ && *(int *)f->esp != SYS_OPEN && *(int *)f->esp != SYS_CLOSE && *(int *)f->esp != SYS_WAIT && *(int *)f->esp != SYS_CREATE && *(int *)f->esp != SYS_REMOVE && *(int *)f->esp != SYS_FILESIZE && *(int *)f->esp != SYS_SEEK && *(int *)f->esp != SYS_TELL && *(int *)f->esp != SYS_MMAP && *(int *)f->esp != SYS_MUNMAP)
  {
    /*terminate the program and free its resources */
    exit(-1);
  }
}

/*Shut PintOS down*/
void halt()
{
  /*see "device/shutdown.c" line 57 for detail*/
  shutdown_power_off();
}

/*clear the map*/
void unmap(struct map *m)
{
  struct thread *curr = thread_current();
  /*remove the map from the process' map list*/
  list_remove(&m->elem);
  int i = 0;
  /* For each page in the memory mapped file... */
  for (; i < m->page_count; i++)
  {
    /* ...determine whether or not the page is dirty (modified). If so, write that page back out to disk. */
    if (pagedir_is_dirty(curr->pagedir, ((const void *)((m->index) + (PGSIZE * i)))))
    {
      lock_acquire(&lock_f);
      file_write_at(m->file, (const void *)(m->index + (PGSIZE * i)), (PGSIZE * (m->page_count)), (PGSIZE * i));
      lock_release(&lock_f);
    }
  }
  int j = 0;
  /**/
  for (; j < m->page_count; j++)
  {
    page_eviction((void *)((m->index) + (PGSIZE * j)));
  }
}
/*sys call that terminates the current user program.
  and store its status in kernel*/
void exit(int status)
{
  /*store the status in kernel*/
  struct thread *curr = thread_current();
  curr->exitcode = status;
  /*call thread_exit() and in user program it will call
    process_exit() to terminate the process and print the
    exit status*/
  thread_exit();
}

/*Writes size bytes from buffer to the open file fd. Returns the number of bytes 
  actually written, which may be less than size if some bytes could not be written*/
int write(int fd, const void *buffer, unsigned size)
{
  struct list_elem *temp;
  int bytes_written = 0;
  unsigned buff_size = size;
  void *buff = buffer;
  while (buff != NULL)
  {
    if (buff != NULL && is_user_vaddr(buff))
    {
      if (pagedir_get_page(thread_current()->pagedir, buff) == NULL)
      {
        exit(-1);
      }
    }
    else
    {
      exit(-1);
    }
    
    if (buff_size > PGSIZE)
    {
      buff += PGSIZE;
      buff_size -= PGSIZE;
    }
    else if (buff_size == 0)
    {
      buff = NULL;
    }
    else
    {
      buff = buffer + size - 1;
      buff_size = 0;
    }
  }
  /*acquire the lock that ensure that only one process is writing on file system*/
  lock_acquire(&lock_f);
  /*if FD is i then write to console*/
  if (fd == 1)
  {
    /*see "lib/kernel/console.c" line 151 for detail of writing func*/
    putbuf(buffer, size);
    /*release the lock after writing*/
    lock_release(&lock_f);
    /*return size since it's writing to STDOUT*/
    return size;
  }
  struct thread *curr = thread_current();
  /*if it is STDIN or no file then return 0*/
  if (fd == 0 || list_empty(&curr->file_des))
  {
    /*release the lock since no writing*/
    lock_release(&lock_f);
    return -1;
  }
  /*get the current thread's fd*/
  temp = list_begin(&curr->file_des);
  while (temp != list_end(&curr->file_des))
  {
    /*store the file descriptor of current thread*/
    struct file_to_fd *thread_f = list_entry(temp, struct file_to_fd, f_list);
    /*search the fd and write*/
    if (thread_f->f_des == fd)
    {
      int bytes_written = (int)file_write(thread_f->f_addr_ptr, buffer, size);
      /*release the lock after write*/
      lock_release(&lock_f);
      /*return bytes be sucessfully written*/
      return bytes_written;
    }
    temp = list_next(temp);
  }
  /*release anyway before function end*/
  lock_release(&lock_f);
  /*return 0 if can't write*/
  return 0;
}

/*runs the executable whose name is given in cmd_line*/
int exec(const char *file)
{
  /*if the exec file is null*/
  if (file == NULL)
  {
    return -1;
  }
  /*declare a new variable to store file as a temp*/
  char *newfile = (char *)malloc(sizeof(char) * (strlen(file) + 1));
  memcpy(newfile, file, strlen(file) + 1);
  lock_acquire(&lock_f);
  /*run and get new process id*/
  pid_t child_tid = process_execute(newfile);
  lock_release(&lock_f);
  free(newfile);
  return child_tid;
}

/*waits for a child process pid and retrieves the child's exit status*/
int wait(pid_t PID)
{
  /*call process_wait() and return*/
  return process_wait(PID);
}

/*creates a new file called file initially initial_size bytes in size*/
bool create(const char *file, unsigned initial_size)
{
  lock_acquire(&lock_f);
  /*return true if successfully created*/
  bool success = filesys_create(file, initial_size);
  lock_release(&lock_f);
  return success;
}

/*deletes the file with given name*/
bool remove(const char *file)
{
  lock_acquire(&lock_f);
  /*return true if successfully removed*/
  bool success = filesys_remove(file);
  lock_release(&lock_f);
  return success;
}

/*opens the file with given name*/
int open(const char *file)
{
  lock_acquire(&lock_f);
  /*open the file*/
  struct file *f = filesys_open(file);
  /*if file doesn't exist*/
  if (f == NULL)
  {
    lock_release(&lock_f);
    return -1;
  }
  /*get the current thread*/
  struct thread *curr = thread_current();
  /*create a new file-fd-thread struct to store the open file info*/
  struct file_to_fd *new_f = malloc(sizeof(struct file_to_fd));
  /*add open file in*/
  new_f->f_addr_ptr = f;
  /*save the fd of current thread first*/
  int fd = curr->curr_fd;
  /*add curr fd by one for the next file*/
  curr->curr_fd++;
  /*bound the structure with current thread*/
  new_f->f_des = fd;
  list_push_back(&curr->file_des, &new_f->f_list);
  lock_release(&lock_f);
  return fd;
}

/*returns the size(in bytes) of the file open as fd*/
int filesize(int fd)
{
  lock_acquire(&lock_f);
  struct list_elem *temp;
  struct thread *curr = thread_current();
  /*if no file in current thread*/
  if (list_empty(&curr->file_des))
  {
    /*release the lock and return error*/
    lock_release(&lock_f);
    return -1;
  }
  temp = list_front(&curr->file_des);
  /*search the file to fd list in current thread*/
  while (temp != NULL)
  {
    struct file_to_fd *link = list_entry(temp, struct file_to_fd, f_list);
    /*if find the fd file*/
    if (link->f_des == fd)
    {
      /*release the lock and return filesize*/
      lock_release(&lock_f);
      return (int)file_length(link->f_addr_ptr);
    }
    temp = temp->next;
  }
  /*can't find fd file*/
  lock_release(&lock_f);
  return -1;
}

/*reads size bytes from the file open as fd into buffer*/
int read(int fd, void *buffer, unsigned size)
{
  struct list_elem *temp;
  int bytes_read = 0;
  struct thread *curr = thread_current();
  unsigned buff_size = size;
  void *buff = buffer;
  while (buff != NULL)
  {

    if (buff == NULL || !is_user_vaddr(buff))
    {
      exit(-1);
    }
    if (pagedir_get_page(thread_current()->pagedir, buff) == NULL)
    {
      struct page *p;
      p = page_search_all(buff);
      if (p != NULL && p->frame == NULL)
      {
        page_in(p);
        pagedir_set_page(curr->pagedir, p->addr, p->frame->ker_base, !p->writable);
      }
      else if (p == NULL && (buff >= (void *)curr->uesp - 32))
      {
        /*printf("\nin growth\n");*/
        struct page *growth_page = page_allocate(buff, false);
        if (!growth_page->frame)
        {
          growth_page->frame = frame_allocate(growth_page);
          if (growth_page->frame != NULL)
          {
            pagedir_set_page(curr->pagedir, growth_page->addr, growth_page->frame->ker_base, true);
          }
          else
          {
            exit(-1);
          }
        }
      }
      else
      {
        exit(-1);
      }
    }
    if (buff_size == 0)
    {
      buff = NULL;
    }
    else if (buff_size > PGSIZE)
    {
      buff += PGSIZE;
      buff_size -= PGSIZE;
    }
    else
    {
      buff = buffer + size - 1;
      buff_size = 0;
    }
  }
  lock_acquire(&lock_f);
  /*fd == 0 , read from keyboard*/
  if (fd == 0)
  {
    uint8_t input;
    unsigned cnt = size;
    uint8_t *buf = buffer;
    while (cnt > 1 && (input = input_getc()) != 0)
    {
      *buf = input;
      buffer++;
      cnt--;
    }
    *buf = 0;
    bytes_read = size - cnt;
  }
  /*if read from STDOUT or no open file to read*/
  if (fd == 1 || list_empty(&curr->file_des))
  {
    bytes_read = -1; /*attention*/
  }
  if (fd != 1 && fd != 0)
  {
    temp = list_begin(&curr->file_des);
    /*search the file to fd list in current thread*/
    while (temp != list_end(&curr->file_des))
    {
      struct file_to_fd *link = list_entry(temp, struct file_to_fd, f_list);
      /*if find the fd file*/
      if (link->f_des == fd)
      {
        bytes_read = file_read(link->f_addr_ptr, buffer, size);
      }
      temp = list_begin(temp);
    }
  }
  /*can't find fd file*/
  lock_release(&lock_f);
  return bytes_read;
}

/*changes the next byte to be read or written in open file 
  fd to position(in bytes) from the beginning of the file*/
void seek(int fd, unsigned position)
{
  lock_acquire(&lock_f);
  struct list_elem *temp;
  struct thread *curr = thread_current();
  /*if there is no file to seek*/
  if (list_empty(&curr->file_des))
  {
    lock_release(&lock_f);
    return;
  }
  temp = list_front(&curr->file_des);
  /*search the file to fd list in current thread*/
  while (temp != NULL)
  {
    struct file_to_fd *link = list_entry(temp, struct file_to_fd, f_list);
    /*if find the fd file*/
    if (link->f_des == fd)
    {
      /*seek the file for posirion*/
      file_seek(link->f_addr_ptr, position);
      /*release the lock and return*/
      lock_release(&lock_f);
      return;
    }
    temp = temp->next;
  }
  /*can't find fd file*/
  lock_release(&lock_f);
  return;
}

/*returns the position of the next byte to be read or written 
  in open file fd(in bytes) from the beginning of the file*/
unsigned tell(int fd)
{
  lock_acquire(&lock_f);
  struct list_elem *temp;
  struct thread *curr = thread_current();
  /*if there is no file to tell*/
  if (list_empty(&curr->file_des))
  {
    lock_release(&lock_f);
    return -1;
  }
  temp = list_front(&curr->file_des);
  /*search the file to fd list in current thread*/
  while (temp != NULL)
  {
    struct file_to_fd *link = list_entry(temp, struct file_to_fd, f_list);
    /*if find the fd file*/
    if (link->f_des == fd)
    {
      /*save the position to be told*/
      unsigned position = (unsigned)file_tell(link->f_addr_ptr);
      /*release the lock and return the bytes written*/
      lock_release(&lock_f);
      return position;
    }
    temp = temp->next;
  }
  /*can't find fd file*/
  lock_release(&lock_f);
  return -1;
}

/*closes file descriptor fd*/
void close(int fd)
{
  lock_acquire(&lock_f);
  struct list_elem *temp;
  struct thread *curr = thread_current();
  /*terminate if no file in current thread*/
  if (list_empty(&curr->file_des))
  {
    lock_release(&lock_f);
    return;
  }
  temp = list_front(&curr->file_des);
  /*search the file to fd list in current thread*/
  while (temp != NULL)
  {
    struct file_to_fd *link = list_entry(temp, struct file_to_fd, f_list);
    /*if find the fd file*/
    if (link->f_des == fd)
    {
      /*close the file and remove form file list*/
      file_close(link->f_addr_ptr);
      list_remove(&link->f_list);
      /*curr->curr_fd--;*/
      free(link);
      /*release the lock and return*/
      lock_release(&lock_f);
      return;
    }
    temp = temp->next;
  }
  /*can't find fd file*/
  lock_release(&lock_f);
  return;
}

int mmap(int fd, void *addr)
{
  size_t f_offset = 0;
  off_t f_length;
  struct list_elem *temp;
  struct thread *curr = thread_current();
  /*if current thread has no fd*/
  if (list_empty(&curr->file_des))
  {
    /*return error*/
    return -1;
  }
  struct file_to_fd *link;
  temp = list_front(&curr->file_des);
  /*search the file to fd list in current thread*/
  while (temp != NULL)
  {
    link = list_entry(temp, struct file_to_fd, f_list);
    /*if find the fd file*/
    if (link->f_des == fd)
    {
      break;
    }
    temp = temp->next;
  }
  lock_acquire(&lock_f);
  /*reopen the file*/
  struct file *f = file_reopen(link->f_addr_ptr);
  lock_release(&lock_f);
  /*if file doesn't exist*/
  if (f == NULL)
  {
    return -1;
  }
  /*create a map*/
  struct map *m = malloc(sizeof *m);
  /*if we can not create a map or address invalid return -1*/
  if (m == NULL || addr == NULL || pg_ofs(addr) != 0)
  {
    free(m);
    /*printf("here\n");*/
    return -1;
  }
  /*initiate the map and push it to map list*/
  m->page_count = 0;
  m->index = addr;
  m->file = f;
  m->mapid = curr->curr_fd;
  curr->curr_fd++;
  list_push_front(&curr->map_list, &m->elem);
  /*lock filesystem and get the length of file*/
  lock_acquire(&lock_f);
  f_length = file_length(m->file);
  lock_release(&lock_f);
  /*start to map file to memory*/
  while (f_length > 0)
  {
    struct page *p = page_allocate((uint8_t *)addr + f_offset, false);
    /*if can not get page then clear the map*/
    if (p == NULL)
    {
      unmap(m);
      return -1;
    }
    /*save the file info in page*/
    p->swapable = false;
    p->file = m->file;
    p->offset = f_offset;
    if (f_length >= PGSIZE)
    {
      p->bytes = PGSIZE;
    }
    else
    {
      p->bytes = f_length;
    }
    f_offset += p->bytes;
    f_length -= p->bytes;
    m->page_count++;
  }
  return m->mapid;
}
/*unmap the file*/
void munmap(int mapid)
{
  struct thread *curr = thread_current();
  struct list_elem *temp;
  struct map *m;
  /*search for the map with mapid*/
  temp = list_front(&curr->map_list);
  while (temp != NULL)
  {
    m = list_entry(temp, struct map, elem);
    if (m->mapid == mapid)
    {
      break;
    }
    temp = temp->next;
  }
  /*clear map with mapid*/
  unmap(m);
}
