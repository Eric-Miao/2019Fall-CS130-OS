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
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#define ARGS 3

static void syscall_handler(struct intr_frame *);

/*lock on accessing the file system*/
struct lock lock_f;
void get_args(struct intr_frame *f, int *args, int num);
/*Struct that combines file with its descriptor and put in current thread's file descriptor list*/
struct file_to_fd
{
  int f_des;               /*file descriptor*/
  struct file *f_addr_ptr; /*file address*/
  struct dir *d_addr_ptr;  /*directory address*/
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
    /*check if the address is mapped to the physical address*/
    physical_page = (void *)pagedir_get_page(curr->pagedir, (const void *)args[0]);
    /*if not then terminate the program and free its resources*/
    if (physical_page == NULL)
    {
      exit(-1);
    }
    /*send physical page pointer back to args*/
    args[0] = (int)physical_page;
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
    /*check if the address is mapped to the physical address*/
    physical_page = pagedir_get_page(curr->pagedir, (const void *)args[0]);
    /*if not then terminate the program and free its resources*/
    if (physical_page == NULL)
    {
      exit(-1);
    }
    /*send physical page pointer back to args*/
    args[0] = (int)physical_page;
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
    /*send physical page pointer back to args*/
    args[0] = (int)physical_page;
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
    physical_page = pagedir_get_page(curr->pagedir, (const void *)args[1]);
    /*if not then terminate the program and free its resources*/
    if (physical_page == NULL)
    {
      exit(-1);
    }
    /*send physical page pointer back to args*/
    args[1] = (int)physical_page;
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
    physical_page = pagedir_get_page(curr->pagedir, (const void *)args[1]);
    /*if not then terminate the program and free its resources*/
    if (physical_page == NULL)
    {
      exit(-1);
    }
    /*send physical page pointer back to args*/
    args[1] = (int)physical_page;
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
  /*if syscall is change directory*/
  if (*(int *)f->esp == SYS_CHDIR)
  {
    /*get path name*/
    get_args(f, &args[0], 1);
    /*call chdir()*/
    f->eax = chdir((const char *)args[0]);
  }
  /*if syscall is make directory*/
  if (*(int *)f->esp == SYS_MKDIR)
  {
    /*get path name*/
    get_args(f, &args[0], 1);
    /*call chdir()*/
    f->eax = mkdir((const char *)args[0]);
  }
  /*if syscall is read directory*/
  if (*(int *)f->esp == SYS_READDIR)
  {
    /*get file discriptor and path name*/
    get_args(f, &args[0], 2);
    /*call readdir()*/
    f->eax = readdir(args[0], (char *)args[1]);
  }
  /*if syscall is is_directory*/
  if (*(int *)f->esp == SYS_ISDIR)
  {
    /*get file discriptor*/
    get_args(f, &args[0], 1);
    /*call isdir()*/
    f->eax = isdir(args[0]);
  }
  /*if syscall is inode number*/
  if (*(int *)f->esp == SYS_INUMBER)
  {
    /*get file discriptor*/
    get_args(f, &args[0], 1);
    /*call isdir()*/
    f->eax = inumber(args[0]);
  }
  /*if it is an invalid system call*/
  if (*(int *)f->esp != SYS_HALT && *(int *)f->esp != SYS_EXIT && *(int *)f->esp != SYS_EXEC && *(int *)f->esp != SYS_WRITE && *(int *)f->esp != SYS_READ && *(int *)f->esp != SYS_OPEN && *(int *)f->esp != SYS_CLOSE && *(int *)f->esp != SYS_WAIT && *(int *)f->esp != SYS_CREATE && *(int *)f->esp != SYS_REMOVE && *(int *)f->esp != SYS_FILESIZE && *(int *)f->esp != SYS_SEEK && *(int *)f->esp != SYS_TELL && *(int *)f->esp != SYS_CHDIR && *(int *)f->esp != SYS_MKDIR && *(int *)f->esp != SYS_READDIR && *(int *)f->esp != SYS_ISDIR && *(int *)f->esp != SYS_INUMBER)
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
    return 0;
  }
  /*get the current thread's fd*/
  temp = list_front(&curr->file_des);
  while (temp != NULL)
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
    temp = temp->next;
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
  if(strlen(file)>NAME_MAX)
  {
    lock_release(&lock_f);
    return false;
  }
  bool success = filesys_create(file, initial_size, false);
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
  struct inode *inode = filesys_open(file);
  /*if file doesn't exist*/
  if (inode == NULL)
  {
    lock_release(&lock_f);
    return -1;
  }
  /*get the current thread*/
  struct thread *curr = thread_current();
  /*create a new file-fd-thread struct to store the open file info*/
  struct file_to_fd *new_f = malloc(sizeof(struct file_to_fd));
  /*add open file in*/
  if (inode_is_dir(inode))
  {
    new_f->d_addr_ptr = dir_open(inode);
    new_f->f_addr_ptr = NULL;
  }
  else
  {
    new_f->f_addr_ptr = file_open(inode);
    new_f->d_addr_ptr = NULL;
  }
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
  lock_acquire(&lock_f);
  struct list_elem *temp;
  struct thread *curr = thread_current();
  /*fd == 0 , read from keyboard*/
  if (fd == 0)
  {
    lock_release(&lock_f);
    /*see "devices/input.c" for detail*/
    return (int)input_getc();
  }
  /*if read from STDOUT or no open file to read*/
  if (fd == 1 || list_empty(&curr->file_des))
  {
    /*release the lock and return error*/
    lock_release(&lock_f);
    return 0; /*attention*/
  }
  temp = list_front(&curr->file_des);
  /*search the file to fd list in current thread*/
  while (temp != NULL)
  {
    struct file_to_fd *link = list_entry(temp, struct file_to_fd, f_list);
    /*if find the fd file*/
    if (link->f_des == fd)
    {
      /*release the lock and return the bytes written*/
      lock_release(&lock_f);
      return (int)file_read(link->f_addr_ptr, buffer, size);
    }
    temp = temp->next;
  }
  /*can't find fd file*/
  lock_release(&lock_f);
  return -1;
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
      dir_close(link->d_addr_ptr);
      list_remove(&link->f_list);
      curr->curr_fd--;
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

/*changes the current working directory of the process to dir*/
bool chdir(const char *dir)
{
  return filesys_chdir(dir);
}

/*creates the directory named dir, which may be relative or absolute*/
bool mkdir(const char *dir)
{
  return filesys_create(dir, 0, true);
}

/*reads a directory entry from file descriptor fd*/
bool readdir(int fd, char *name)
{
  lock_acquire(&lock_f);
  struct list_elem *temp;
  struct thread *curr = thread_current();
  /*if there is no file to seek*/
  if (list_empty(&curr->file_des))
  {
    lock_release(&lock_f);
    return false;
  }
  temp = list_front(&curr->file_des);
  /*search the file to fd list in current thread*/
  while (temp != NULL)
  {
    struct file_to_fd *link = list_entry(temp, struct file_to_fd, f_list);
    /*if find the fd file*/
    if (link->f_des == fd)
    {
      /*release the lock and return*/
      lock_release(&lock_f);
      return dir_readdir(link->d_addr_ptr, name);
    }
    temp = temp->next;
  }
  /*can't find fd file*/
  lock_release(&lock_f);
  return false;
}

/*returns true if fd represents a directory*/
bool isdir(int fd)
{
  lock_acquire(&lock_f);
  struct list_elem *temp;
  struct thread *curr = thread_current();
  /*if there is no file to seek*/
  if (list_empty(&curr->file_des))
  {
    lock_release(&lock_f);
    return false;
  }
  temp = list_front(&curr->file_des);
  /*search the file to fd list in current thread*/
  while (temp != NULL)
  {
    struct file_to_fd *link = list_entry(temp, struct file_to_fd, f_list);
    /*if find the fd file*/
    if (link->f_des == fd)
    {
      /*release the lock and return*/
      lock_release(&lock_f);
      return link->d_addr_ptr != NULL;
    }
    temp = temp->next;
  }
  /*can't find fd file*/
  lock_release(&lock_f);
  return false;
}

/*returns the inode number of the inode associated with fd*/
int inumber(int fd)
{
  struct list_elem *temp;
  struct inode *inode = NULL;
  struct file_to_fd *target = NULL;
  struct thread *curr = thread_current();
  /*if there is no file to seek*/
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
      target = link;
    }
    temp = temp->next;
  }
  /*if we can't find file with fd*/
  if (target == NULL)
  {
    return -1;
  }
  if (target->f_addr_ptr == NULL)
  {
    inode = dir_get_inode(target->d_addr_ptr);
  }
  else
  {
    inode = file_get_inode(target->f_addr_ptr);
  }
  /*if we can't get inode*/
  if (inode == NULL)
  {
    return -1;
  }
  return inode_get_inumber(inode);
}