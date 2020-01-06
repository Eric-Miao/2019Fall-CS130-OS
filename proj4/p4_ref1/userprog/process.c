#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/syscall.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (struct exec_msg *msg, void (**eip) (void), void **esp);

#define INITIAL_STATUS -2
/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  struct exec_msg *msg = malloc (sizeof (struct exec_msg));
  if (msg == NULL)
    return TID_ERROR;

  tid_t tid;

  /*initialize current working directory */
  struct dir *working_dir = thread_current()->working_dir;
  if (working_dir == NULL)
    msg->working_dir = dir_open_root();
  else
    msg->working_dir = dir_reopen(working_dir);
  if (msg->working_dir == NULL)
    return TID_ERROR;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  msg->fn_copy = palloc_get_page (0);
  if (msg->fn_copy == NULL)
  {
    dir_close(msg->working_dir);
    free(msg);
    return TID_ERROR;
  }
  strlcpy (msg->fn_copy, file_name, PGSIZE);/* extract file name*/

  /* Make a copy of the extracted file name */
  int len = strcspn (file_name, " ");
  msg->prog_name = malloc ((len + 1) * sizeof (char));
  if (msg->prog_name == NULL)
  {
    dir_close(msg->working_dir);
    free(msg);
    return TID_ERROR;
  }
  memcpy (msg->prog_name, file_name, len);
  msg->prog_name[len] = '\0';

  sema_init (&msg->load_sema, 0);
  msg->load_complete = false;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (msg->prog_name, PRI_DEFAULT, start_process, msg);
  sema_down (&msg->load_sema);/* wait for the new process to load */

  if (msg->load_complete == false)
  {
    tid = TID_ERROR; 
  }
  palloc_free_page (msg->fn_copy);
  free (msg->prog_name);
  free (msg);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *aux)
{
  struct exec_msg *msg = (struct exec_msg *) aux;
  struct intr_frame if_;
  bool success;

  thread_current()->working_dir = msg->working_dir;
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (msg, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  if (!success) 
  {
    exit (EXIT_ERROR);
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}


/* checks if child_tid is one of current thread's children */
static bool
is_child(tid_t child_tid)
{
  struct list_elem *e;
  struct process_info *process = NULL;
  struct thread* current = thread_current ();
  for (e = list_begin (&current->children_list);
       e != list_end (&current->children_list) ; e = list_next(e))
  {
    process = list_entry(e, struct process_info, elem);
    if (process->tid == child_tid)
      return true;
  }
  return false;
}
/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct list_elem *e;
  struct process_info *process = NULL;
  struct thread* cur = thread_current ();
  if (!is_child(child_tid))
    return -1;

  /* find the child */
  for (e = list_begin (&cur->children_list);
       e != list_end (&cur->children_list) ; e = list_next(e))
  {
    process = list_entry(e, struct process_info, elem);
    if (process->tid == child_tid)
      break;
  }
  lock_acquire(&process->wait_l);

  if (process->waited)/*process is already waited */
  {
    lock_release(&process->wait_l);
    return -1;
  }
  process->waited = true;
  sema_down(&process->exit_sema);
  /* wait for the child process to exit */
  int exit_status = process->exit_status;
  list_remove(&process->elem);
  lock_release(&process->wait_l);
  free(process);
  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  struct list_elem *e = list_begin (&cur->children_list);
  struct list_elem *next;
  struct process_info *process = NULL;
  uint32_t *pd;

  ASSERT (cur->process != NULL);

  printf ("%s: exit(%d)\n", cur->name, cur->exit_status);
  cur->process->exit_status = cur->exit_status;
  sema_up(&cur->process->exit_sema); /* signaling parent that we are done */

  /* close all files opened and the exectuable file */
  close_all ();
  close_all_mmap();
  dir_close(thread_current()->working_dir);
  spt_destroy (&thread_current()->spt_table);
  
  if(cur->exec_file != NULL)
  {
    file_close (cur->exec_file);
  }

  /* free itself if it doesn't have a parent */
  if (cur->process->parent == NULL) 
  {
    free (cur->process);
  }

  /* sets all of its children's parent thread to be null
     and frees dead children's struct */
  while (e != list_end(&cur->children_list))
  {
    next = list_next(e);
    process = list_entry(e, struct process_info, elem);
    process->parent = NULL;
    if (process->exit_status != INITIAL_STATUS)
    {
    /*child process already exited */
      list_remove(&process->elem);
      free(process);
    }
    e = next;
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char* file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (struct exec_msg *msg, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = file_open(filesys_open (msg->prog_name));
  
  if (file != NULL) 
    file_deny_write (file); /* deny write */
  else 
  {
    printf ("load: %s: open failed\n", msg->prog_name);
    goto done; 
  }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", msg->prog_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, msg->fn_copy))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  t->exec_file = file;

 done:
  /* We arrive here whether the load is successful or not. */
  msg->load_complete = success;
  sema_up(&msg->load_sema);
  return success;
}

/* load() helpers. */


/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      if (!spt_add (VM_EXECUTABLE_TYPE, upage, writable, file, ofs, page_read_bytes))
        return false;

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += page_read_bytes;
    }
  return true;
}

/* decrease stack pointer and copy data to new stack pointer */
static void push_to_stack(void **esp, void *data, size_t size) 
{
  *esp -= size;
  memcpy(*esp, data, size);
}
/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char* file_name) 
{
  uint8_t *upage;
  bool success = false;
  char *token, *save_ptr;
  int i;

  upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
  if (spt_add (VM_STACK_TYPE, upage, true))
    success = spt_load_page (upage);
  if (!success)
    return false;
  *esp = PHYS_BASE;

  /* count arguments */

  int argc = 0;
  for (token = strtok_r ((char *)file_name, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr))
    argc++;

  char **argv = malloc((argc + 1)*sizeof(char *));
  if (argv == NULL)
    return false;
  save_ptr = (char *)file_name;

  /* push arguments to the stack */
  for (i = 0; i < argc; i++) 
  {
    push_to_stack(esp, save_ptr, strlen(save_ptr) + 1);
    save_ptr = strchr(save_ptr, '\0') + 1;
    argv[i] = *esp;
    while(*save_ptr == ' ') /* skip delimiters */
      save_ptr++;
  }

  argv[argc] = 0; /* the null pointer sentinel */

  /* add padding to the stack */
  char c = 0; /* char used for aligning */
  int align =(int) *esp % 4;
  if (align != 0) 
  {
    for (i = 0; i < align; i++)
    {
      push_to_stack(esp, &c, sizeof(c));
    }
  }

  /*push argv[i] to the stack in reverse order */
  for (i = argc; i >= 0; i--)
  {
    push_to_stack(esp, &argv[i], sizeof(char *));
  }

  /* push argv and argc to the stack */
  save_ptr = *esp;
  push_to_stack(esp, &save_ptr, sizeof (char *));
  push_to_stack(esp, &argc, sizeof(int));

  /* push the fake return address */
  int fake_address = 0;
  push_to_stack(esp, &fake_address, sizeof(int));

  free(argv);
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
