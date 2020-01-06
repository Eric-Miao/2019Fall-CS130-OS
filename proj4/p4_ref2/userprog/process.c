#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

extern struct frame_table frame_table;
static const char *delimiters_str = " \t\n\v\f\r";

static thread_func start_process NO_RETURN;
static bool load (const char *file_name, const char *cmd_line, void (**eip) (void), void **esp);
static bool push_args(const char *cmdline, const char *delimiters, void **esp);

void get_file_name(const char *cmd_line, const char *delimiters, char *prog_name) {
    const char *begin = cmd_line;
    while (strchr(delimiters, *begin) != NULL)
        ++begin;
    const char *end = begin;
    while (strchr(delimiters, *end) == NULL && *end != '\0')
        ++end;
    strlcpy(prog_name, begin, end - begin + 1);
}

static bool push_args(const char *cmdline, const char *delimiters, void **esp) {
    int argc = 0;
    int argv_len = 0;
    bool is_del = true;

    const char *ptr = cmdline;
    while (*ptr != '\0') {
        if (strchr(delimiters, *ptr) != NULL)
            is_del = true;
        else {
            if (is_del) {
                is_del = false;
                ++argc;
            }
            ++argv_len;
        }
        ++ptr;
    }

    int arg_size = argv_len + argc;
    arg_size += arg_size % 4 ? 0 : 4 - arg_size % 4;

    if (arg_size + (argc + 1) * sizeof(char*) + sizeof(char**) + sizeof(int)
        + sizeof(void *) > PGSIZE)
        return false;

    char *argv_data, **argv_ptr;
    *esp -= arg_size;
    argv_data = *esp;
    *esp -= (argc + 1) * sizeof(char*);
    argv_ptr = (char**) *esp;

    const char *token, *save_ptr;
    size_t token_len;
    for (token = strtok_rr(cmdline, delimiters_str, &token_len, &save_ptr);
        token != NULL; token = strtok_rr(NULL, delimiters_str, &token_len, &save_ptr)) {
        strlcpy(argv_data, token, token_len);
        *argv_ptr = argv_data;
        argv_data += token_len;
        ++argv_ptr;
    }
    *argv_ptr = NULL;

    *esp -= sizeof(char**);
    *((char***) *esp) = *esp + sizeof(char**);
    *esp -= sizeof(int);
    *((int*) *esp) = argc;
    *esp -= sizeof(void*);
    *((void**) *esp) = NULL;

    return true;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmd_line)
{
    tid_t tid;

    /* Make a copy of CMDLINE.
       Otherwise there's a race between the caller and load(). */
    char *cmd_line_copy = palloc_get_page(0);
    if (!cmd_line_copy) {
        return TID_ERROR;
    }
    strlcpy (cmd_line_copy, cmd_line, CMDLINE_MAX);

    char *file_name = palloc_get_page(0);
    if (!file_name) {
        palloc_free_page(cmd_line_copy);
        return TID_ERROR;
    }
    get_file_name(cmd_line_copy, delimiters_str, file_name);

    struct thread *cur = thread_current();
    struct load_aux la;
    la.parent = cur;
    la.file_name = file_name;
    la.cmd_line = cmd_line_copy;
    sema_init(&la.sema, 0);
    la.success = false;
    struct child_status *cs = malloc(sizeof(struct child_status));
    if (!cs) {
        palloc_free_page(cmd_line_copy);
        palloc_free_page(file_name);
        return TID_ERROR;
    }
    cs->waited = false;
    cs->exit_code = 0;
    cs->parent_ref = true;
    cs->child_ref = false;
    lock_init(&cs->ref_lock);
    sema_init(&cs->sema_wait, 0);
    la.cs = cs;

    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create (file_name, PRI_DEFAULT, start_process, &la);
    sema_down(&la.sema);

    if (tid == TID_ERROR)
        palloc_free_page (cmd_line_copy);
    palloc_free_page(file_name);

    return la.success ? tid : TID_ERROR;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *aux)
{
    struct load_aux *la = aux;
    char *file_name = la->file_name;
    char *cmd_line = la->cmd_line;
    struct intr_frame if_;
    bool success;

    /* Initialize interrupt frame and load executable. */
    memset (&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load (file_name, cmd_line, &if_.eip, &if_.esp);
    palloc_free_page(cmd_line);

    struct thread *cur = thread_current();
    struct child_status *cs = la->cs;

    la->success = success;
    if (!success) {
        /* If load failed, quit. */
        free(cs);
        sema_up(&la->sema);
        cur->exit_code = -1;
        thread_exit();
    }

    struct thread *parent = la->parent;
    lock_acquire(&parent->children_lock);
    list_push_front(&parent->children, &cs->elem);
    lock_release(&parent->children_lock);
    cs->tid = cur->tid;
    cs->child_ref = true;
    cur->cs = cs;
    sema_up(&la->sema);

    /* Start the user process by simulating a return from an
       interrupt, implemented by intr_exit (in
       threads/intr-stubs.S).  Because intr_exit takes all of its
       arguments on the stack in the form of a `struct intr_frame',
       we just point the stack pointer (%esp) to our stack frame
       and jump to it. */

    asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
    NOT_REACHED ();
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
process_wait (tid_t child_tid)
{
    struct thread *cur = thread_current();
    struct list_elem *e;
    int ret = -1;
    lock_acquire(&cur->children_lock);
    for (e = list_begin(&cur->children); e != list_end(&cur->children);
         e = list_next(e)) {
        struct child_status *cs = list_entry(e, struct child_status, elem);
        lock_acquire(&cs->ref_lock);
        if (cs->tid == child_tid) {
            if (!cs->waited) {
                cs->waited = true;
                lock_release(&cs->ref_lock);
                sema_down(&cs->sema_wait);
                ret = cs->exit_code;
                goto wait_done;
            }
            else {
                lock_release(&cs->ref_lock);
                goto wait_done;
            }
        }
        lock_release(&cs->ref_lock);
    }
    wait_done:
    lock_release(&cur->children_lock);
    return ret;
}

/* Free the current process's resources. */
void
process_exit (void)
{
    struct thread *cur = thread_current ();

    printf("%s: exit(%d)\n", thread_name(), cur->exit_code);

    lock_acquire(&frame_table.lock);
    while (!list_empty(&cur->frame_table)) {
        struct list_elem *e = list_pop_front(&cur->frame_table);
        struct frame_table_entry *fe = list_entry(e,
                struct frame_table_entry, elem_owner);
        if (fe->sup) {
            fe->sup->frame = NULL;
        }
        list_remove(&fe->elem);
        free(fe);
    }
    lock_release(&frame_table.lock);
    hash_clear(&cur->mmap_table, mmap_entry_free);
    hash_clear(&cur->sup_page_table, sup_page_table_entry_free);

    struct file_opened *fo = cur->files;
    int i;
    for (i = 0; i < cur->num_files; ++i) {
        if (!fo[i].closed) {
            file_close(fo[i].file);
        }
    }
    free(fo);

    if (cur->file_executing) {
        file_allow_write(cur->file_executing);
        file_close(cur->file_executing);
    }

    while (!list_empty(&cur->locks)) {
        struct list_elem *e = list_front(&cur->locks);
        struct lock *l = list_entry(e, struct lock, elem);
        lock_release(l);
    }

    uint32_t *pd;

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

    if (cur->cs) {
        lock_acquire(&cur->children_lock);
        while (!list_empty(&cur->children)) {
            struct list_elem *e = list_pop_front(&cur->children);
            struct child_status *cs = list_entry(e, struct child_status, elem);
            lock_acquire(&cs->ref_lock);
            if (!cs->child_ref) {
                lock_release(&cs->ref_lock);
                free(cs);
            } else {
                cs->parent_ref = false;
                lock_release(&cs->ref_lock);
            }
        }
        lock_release(&cur->children_lock);

        lock_acquire(&cur->cs->ref_lock);
        if (!cur->cs->parent_ref) {
            lock_release(&cur->cs->ref_lock);
            free(&cur->cs);
        } else {
            cur->cs->child_ref = false;
            cur->cs->exit_code = cur->exit_code;
            sema_up(&cur->cs->sema_wait);
            lock_release(&cur->cs->ref_lock);
        }
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

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
static bool
load (const char *file_name, const char *cmd_line, void (**eip) (void), void **esp)
{
    struct thread *t = thread_current ();
    struct Elf32_Ehdr ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    int i;

    /* Allocate and activate page directory. */
    t->pagedir = pagedir_create ();
    if (t->pagedir == NULL)
        goto fail;
    process_activate ();

    /* Open executable file. */
    file = filesys_open (file_name);
    if (file == NULL)
    {
        printf ("load: %s: open failed\n", file_name);
        goto fail;
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
        printf ("load: %s: error loading executable\n", file_name);
        goto fail;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++)
    {
        struct Elf32_Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length (file))
            goto fail;
        file_seek (file, file_ofs);

        if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
            goto fail;
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
                goto fail;
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
                        goto fail;
                }
                else
                    goto fail;
                break;
        }
    }

    /* Set up stack. */
    if (!setup_stack (esp))
        goto fail;

    if (!push_args(cmd_line, delimiters_str, esp))
        goto fail;

    /* Start address. */
    *eip = (void (*) (void)) ehdr.e_entry;

    /* Success! */
    file_deny_write(file);
    t->file_executing = file;
    return true;

    fail:
    /* We arrive here whether the load is successful or not. */
    file_close (file);
    return false;
}

/* load() helpers. */

//static bool install_page (void *upage, void *kpage, bool writable);

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

    return load_lazy(file, ofs, upage, read_bytes, zero_bytes, writable, SUP_SEG);
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
    bool success = stack_growth(((uint8_t *) PHYS_BASE) - PGSIZE);
    if (success)
        *esp = PHYS_BASE;
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
