#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include <round.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "vm/page.h"

extern struct frame_table frame_table;

static void syscall_handler (struct intr_frame *);

// Project 2
static void _halt (void) NO_RETURN;
// void _exit (int status) NO_RETURN;
static pid_t _exec (const char *cmd_line);
static int _wait (pid_t pid);
static bool _create (const char *file, unsigned initial_size);
static bool _remove (const char *file);
static int _open (const char *file);
static int _filesize (int fd);
static int _read (int fd, void *buffer, unsigned size);
static int _write (int fd, const void *buffer, unsigned size);
static void _seek (int fd, unsigned position);
static unsigned _tell (int fd);
static void _close (int fd);

// Project 3
static mapid_t _mmap (int fd, void *addr);
static void _munmap (mapid_t mapping);

// Project 4
static bool _chdir (const char *pathname);
static bool _mkdir (const char *pathname);
static bool _readdir (int fd, char *filename);
static bool _isdir (int fd);
static int _inumber (int fd);

static inline int get_user(const uint8_t *uaddr);
static inline bool put_user(uint8_t *udst, uint8_t byte);
static inline void pin_vaddr(const void *vaddr);
static inline void unpin_vaddr(const void *vaddr);
static inline void pin_vaddr_range(const void *vaddr, size_t size);
static inline void unpin_vaddr_range(const void *vaddr, size_t size);
static inline bool is_user_vaddr_range(const void *vaddr, size_t size);
static inline bool is_readable_vaddr_range(const void *vaddr, size_t size);
static inline bool is_writable_vaddr_range(void *vaddr, size_t size);
static inline int is_readable_str_vaddr_range(const void *vaddr, size_t size);
static inline void unpin_str(const void *vaddr, size_t size);
static int thread_open_file_tail(struct file *f);
static struct file_opened *find_file_opened(int fd);
static void *get_next_argument(void **esp, unsigned offset);
#define GET_NEXT_ARGUMENT(esp, type) (*(type*) get_next_argument((esp), sizeof(type)))

static inline void pin_vaddr(const void *vaddr) {
    struct sup_page_table_entry *se = sup_page_table_find(
            &thread_current()->sup_page_table, pg_round_down(vaddr));
    if (se) {
        lock_acquire(&se->lock);
        se->pin = true;
        lock_release(&se->lock);
    }
}

static inline void unpin_vaddr(const void *vaddr) {
    struct sup_page_table_entry *se = sup_page_table_find(
            &thread_current()->sup_page_table, pg_round_down(vaddr));
    if (se) {
        lock_acquire(&se->lock);
        se->pin = false;
        lock_release(&se->lock);
    }
}

static inline void pin_vaddr_range(const void *vaddr, size_t size) {
    void *addr;
    for (addr = pg_round_down(vaddr); addr < vaddr + size; addr += PGSIZE) {
        pin_vaddr(addr);
    }
}

static inline void unpin_vaddr_range(const void *vaddr, size_t size) {
    void *addr;
    for (addr = pg_round_down(vaddr); addr < vaddr + size; addr += PGSIZE) {
        unpin_vaddr(addr);
    }
}

static inline bool is_readable_vaddr(const void *vaddr) {
    return get_user(vaddr) != -1;
}

static inline bool is_writable_vaddr(void *vaddr) {
    int ch = get_user(vaddr);
    if (ch == -1)
        return false;
    return put_user(vaddr, (uint8_t) ch);
}

static inline bool is_user_vaddr_range(const void *vaddr, size_t size) {
    if (!vaddr)
        return false;
    if (size == 0)
        return true;
    return is_user_vaddr(vaddr + size - 1);
}

static inline bool is_readable_vaddr_range(const void *vaddr, size_t size) {
    if (size == 0)
        return true;
    if (!is_user_vaddr_range(vaddr, size))
        return false;
    const void *addr;
    for (addr = pg_round_down(vaddr); addr < vaddr + size; addr += PGSIZE) {
        if (!is_readable_vaddr(addr))
            return false;
    }
    return true;
}

static inline bool is_writable_vaddr_range(void *vaddr, size_t size) {
    if (size == 0)
        return true;
    if (!is_user_vaddr_range(vaddr, size))
        return false;
    void *addr;
    for (addr = pg_round_down(vaddr); addr < vaddr + size; addr += PGSIZE) {
        if (!is_writable_vaddr(addr))
            return false;
    }
    return true;
}

static inline int is_readable_str_vaddr_range(const void *vaddr, size_t size) {
    size_t offset;
    const uint8_t *next_to_pin = pg_round_down(vaddr);
    for (offset = 0; offset <= size; ++offset) {
        const uint8_t *ptr = vaddr + offset;
        if (ptr >= next_to_pin) {
            pin_vaddr(next_to_pin);
            next_to_pin += PGSIZE;
        }
        if (is_kernel_vaddr(ptr) || !is_readable_vaddr(ptr))
            return -1;
        else if (*ptr == 0)
            return (int) offset;
    }
    return -2;
}

static inline void unpin_str(const void *vaddr, size_t size) {
    unpin_vaddr_range(vaddr, size + 1);
}

static void *get_next_argument(void **esp, unsigned offset) {
    void *old_esp = *esp;
    if (is_kernel_vaddr(old_esp) || !is_readable_vaddr_range(old_esp, offset))
        _exit(-1);
    *esp += offset;
    return old_esp;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static inline int
get_user (const uint8_t *uaddr)
{
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
    : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}

static void
syscall_handler (struct intr_frame *f)
{
    struct thread *cur = thread_current();
    void *esp = f->esp;
    bool old_syscall = cur->syscall;
    void *old_esp = cur->esp;
    cur->syscall = true;
    cur->esp = f->esp;
    uint32_t syscall_no = GET_NEXT_ARGUMENT(&esp, uint32_t);

    switch (syscall_no) {
        case SYS_HALT: {
            _halt();
            break;
        }

        case SYS_EXIT: {
            int status = GET_NEXT_ARGUMENT(&esp, int);
            _exit(status);
            break;
        }

        case SYS_EXEC: {
            const char *file = GET_NEXT_ARGUMENT(&esp, char*);
            f->eax = (uint32_t) _exec(file);
            break;
        }

        case SYS_WAIT: {
            pid_t pid = GET_NEXT_ARGUMENT(&esp, pid_t);
            f->eax = (uint32_t) _wait(pid);
            break;
        }

        case SYS_CREATE: {
            const char *file = GET_NEXT_ARGUMENT(&esp, char*);
            unsigned int initial_size = GET_NEXT_ARGUMENT(&esp, unsigned int);
            f->eax = (uint32_t) _create(file, initial_size);
            break;
        }

        case SYS_REMOVE: {
            const char *file = GET_NEXT_ARGUMENT(&esp, char*);
            f->eax = (uint32_t) _remove(file);
            break;
        }

        case SYS_OPEN: {
            const char *file = GET_NEXT_ARGUMENT(&esp, char*);
            f->eax = (uint32_t) _open(file);
            break;
        }

        case SYS_FILESIZE: {
            int fd = GET_NEXT_ARGUMENT(&esp, int);
            f->eax = (uint32_t) _filesize(fd);
            break;
        }

        case SYS_READ: {
            int fd = GET_NEXT_ARGUMENT(&esp, int);
            void *buffer = GET_NEXT_ARGUMENT(&esp, void*);
            unsigned int size = GET_NEXT_ARGUMENT(&esp, unsigned int);
            f->eax = (uint32_t) _read(fd, buffer, size);
            break;
        }

        case SYS_WRITE: {
            int fd = GET_NEXT_ARGUMENT(&esp, int);
            const void *buffer = GET_NEXT_ARGUMENT(&esp, void*);
            unsigned int size = GET_NEXT_ARGUMENT(&esp, unsigned int);
            f->eax = (uint32_t) _write(fd, buffer, size);
            break;
        }

        case SYS_SEEK: {
            int fd = GET_NEXT_ARGUMENT(&esp, int);
            unsigned int position = GET_NEXT_ARGUMENT(&esp, unsigned int);
            _seek(fd, position);
            break;
        }

        case SYS_TELL: {
            int fd = GET_NEXT_ARGUMENT(&esp, int);
            f->eax = (uint32_t) _tell(fd);
            break;
        }

        case SYS_CLOSE: {
            int fd = GET_NEXT_ARGUMENT(&esp, int);
            _close(fd);
            break;
        }

        case SYS_MMAP: {
            int fd = GET_NEXT_ARGUMENT(&esp, int);
            void *addr = GET_NEXT_ARGUMENT(&esp, void*);
            f->eax = (uint32_t) _mmap(fd, addr);
            break;
        }

        case SYS_MUNMAP: {
            mapid_t mapping = GET_NEXT_ARGUMENT(&esp, mapid_t);
            _munmap(mapping);
            break;
        }

        case SYS_CHDIR: {
            const char *pathname = GET_NEXT_ARGUMENT(&esp, const char*);
            f->eax = (uint32_t) _chdir(pathname);
            break;
        }

        case SYS_MKDIR: {
            const char *pathname = GET_NEXT_ARGUMENT(&esp, const char*);
            f->eax = (uint32_t) _mkdir(pathname);
            break;
        }

        case SYS_READDIR: {
            int fd = GET_NEXT_ARGUMENT(&esp, int);
            char *filename = GET_NEXT_ARGUMENT(&esp, char*);
            f->eax = (uint32_t) _readdir(fd, filename);
            break;
        }

        case SYS_ISDIR: {
            int fd = GET_NEXT_ARGUMENT(&esp, int);
            f->eax = (uint32_t) _isdir(fd);
            break;
        }

        case SYS_INUMBER: {
            int fd = GET_NEXT_ARGUMENT(&esp, int);
            f->eax = (uint32_t) _inumber(fd);
            break;
        }

        default:
            break;

    }

    cur->syscall = old_syscall;
    cur->esp = old_esp;
}

void
syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void _halt (void) {
    shutdown_power_off();
}

void _exit (int status) {
    struct thread *cur = thread_current();
    cur->exit_code = status;
    thread_exit();
}

static pid_t _exec (const char *cmd_line) {
    int length = is_readable_str_vaddr_range(cmd_line, CMDLINE_MAX);
    if (length == -1)
        _exit(-1);
    else if (length == -2) {
        unpin_str(cmd_line, CMDLINE_MAX);
        return PID_ERROR;
    }

    pid_t pid = process_execute(cmd_line);
    unpin_str(cmd_line, (size_t) length);
    return pid;
}

static int _wait (pid_t pid) {
    return process_wait(pid);
}

static bool _create (const char *file, unsigned initial_size) {
    int length = is_readable_str_vaddr_range(file, PATHNAME_MAX);
    if (length == -1)
        _exit(-1);
    else if (length == -2) {
        unpin_str(file, PATHNAME_MAX);
        return false;
    }

    bool result = filesys_create(file, initial_size);
    unpin_str(file, (size_t) length);
    return result;
}

static bool _remove (const char *file) {
    int length = is_readable_str_vaddr_range(file, PATHNAME_MAX);
    if (length == -1)
        _exit(-1);
    else if (length == -2) {
        unpin_str(file, PATHNAME_MAX);
        return false;
    }

    bool result = filesys_remove(file);
    unpin_str(file, (size_t) length);
    return result;
}

static int _open (const char *file) {
    int length = is_readable_str_vaddr_range(file, PATHNAME_MAX);
    if (length == -1)
        _exit(-1);
    else if (length == -2) {
        unpin_str(file, PATHNAME_MAX);
        return false;
    }

    struct file *f = filesys_open(file);
    unpin_str(file, (size_t) length);
    return thread_open_file_tail(f);
}

static int _filesize (int fd) {
    struct file_opened *fo = find_file_opened(fd);
    if (!fo || fo->closed)
        return -1;

    int size = file_length(fo->file);
    return size;
}

static int _read (int fd, void *buffer, unsigned size) {
    pin_vaddr_range(buffer, size);
    if (!is_writable_vaddr_range(buffer, size)) {
        _exit(-1);
    }
    if (fd == STDOUT_FILENO) {
        unpin_vaddr_range(buffer, size);
        return -1;
    }

    if (fd == STDIN_FILENO) {
        size_t offset;
        for (offset = 0; offset < size; ++offset) {
            *((uint8_t*) buffer + offset) = input_getc();
        }
        unpin_vaddr_range(buffer, size);
        return size;
    }
    else {
        struct file_opened *fo = find_file_opened(fd);
        if (!fo || fo->closed) {
            unpin_vaddr_range(buffer, size);
            return -1;
        }
        int result = file_read(fo->file, buffer, size);
        unpin_vaddr_range(buffer, size);
        return result;
    }
}

static int _write (int fd, const void *buffer, unsigned size) {
    pin_vaddr_range(buffer, size);
    if (!is_readable_vaddr_range(buffer, size)) {
        _exit(-1);
    }
    if (fd == STDIN_FILENO) {
        unpin_vaddr_range(buffer, size);
        return -1;
    }

    if (fd == STDOUT_FILENO) {
        size_t offset;
        for (offset = 0; offset + BUFFER_TRUNK < size; offset += BUFFER_TRUNK) {
            putbuf((const char*) buffer + offset, BUFFER_TRUNK);
        }
        putbuf((const char*) buffer + offset, size - offset);
        unpin_vaddr_range(buffer, size);
        return size;
    }
    else {
        struct file_opened *fo = find_file_opened(fd);
        if (!fo || fo->closed || inode_is_dir(file_get_inode(fo->file))) {
            unpin_vaddr_range(buffer, size);
            return -1;
        }
        int result = file_write(fo->file, buffer, size);
        unpin_vaddr_range(buffer, size);
        return result;
    }
}

static void _seek (int fd, unsigned position) {
    struct file_opened *fo = find_file_opened(fd);
    if (!fo || fo->closed)
        return;

    file_seek(fo->file, position);
}

static unsigned _tell (int fd) {
    struct file_opened *fo = find_file_opened(fd);
    if (!fo || fo->closed)
        return (unsigned) -1;

    unsigned off = (unsigned) file_tell(fo->file);
    return off;
}

static void _close (int fd) {
    struct file_opened *fo = find_file_opened(fd);
    if (!fo || fo->closed)
        return;

    file_close(fo->file);
    fo->closed = true;
}

static mapid_t _mmap (int fd, void *addr) {
    struct thread *cur = thread_current();
    if (!addr || pg_ofs(addr) != 0 || addr >= STACK_LIMIT)
        return MAP_FAILED;

    struct file_opened *fo = find_file_opened(fd);
    if (!fo || fo->closed)
        return MAP_FAILED;

    int len = _filesize(fd);
    if (len == -1)
        return MAP_FAILED;

    size_t offset;
    for (offset = 0; offset < (size_t) len; offset += PGSIZE) {
        if (lookup_page(cur->pagedir, addr + offset, false))
            return MAP_FAILED;
    }

    struct file *f = file_reopen(fo->file);
    if (!f)
        return MAP_FAILED;

    struct mmap_entry *me = malloc(sizeof(struct mmap_entry));
    if (!me)
        return MAP_FAILED;
    me->mid = cur->num_mmap;
    cur->num_mmap++;
    me->user_vaddr = addr;
    me->file = f;
    me->num_pages = offset / PGSIZE;

    uint32_t read_bytes = (uint32_t) len;
    uint32_t zero_bytes = (uint32_t) offset - read_bytes;
    if (!load_lazy(f, 0, addr, read_bytes, zero_bytes, true, SUP_MMAP) ||
        hash_insert(&cur->mmap_table, &me->elem))
        return MAP_FAILED;

    return me->mid;
}

void munmap_entry(struct mmap_entry *me) {
    if (!me)
        return;

    struct thread *cur = thread_current();
    size_t i;
    for (i = 0; i < me->num_pages; ++i) {
        void *uaddr = me->user_vaddr + i * PGSIZE;
        struct sup_page_table_entry *se = sup_page_table_find(
                &cur->sup_page_table, uaddr);
        if (!se)
            continue;

        lock_acquire(&se->lock);
        se->pin = true;
        lock_release(&se->lock);
        if (pagedir_is_dirty(cur->pagedir, uaddr)) {
            file_write_at(se->file, uaddr, (off_t) se->read_bytes, se->offset);
        }

        lock_acquire(&frame_table.lock);
        struct frame_table_entry *fe = se->frame;
        if (fe) {
            list_remove(&fe->elem);
            list_remove(&fe->elem_owner);
            palloc_free_page(fe->frame);
            free(fe);
            pagedir_clear_page(cur->pagedir, se->user_vaddr);
        }
        lock_release(&frame_table.lock);

        hash_delete(&cur->sup_page_table, &se->elem);
        free(se);
    }
    hash_delete(&cur->mmap_table, &me->elem);
    file_close(me->file);
    free(me);
}

static void _munmap (mapid_t mapping) {
    struct mmap_entry me;
    me.mid = mapping;
    struct hash_elem *e = hash_find(&thread_current()->mmap_table, &me.elem);
    if (!e)
        return;
    munmap_entry(hash_entry(e, struct mmap_entry, elem));
}

static bool _chdir (const char *pathname) {
    struct thread *cur = thread_current();

    int length = is_readable_str_vaddr_range(pathname, PATHNAME_MAX);
    if (length == -1)
        _exit(-1);
    else if (length == -2) {
        unpin_str(pathname, PATHNAME_MAX);
        return false;
    }

    struct dir *dir;
    char *filename;
    int result = parse_pathname(pathname, &dir, &filename);
    if (result == -1) {
        return false;
    }
    else if (result == 2) {
        // root directory
        dir_close(cur->cwd);
        cur->cwd = dir_open_root();
        return true;
    }

    struct inode *inode = NULL;
    if (!dir_lookup(dir, filename, &inode) || !inode_is_dir(inode)) {
        dir_close(dir);
        free(filename);
        return false;
    }
    dir_close(dir);
    free(filename);
    dir_close(cur->cwd);
    cur->cwd = dir_open(inode);
    unpin_str(pathname, PATHNAME_MAX);
    return true;
}

static bool _mkdir (const char *pathname) {
    int length = is_readable_str_vaddr_range(pathname, PATHNAME_MAX);
    if (length == -1)
        _exit(-1);
    else if (length == -2) {
        unpin_str(pathname, PATHNAME_MAX);
        return false;
    }

    struct dir *dir;
    char *filename;
    int result = parse_pathname(pathname, &dir, &filename);
    if (result == -1 || result == 2) {
        unpin_str(pathname, PATHNAME_MAX);
        return false;
    }

    block_sector_t inode_sector = 0;

    bool success = free_map_allocate(1, &inode_sector)
            && dir_create(inode_sector, 16)
            && dir_add(dir, filename, inode_sector, true);

    if (!success && inode_sector != 0) {
        free_map_release(inode_sector, 1);
    }

    if (success) {
        struct dir *newdir = dir_open_sector(inode_sector);
        dir_add(newdir, ".", inode_sector, true);
        dir_add(newdir, "..", inode_get_inumber(dir_get_inode(dir)), true);
        dir_close(newdir);
    }

    dir_close(dir);
    free(filename);
    unpin_str(pathname, PATHNAME_MAX);
    return success;
}

static bool _readdir (int fd, char *filename) {
    int length = is_readable_str_vaddr_range(filename, NAME_MAX);
    if (length == -1)
        _exit(-1);
    else if (length == -2) {
        unpin_str(filename, NAME_MAX);
        return false;
    }

    struct file_opened *fo = find_file_opened(fd);
    if (!fo || fo->closed) {
        unpin_str(filename, NAME_MAX);
        return false;
    }

    struct file *file = fo->file;
    struct inode *inode = file_get_inode(file);
    if (!inode_is_dir(inode)) {
        unpin_str(filename, NAME_MAX);
        return false;
    }
    off_t pos = file_tell(file);
    struct dir *dir = dir_open(inode);
    dir_seek(dir, pos);
    bool result = dir_readdir(dir, filename);
    file_seek(file, dir_tell(dir));
    free(dir);
    unpin_str(filename, NAME_MAX);
    return result;
}

static bool _isdir (int fd) {
    struct file_opened *fo = find_file_opened(fd);
    if (!fo || fo->closed)
        return false;

    return inode_is_dir(file_get_inode(fo->file));
}

static int _inumber (int fd) {
    struct file_opened *fo = find_file_opened(fd);
    if (!fo || fo->closed)
        return -1;

    return inode_get_inumber(file_get_inode(fo->file));
}

static int thread_open_file_tail(struct file *f) {
    if (!f)
        return -1;

    struct thread *cur = thread_current();
    if (!cur->files) {
        cur->max_num_files = 16;
        cur->files = malloc(sizeof(struct file_opened) * 16);
        if (!cur->files)
            return -1;
    } else if (cur->num_files >= cur->max_num_files) {
        cur->max_num_files <<= 1;
        void *new_block = realloc(cur->files,
                sizeof(struct file_opened) * cur->max_num_files);
        if (!new_block)
            return -1;
        cur->files = new_block;
    }

    struct file_opened *fo = cur->files + cur->num_files;
    fo->file = f;
    fo->fd = cur->num_files + 3;
    fo->closed = false;
    cur->num_files++;
    return fo->fd;
}

static struct file_opened *find_file_opened(int fd) {
    if (fd <= 2)
        return NULL;

    struct thread *cur = thread_current();
    int index = fd - 3;
    if (index >= cur->num_files)
        return NULL;

    struct file_opened *fo = cur->files + index;
    if (fo->closed)
        return NULL;

    return fo;
}
