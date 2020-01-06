#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include <threads/thread.h>
#include "filesys/cache.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/malloc.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format)
{
    fs_device = block_get_role (BLOCK_FILESYS);
    if (fs_device == NULL)
        PANIC ("No file system device found, can't initialize file system.");

    inode_init ();
    free_map_init ();
    cache_init ();

    if (format)
        do_format ();

    free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void)
{
    free_map_close ();
    cache_flush_all ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *pathname, off_t initial_size)
{
    block_sector_t inode_sector = 0;
    struct dir *dir;
    char *filename;
    int result = parse_pathname(pathname, &dir, &filename);
    // only creating a file other than directory (return 0) is valid
    if (result)
        return false;

    bool success = (dir != NULL
                    && free_map_allocate (1, &inode_sector)
                    && inode_create (inode_sector, initial_size, false)
                    && dir_add (dir, filename, inode_sector, false));
    if (!success && inode_sector != 0)
        free_map_release (inode_sector, 1);
    dir_close (dir);
    free(filename);
    return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *pathname)
{
    struct dir *dir;
    char *filename;
    int result = parse_pathname(pathname, &dir, &filename);
    if (result == -1)
        return false;
    // open a root directory directly
    else if (result == 2)
        return file_open(inode_open(ROOT_DIR_SECTOR));

    // otherwise, open a file (or directory) under a directory
    struct inode *inode = NULL;
    if (dir != NULL)
        dir_lookup(dir, filename, &inode);
    dir_close(dir);
    free(filename);
    return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *pathname)
{
    struct dir *dir;
    char *filename;
    int result = parse_pathname(pathname, &dir, &filename);
    // parsing error or trying to remove a root directory
    if (result == -1 || result == 2)
        return false;

    if (!strcmp(filename, ".") || !strcmp(filename, "..")) {
        dir_close(dir);
        free (filename);
        return false;
    }

    bool success = dir != NULL && dir_remove (dir, filename);
    dir_close(dir);
    free(filename);
    return success;
}

int parse_pathname(const char *pathname, struct dir **dir, char **filename) {
    *dir = NULL;
    *filename = NULL;

    size_t len = strlen(pathname);
    if (len == 0)
        return -1;

    char *path_buf = malloc(len + 1);
    if (!path_buf)
        return -1;
    memcpy(path_buf, pathname, len + 1);

    bool abso = (*path_buf == '/');    // absolute path starts with '/'
    // relative directories always fail in removed cwd
    if (!abso && dir_cwd_removed()) {
        return -1;
    }

    char *last = path_buf + len - 1;
    bool must_dir = (*last == '/');
    while (last >= path_buf && *last == '/') {
        --last;
    }
    ++last;
    if (last == path_buf) {
        // root directory
        free(path_buf);
        return 2;
    }

    // extract filename
    *last = '\0';
    --last;    // should still >= path_buf
    while (last >= path_buf && *last != '/')
        --last;
    ++last;

    // the length of filename should be positive
    size_t len_filename = strlen(last);
    ASSERT(len_filename > 0);

    struct dir *cd = abso ? dir_open_root() : dir_open_cwd();
    char *token, *save_ptr;
    for (token = strtok_r(path_buf, "/", &save_ptr);
         token != last && token != NULL;
         token = strtok_r(NULL, "/", &save_ptr)) {
        struct inode *inode;
        if (!dir_lookup(cd, token, &inode)) {
            dir_close(cd);
            free(path_buf);
            return -1;
        }
        dir_close(cd);
        cd = dir_open(inode);
    }
    *dir = cd;

    *filename = malloc(len_filename + 1);
    if (!*filename) {
        free(path_buf);
        return -1;
    }
    memcpy(*filename, last, len_filename + 1);
    free(path_buf);
    return must_dir ? 1 : 0;
}

/* Formats the file system. */
static void
do_format (void)
{
    printf ("Formatting file system...");
    free_map_create ();
    if (!dir_create (ROOT_DIR_SECTOR, 16))
        PANIC ("root directory creation failed");
    struct dir *dir = dir_open_root();
    dir_add(dir, ".", ROOT_DIR_SECTOR, true);
    dir_add(dir, "..", ROOT_DIR_SECTOR, true);
    dir_close(dir);
    free_map_close ();
    printf ("done.\n");
}
