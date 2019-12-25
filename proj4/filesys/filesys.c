#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/thread.h"
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
  cache_init();
  free_map_init ();

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
  cache_clear();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  block_sector_t inode_sector = 0;
  struct dir *dir;
  struct inode *inode;
  char* filename;
  bool success;

  int open_status = parse_path(name, &dir, &filename);
  /* Only create files no dir */
  if (open_status != 1)
    return false;

  success = (dir != NULL && free_map_allocate (1, &inode_sector));

  if (success)
  {
    inode = inode_create(inode_sector, initial_size, false);

    if (inode_write_at(inode, "", 1, initial_size - 1) != 1)
    {
      success = false;
      goto done;
    }

    if (inode != NULL)
    {
      if (dir_add(dir, name, inode_sector,false))
      {
        success = true;
        goto done;
      }
      else
      {
        success=false;
        goto done;
      }
    }
    else
    {
      success = false;
      goto done;
    }
    
  }

done:
  if (inode != NULL)
  {  
    inode_close(inode);
    if (!success)
      inode_remove(inode); 
  }

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
filesys_open (const char *name)
{
  struct dir *dir = dir_open_root ();
  char *filename;
  struct inode *inode = NULL;

  int result = parse_path(name, &dir, &filename);
  if (result == -1)
    return false;
  if (result == 2)
    return file_open(inode_open(ROOT_DIR_SECTOR));

  if (dir != NULL)
    if(!dir_lookup (dir, name, &inode))
    {
      dir_close(dir);
      return NULL;
    }
  dir_close (dir);

  free(filename);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct dir *dir;
  char *filename;
  int result = parse_path(name, &dir, &filename);
  bool success;

  /* Root dir cannot be removed and if fail parsing */
  if (result == -1 || result == 2 || dir == NULL)
    return false;

  /* In case there are . and .. */
  if (!strcmp(filename, ".") || !strcmp(filename, ".."))
  {
    dir_close(dir);
    free(filename);
    return false;
  }

  success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);
  free(filename);

  return success;
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

/* parse the filename from the pathname.
  Store the parsed name into filename.
  Store the opeded inode of dir in dir if the pathname is a dir.
  return value -1:fail; 0:file; 1:dir; 2:root dir */
int 
parse_path(const char *pathname, struct dir **dir, char **filename)
{
  int ret;
  char *path_buffer;
  char *ptr_last;
  char *token, *save_ptr;
  bool if_absolute;
  bool if_dir;
  struct dir *cwd;

  *dir = NULL;
  *filename = NULL;

  size_t len = strlen(pathname);
  /* invalid name: empty name */
  if (len == 0)
  {    
    ret = -1;
    goto done;
  }

  path_buffer = malloc(len + 1);
  /* invalid operations: malloc fail */
  if (!path_buffer)
  {
    ret = -1;
    goto done;
  }
  memcpy(path_buffer, pathname, len+1);

  /* If a path begins with '/', it's a absolute addr. */
  if_absolute = (*path_buffer == '/');
  /* dir_cwd_removed check if current cwd exists.
    which is only a problem with relative path because 
    it depends on the relative path to locate the file.*/
  if (!if_absolute && inode_removed(thread_current()->directory->inode))
  {
    free(path_buffer);
    ret = -1;
    goto done;
  }

  ptr_last = path_buffer + len - 1;
  /* If the path ends with a '/', it's a dir rather than
    a file. */
  if_dir = (*ptr_last == '/');
  while (ptr_last > path_buffer && *ptr_last == '/')
    ptr_last--;
  /* Go all the way to the begin point of the pathname
    If the whole path is ///////, this is a root dir.
    Otherwise the last points at the last not / position's / behind that. */
  if (ptr_last == '/')
  {
    free(path_buffer);
    ret = 2;
    goto done;
  }

  /* Now it's time to abstract the filename */
  /* This set the prt to become a char string. */
  *(ptr_last + 1)= '\0';
  while (ptr_last >= path_buffer && *ptr_last != '/')
    --ptr_last;
  ++ptr_last;
  /* Now the ptr shall stop at the beginning position of file name.*/

  size_t len_filename = strlen(ptr_last);
  /* For bebug, check the len_filename > 0. */
  ASSERT(len_filename > 0);
  if (len_filename > NAME_MAX)
  {    
    ret = -1;
    goto done;
  }

  cwd = if_absolute ? dir_open_root() : dir_open_current();
  for (token = strtok_r(path_buffer, "/", &save_ptr);
       token != ptr_last && token != NULL;
       token = strtok_r(NULL, "/", &save_ptr))
  {
    struct inode *inode;
    /* Check if we have the file named token in cwd. */
    if (!dir_lookup(cwd, token, &inode))
    {
      dir_close(cwd);
      free(path_buffer);
      ret = -1;
      goto done;
    }
    dir_close(cwd);
    cwd = dir_open(inode);
  }
  *dir = cwd;

  *filename = malloc(len_filename + 1);
  if (!*filename)
  {
    free(path_buffer);
    ret -1;
    goto done;
  }

  /* extracted filename stored into *filename */
  memcpy(*filename, ptr_last, len_filename + 1);
  free(path_buffer);
  ret = 1 ? if_dir : 0;
  goto done;

  done:
    return ret;
}