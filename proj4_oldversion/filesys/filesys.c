#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format(void);
static int extract_next_string(char *, char **);
static struct dir *get_dir_from_path(char *, char *);
static struct inode *file_create(block_sector_t, off_t);
static bool is_root(const char *);

/* Initializes the file system module.
If FORMAT is true, reformats the file system. */
void filesys_init(bool format)
{
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();
  cache_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void)
{
  cache_clear();
  free_map_close();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char *name, off_t initial_size, bool isdir)
{
  block_sector_t inode_sector = 0;
  char *name_ = (char *)name;
  struct inode *inode = NULL;
  char file_name[NAME_MAX + 1];
  struct dir *dir = get_dir_from_path(file_name, name_);
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector));
  if (success)
  {
    if (isdir)
    {
      if (dir_create(inode_sector, inode_get_inumber(dir_get_inode(dir))))
      {
        inode = inode_open(inode_sector);
      }
    }
    else
    {
      inode = file_create(inode_sector, initial_size);
    }

    if (inode != NULL)
    {
      if (dir_add(dir, file_name, inode_sector))
      {
        success = true;
        goto done;
      }
      else
      {
        success = false;
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

  dir_close(dir);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open(const char *name)
{
  char *name_ = (char *)name;
  if (is_root(name_))
  {
    return inode_open(ROOT_DIR_SECTOR);
  }
  else
  {
    char file_name[NAME_MAX + 1];
    struct dir *dir = get_dir_from_path(file_name, name_);
    /* Cannot path a file from the given path. */
    if (dir == NULL)
      return NULL;

    struct inode *inode;
    if (dir_lookup(dir, file_name, &inode))
    {
      dir_close(dir);
      return inode;
    }
    else
    {
      dir_close(dir);
      return NULL;
    }
  }
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char *name)
{
  char *name_ = (char *)name;
  char file_name[NAME_MAX + 1];
  struct dir *dir = get_dir_from_path(file_name, name_);
  if (dir == NULL)
    return false;
  else
  {
    if (dir_remove(dir, file_name))
    {
      dir_close(dir);
      return true;
    }
    else
      return false;
  }
}

/* Formats the file system. */
static void
do_format(void)
{
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}

/* change the working dir of current thread the NAME. */
bool filesys_chdir(const char *name)
{
  bool success = false;
  struct dir *dir = dir_open(filesys_open(name));
  if (dir != NULL)
  {
    dir_close(thread_current()->directory);
    thread_current()->directory = dir;
    success = true;
  }
  return success;
}

/* Extract the next string from the full_path into string
  and shorten the full_path with the string extracted.
  Return 0: no more string to extract, 1: succeed, -1: failure with over_length name.
*/
static int
extract_next_string(char *string, char **full_path)
{
  char *path = *full_path;
  int length = 0;
  while (*path == '/')
    path++;
  /* From the head all the way to the end is '/' */
  if (*path == '\0')
    return 0;
  while (*path != '\0' && *path != '/')
  {
    string[length] = *path;
    length++;
    path++;
  }
  /* Substitude the original path with a new shorten, post-extracted path. */
  *full_path = path;
  /* Indicate the end of a string with a null pointer. */
  string[length] = '\0';
  return 1;
}

/* This is actually getting the last dir from the full_path
We require a path, an string to store the parsed filename and the dir the filename
belongs to.
 */
static struct dir *
get_dir_from_path(char *file_name, char *full_path)
{
  struct dir *dir = NULL;
  if (full_path == NULL)
    return dir;

  /* Before we start parse the dir from path,
  we first locate oursevles at the root dir, or
  the current working_dir if exists. */
  /* Start with '/' is a absolute addr. */
  if (full_path[0] == '/')
    dir = dir_open_root();

  /* Otherwise, this should be relative path. */
  else
  {
    if (thread_current()->directory == NULL)
      thread_current()->directory = dir_open_root();

    dir = dir_reopen(thread_current()->directory);
  }
  /* Something wrong with the open operations above. */
  if (dir == NULL)
    return NULL;

  char string[NAME_MAX + 1];
  char temp_name[NAME_MAX + 1];
  char *fp = full_path;
  char *temp_path = fp;
  struct inode *inode;
  int status;

  /* No more string to parse except for '/' */
  if (extract_next_string(temp_name, &temp_path) == 0)
  {
    /* Get no more new dir from the path, so exit with NULL */
    dir_close(dir);
    return NULL;
  }

  int len = strlen(full_path);
  char *last = fp + len - 1;
  while (last >= fp && *last == '/')
  {
    --last;
  }
  ++last;
  /* Parse the full_path in to string all the way until either 0: no mroe string -1: failure. 
    string is the next level name, fp is what left.*/
  while ((status = extract_next_string(string, &fp)) == 1)
  {
    /* Use temp_path to taken down the fp temperory, and parse one more time. */
    if (fp == last)
      break;

    /* find no file/dir named string in the give dir. */
    if (dir_lookup(dir, string, &inode) == false)
    {
      dir_close(dir);
      return NULL;
    }
    /* The next string is the filename not dir name. */
    if (!inode_is_dir(inode))
    {
      inode_close(inode);
      return NULL;
    }

    /* Close current dir and go one step deep. */
    dir_close(dir);
    dir = dir_open(inode);
  }
  strlcpy(file_name, string, NAME_MAX + 1);
  return dir;
}

/* Check if the input path is a root dir, return true if so. */
static bool
is_root(const char *path)
{
  char *temp_path = (char *)path;
  if (path[0] == '/')
  {
    while (*temp_path == '/')
      temp_path++;
    /* From the head all the way to the end is '/' */
    if (*temp_path == '\0')
      return true;
    else
      return false;
  }
  return false;
}

/* This could be simplified in to the function filesys_create as we did in the pre_version. */
static struct inode *
file_create(block_sector_t inode_sector, off_t initial_size)
{
  struct inode *inode = inode_create(inode_sector, initial_size, false);
  if (inode == NULL || initial_size == 0)
    return inode;
  if (inode_write_at(inode, "", 1, initial_size - 1) != 1)
  {
    inode_remove(inode);
    inode_close(inode);
    return NULL;
  }
  return inode;
}