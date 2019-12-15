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

static void do_format (void);
static int next_string(char *string, char **full_path);
static struct dir* 
get_directory_from_path(char *file_name, char *full_path);


/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  cache_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/*put the next directory/file name into string
  return 1 if successful, 0 if end of path, -1 if name is too long*/
static int next_string(char *string, char **full_path)
{
  char *path = *full_path;
  int length = 0;

  while(*path == '/')
    path++; /*skipping all the leading / */
  if(*path == '\0') /*end of path */
    return 0;

  while(*path != '\0' && *path != '/')
  {
    string[length] = *path;
    length++;
    if (length > NAME_MAX)
      return -1;
    path++;
  }

  *full_path = path;
  string[length] = '\0';/*null terminated*/
  return 1;
}

/* get the corresponding directory according to full_path
   and store the file name in file_name */
static struct dir* 
get_directory_from_path(char *file_name, char *full_path)
{
  struct dir *directory = NULL;
  if (full_path == NULL)
    return directory;

  if(full_path[0] == '/') /*absolute path */
    {
      directory = dir_open_root ();
    }
  else/* relative path */
    {
      if(thread_current()->working_dir == NULL)
	{
	  thread_current()->working_dir = dir_open_root ();
	}
      directory = dir_reopen(thread_current()->working_dir);
    }
  if (directory == NULL)
    return NULL;
  char string[NAME_MAX+1];
  char temp_name[NAME_MAX+1];
  char *fp = full_path;
  char *temp_path = fp;
  struct inode *inode;
  int value;

  /*the path has no file name*/
  if (next_string(temp_name, &temp_path) == 0)
  {
    dir_close(directory);
    return NULL;
  }

  while((value = next_string(string, &fp)) == 1)
  {
    temp_path = fp;
    if (next_string(temp_name, &temp_path) == 0)
        break;/*we are at the end of path*/
    if (dir_lookup(directory, string, &inode) == false)
    {
      dir_close(directory);
      return NULL;
    }
    if (!inode_is_dir(inode)) 
    /*we find a file but we are not at the end of path */
    {
      inode_close(inode);
      return NULL;
    }

    dir_close(directory);
    directory = dir_open(inode);
  }

  if (value == -1)/* file name too long */
  {
    dir_close(directory);
    return NULL;
  } else {
    strlcpy(file_name, string, NAME_MAX+1);
    return directory;
  }
}

/* return true if name is '/'*/
static bool is_root(const char *name) 
{
  char temp_name[NAME_MAX+1];
  char *temp_path = (char *)name;
  if (name[0] == '/' && next_string(temp_name, &temp_path) == 0)
    return true;
  return false;
}


/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  cache_flush ();
  free_map_close ();
}

/* create a file according to inode_sector and initial_size*/
static struct inode*
file_create(block_sector_t inode_sector,off_t initial_size)
{
  struct inode *inode = inode_create (inode_sector,false);
  if (inode == NULL || initial_size == 0)
    return inode;
  if (inode_write_at(inode, "", 1, initial_size - 1) !=1)
  {
    inode_remove(inode);
    inode_close(inode);
    return NULL;
  }

  return inode;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name_, off_t initial_size, bool isdir) 
{
  block_sector_t inode_sector = 0;
  char *name = (char *)name_;
  struct inode *inode = NULL;
  char file_name[NAME_MAX+1];
  struct dir *dir = get_directory_from_path(file_name, name);
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector));
  if (success)
  {
    if (isdir)
      {
	if (dir_create (inode_sector, inode_get_inumber(dir_get_inode (dir))))
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
        inode_close(inode);
      } else {
        success = false;
        inode_remove(inode);
        inode_close(inode);
      }
    } else {
      success = false;
    }
  }

  dir_close (dir);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct inode *
filesys_open (const char *name_)
{
  char *name = (char *)name_;
  if (is_root(name))
    return inode_open (ROOT_DIR_SECTOR);
  else
  {
    char file_name[NAME_MAX+1];
    struct dir *dir = get_directory_from_path(file_name, name);
    if (dir != NULL)
    {
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
    return NULL;
  }
}


/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name_) 
{
  char *name = (char *)name_;
  char file_name[NAME_MAX+1];
  struct dir *dir = get_directory_from_path(file_name, name);
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

/*change current direcotry to NAME
  return true if successful
  false if NAME is not valid */
bool
filesys_chdir (const char *name) 
{
  bool success = false;
  struct dir *dir = dir_open(filesys_open (name));
  if (dir != NULL)
  {
    dir_close(thread_current()->working_dir);
    thread_current()->working_dir = dir;
    success = true;
  }

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  /*root directory is its own parent */
  if (!dir_create (ROOT_DIR_SECTOR, ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
