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
  //printf("\nin filesys create\n");
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
  //printf("\nin file open name is : %s\n",name);
  char *name_ = (char *)name;
  if (is_root(name_))
  {
    return inode_open(ROOT_DIR_SECTOR);
  }
  else
  {
    //printf("\nin is file open\n");
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
  //printf("\nin is extracting\n");
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
    // /* Name is too long to fit in one file. */
    // if (length > NAME_MAX)
    // {
    //   return -1;
    // }
    path++;
  }
  /* Substitude the original path with a new shorten, post-extracted path. */
  *full_path = path;
  /* Indicate the end of a string with a null pointer. */
  string[length] = '\0';
  return 1;
}

/* This is actually getting the last dir from the full_path, which in my opinion 
can be substituded by the way ref2 implemented. */
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
  //char *string, *temp_name;
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
  /* Parse the full_path in to string all the way until either 0: no mroe string -1: failure. 
    string is the next level name, fp is what left.*/
  while ((status = extract_next_string(string, &fp)) == 1)
  {
    /* Use temp_path to taken down the fp temperory, and parse one more time. */
    temp_path = fp;
    /* No more string to path */
    if (extract_next_string(temp_name, &temp_path) == 0)
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

  if (status == -1)
  {
    dir_close(dir);
  }
  else
  {
    strlcpy(file_name, string, NAME_MAX + 1);
    return dir;
  }
}

static bool
is_root(const char *path)
{
  //printf("\nin is root\n");
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
  //printf("\nin file create\n");
  struct inode *inode = inode_create(inode_sector, initial_size, false);
  if (inode == NULL || initial_size == 0)
    return inode;
  //printf("\nbefore inode create\n");
  if (inode_write_at(inode, "", 1, initial_size - 1) != 1)
  {
    //printf("\nafter inode write fail\n");
    inode_remove(inode);
    inode_close(inode);
    return NULL;
  }
  //printf("\nafter inode write success\n");
  return inode;
}

// /* Parse the given pathname into filename and dir return the status of paring */
// int parse_pathname(const char *pathname, struct dir **dir, char **filename)
// {
//   *dir = NULL;
//   *filename = NULL;

//   size_t len = strlen(pathname);
//   if (len == 0)
//     return -1;

//   char *path_buf = malloc(len + 1);
//   if (!path_buf)
//     return -1;
//   memcpy(path_buf, pathname, len + 1);

//   bool abso = (*path_buf == '/'); // absolute path starts with '/'
//   // relative directories always fail in removed cwd
//   if (!abso && dir_cwd_removed())
//   {
//     return -1;
//   }

//   char *last = path_buf + len - 1;
//   bool must_dir = (*last == '/');
//   while (last >= path_buf && *last == '/')
//   {
//     --last;
//   }
//   ++last;
//   if (last == path_buf)
//   {
//     // root directory
//     free(path_buf);
//     return 2;
//   }

//   // extract filename
//   *last = '\0';
//   --last; // should still >= path_buf
//   while (last >= path_buf && *last != '/')
//     --last;
//   ++last;

//   // the length of filename should be positive
//   size_t len_filename = strlen(last);
//   ASSERT(len_filename > 0);

//   struct dir *cd = abso ? dir_open_root() : dir_open_cwd();
//   char *token, *save_ptr;
//   for (token = strtok_r(path_buf, "/", &save_ptr);
//        token != last && token != NULL;
//        token = strtok_r(NULL, "/", &save_ptr))
//   {
//     struct inode *inode;
//     if (!dir_lookup(cd, token, &inode))
//     {
//       dir_close(cd);
//       free(path_buf);
//       return -1;
//     }
//     dir_close(cd);
//     cd = dir_open(inode);
//   }
//   *dir = cd;

//   *filename = malloc(len_filename + 1);
//   if (!*filename)
//   {
//     free(path_buf);
//     return -1;
//   }
//   memcpy(*filename, last, len_filename + 1);
//   free(path_buf);
//   return must_dir ? 1 : 0;
// }
// char *last = temp_path + len - 1;
// bool must_dir = (*last == '/');
// while (last >= temp_path && *last == '/')
// {
//   --last;
// }
// ++last;
// /* We reach the beginning from the end. */
// if (last == temp_path)
// {
//   // root directory
//   return NULL;
// }
// /* Set a new end.  */
// *last = '\0';
// /* Return back to the paresed new end. */
// --last;
// /* Here we extract the last part of the path, which is 
//   either a path name or a file name out first, and the rest shall
//   all be to path to this final name. */
// while (last >= temp_path && *last != '/')
//   --last;
// ++last;
// size_t len_filename = strlen(last);
// // printf("string lenth is %d\n\n\n\n",len_filename);
// ASSERT(len_filename > 0);

/* Parse the full_path in to string all the way until either 0: no mroe string -1: failure. 
    string is the next level name, fp is what left.*/
// while ((status = extract_next_string(string, &fp)) == 1)
// {
//   /* Use temp_path to taken down the fp temperory, and parse one more time. */
//   temp_path = fp;
//   /* No more string to path so that this path is a dir*/
//   if (extract_next_string(temp_name, &temp_path) == 0)
//     break;

//   /* find no file/dir named string in the give dir. */
//   if (dir_lookup(dir, string, &inode) == false)
//   {
//     dir_close(dir);
//     return NULL;
//   }
//   /* The next string is the filename not dir name. */
//   if (!inode_is_dir(inode))
//   {
//     inode_close(inode);
//     return NULL;
//   }

//   /* Close current dir and go one step deep. */
//   dir_close(dir);
//   dir = dir_open(inode);
// }
// char *token, *save_ptr;
// for (token = strtok_r(temp_path, "/", &save_ptr);
//      token != last && token != NULL;
//      token = strtok_r(NULL, "/", &save_ptr))
// {
//   struct inode *inode;
//   if (!dir_lookup(dir, token, &inode))
//   {
//     dir_close(dir);
//     return NULL;
//   }

//   if (!inode_is_dir(inode))
//   {
//     inode_close(inode);
//     return NULL;
//   }

//   dir_close(dir);
//   dir = dir_open(inode);
// }

// // if (status == -1)
// // {
// //   dir_close(dir);
// // }
// if (len_filename > NAME_MAX)
// {
//   dir_close(dir);
// }
// else
// {
//   strlcpy(file_name, last, len_filename + 1);
//   return dir;
// }