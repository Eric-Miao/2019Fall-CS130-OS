#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
static size_t bytes_to_sectors(off_t);
static void remove_inode(struct inode *);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static size_t
bytes_to_sectors(off_t size)
{
  return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE);
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
//   static block_sector_t
//   byte_to_sector(const struct inode *inode, off_t pos)
//   {
//     ASSERT(inode != NULL);
//     if (pos < inode->data.length)
//       return inode->data.start + pos / BLOCK_SECTOR_SIZE;
//     else
//       return -1;
// }

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
/* Lock to prevent change to list: open_inodes. */
static struct lock lock_open_inodes;

/* Initializes the inode module. */
void inode_init(void)
{
  list_init(&open_inodes);
  lock_init(&lock_open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
struct inode *
inode_create(block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;

  struct cache_line *cache_line;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  cache_line = cache_allocate(sector, true);
  disk_inode = cache_get_zero(cache_line);
  disk_inode->length = 0;
  disk_inode->is_dir = is_dir ? 1 : 0;
  disk_inode->magic = INODE_MAGIC;
  cache_set_dirty(cache_line);
  cache_wake(cache_line, true);

  struct inode *inode = inode_open(sector);
  if (inode == NULL)
  {
    cache_free(sector);
    free_map_release(sector, 1);
  }
  return inode;
}

/* Check whether this inode is a directory inode. */
bool inode_is_dir(struct inode *inode)
{
  if (inode == NULL)
    return false;
  struct cache_line *cl = cache_allocate(inode->sector, false);
  struct inode_disk *disk_inode = cache_get_data(cl);
  bool type = disk_inode->is_dir;
  cache_wake(cl, false);
  return (type);
}
/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open(block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  lock_acquire(&lock_open_inodes);
  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes);
       e = list_next(e))
  {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector)
    {
      inode_reopen(inode);
      lock_release(&lock_open_inodes);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
  {
    lock_release(&lock_open_inodes);
    return NULL;
  }

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  // block_read (fs_device, inode->sector, &inode->data);

  /* Should also init the con var or lock here for deny write. */
  lock_init(&inode->inode_lock);
  lock_init(&inode->writer_lock);
  cond_init(&inode->writer_cond);
  inode->being_written = 0;

  lock_release(&lock_open_inodes);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen(struct inode *inode)
{
  if (inode != NULL)
  {
    lock_acquire(&lock_open_inodes);
    inode->open_cnt++;
    lock_release(&lock_open_inodes);
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber(const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
  {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed)
      remove_inode(inode);
    free(inode);
  }
}
static void
remove_inode(struct inode *inode)
{
  struct cache_line *cl = cache_allocate(inode->sector, true);
  struct inode_disk *disk_inode = cache_get_data(cl);

  for (int i = 0; i < NUM_TOTAL_SECTOR_IN_ARRAY; i++)
  {
    block_sector_t sector = disk_inode->blocks[i];
    if (sector != 0)
    {
      int level = (i >= (int)NUM_DATA_SECTOR) +
                  (i >= (int)(NUM_DATA_SECTOR + NUM_INDIRECT_SECTOR));
      switch (level)
      {
      case 0:
      {
        cache_free(sector);
        free_map_release(sector, 1);
        break;
      }

      case 1:
      {
        struct cache_line *ce_indirect = cache_allocate(sector, true);
        block_sector_t *disk_inode_indirect = cache_get_data(ce_indirect);

        for (int j = 0; j < NUM_BLOCK_PTR_PER_INODE; j++)
        {
          block_sector_t sector_indirect = disk_inode_indirect[j];
          if (sector_indirect != 0)
          {
            cache_free(sector_indirect);
            free_map_release(sector_indirect, 1);
          }
        }
        cache_wake(ce_indirect, true);
        cache_free(sector);
        free_map_release(sector, 1);
        break;
      }
      case 2:
      {
        struct cache_line *ce_indirect = cache_allocate(sector, true);
        block_sector_t *disk_inode_indirect = cache_get_data(ce_indirect);

        for (int j = 0; j < NUM_BLOCK_PTR_PER_INODE; j++)
        {
          block_sector_t sector_indirect = disk_inode_indirect[j];
          if (sector_indirect != 0)
          {
            struct cache_line *ce_doub_indirect = cache_allocate(sector_indirect, true);
            block_sector_t *disk_inode_doub_indirect = cache_get_data(ce_indirect);

            for (int j = 0; j < NUM_BLOCK_PTR_PER_INODE; j++)
            {
              block_sector_t sector_doub_indirect = disk_inode_doub_indirect[j];
              if (sector_doub_indirect != 0)
              {
                cache_free(sector_doub_indirect);
                free_map_release(sector_doub_indirect, 1);
              }
            }
            cache_wake(ce_doub_indirect, true);
            cache_free(sector_indirect);
            free_map_release(sector_indirect, 1);
          }
        }
        cache_wake(ce_indirect, true);
        cache_free(sector);
        free_map_release(sector, 1);
        break;
      }
      default:
        break;
      }
    }
  }

  cache_wake(cl, true);
  cache_free(inode->sector);
  free_map_release(inode->sector, 1);
  return;
}
/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode *inode)
{
  ASSERT(inode != NULL);
  inode->removed = true;
}

static bool
read_block(struct inode *inode, off_t offset, bool is_write, struct cache_line **cl_result)
{
  /* Check basic properties. */
  ASSERT(inode != NULL);
  ASSERT(offset >= 0);
  ASSERT(offset <= (off_t)INODE_MAX_LENGTH);

  /* Offset in 3 different level. */
  off_t sector_offs[3];
  int level;

  /* Calculate the total offset by sector indicated by the offset. */
  off_t sector_offset_total = offset / BLOCK_SECTOR_SIZE;

  off_t bound0 = NUM_DATA_SECTOR;
  off_t bound1 = bound0 + NUM_BLOCK_PTR_PER_INODE * NUM_INDIRECT_SECTOR;

  if (sector_offset_total < bound0)
  {
    level = 0;
    sector_offs[0] = sector_offset_total;
  }
  else if (sector_offset_total < bound1)
  {
    level = 1;
    sector_offs[0] = NUM_DATA_SECTOR + sector_offset_total / NUM_BLOCK_PTR_PER_INODE;
    sector_offs[1] = sector_offset_total % NUM_BLOCK_PTR_PER_INODE;
  }
  else
  {
    level = 2;
    sector_offs[0] = NUM_DATA_SECTOR + NUM_INDIRECT_SECTOR +
                     sector_offset_total / (NUM_BLOCK_PTR_PER_INODE * NUM_BLOCK_PTR_PER_INODE);
    sector_offs[1] = sector_offset_total / NUM_BLOCK_PTR_PER_INODE;
    sector_offs[2] = sector_offset_total % NUM_BLOCK_PTR_PER_INODE;
  }

  int this_level = 0;
  block_sector_t sector = inode->sector;
  struct cache_line *cl;
  uint32_t *data;
  block_sector_t *next_sector;
  struct cache_line *next_ce;

  while (true)
  {
    cl = cache_allocate(sector, false);
    data = cache_get_data(cl);
    next_sector = &data[sector_offs[this_level]];

    /* Check if we have the 'next level sectors.' */
    if (*next_sector != 0)
    {
      /* Check if we are at the correct level of inodes */
      if (this_level == level)
      {
        /* Do the read ahead by locate one sector beyond the given one. */
        if ((this_level == 0 && sector_offs[this_level] < (off_t)NUM_DATA_SECTOR - 1) || (this_level > 0 && sector_offs[this_level] < (off_t)NUM_BLOCK_PTR_PER_INODE - 1))
        {
          block_sector_t readahead_sector = data[sector_offs[this_level] + 1];
          if (readahead_sector && readahead_sector < block_size(fs_device))
            add_to_prepare(readahead_sector);
        }

        cache_wake(cl, false);
        *cl_result = cache_allocate(*next_sector, is_write);
        return true;
      }
      sector = *next_sector;
      cache_wake(cl, false);
      this_level++;
      continue;
    }
    cache_wake(cl, false);

    if (!is_write)
    {
      *cl_result = NULL;
      return true;
    }

    /* Need to allocate a new sector. */
    cl = cache_allocate(sector, true);
    data = cache_get_data(cl);

    next_sector = &data[sector_offs[this_level]];

    if (*next_sector != 0)
    {
      cache_wake(cl, true);
      continue;
    }

    /* Allocate the sector in disk. */
    if (!free_map_allocate(1, next_sector))
    {
      cache_wake(cl, true);
      *cl_result = NULL;
      return false;
    }

    cache_set_dirty(cl);
    next_ce = cache_allocate(*next_sector, true);
    cache_get_zero(next_ce);

    cache_wake(cl, true);

    if (this_level == level)
    {
      *cl_result = next_ce;
      return true;
    }

    sector = *next_sector;
    cache_wake(next_ce, true);
    this_level++;
  }
}
/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0)
  {
    /* Disk sector to read, starting byte offset within sector. */
    // block_sector_t sector_idx = byte_to_sector (inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    // if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
    //   {
    //     /* Read full sector directly into caller's buffer. */
    //     block_read (fs_device, sector_idx, buffer + bytes_read);
    //   }
    // else
    //   {
    //     /* Read sector into bounce buffer, then partially copy
    //        into caller's buffer. */
    //     if (bounce == NULL)
    //       {
    //         bounce = malloc (BLOCK_SECTOR_SIZE);
    //         if (bounce == NULL)
    //           break;
    //       }
    //     block_read (fs_device, sector_idx, bounce);
    //     memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
    //   }

    struct cache_line *cl;
    if (!read_block(inode, offset, false, &cl))
      break;

    if (cl == NULL)
      memset(buffer + bytes_read, 0, chunk_size);
    else
    {
      uint8_t *data = cache_get_data(cl);
      memcpy(buffer + bytes_read, data + sector_ofs, chunk_size);
      cache_wake(cl, false);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  // free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode *inode, const void *buffer_, off_t size,
                     off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  /* Check whether write is allowed. */
  lock_acquire(&inode->writer_lock);
  if (inode->deny_write_cnt > 0)
  {
    lock_release(&inode->writer_lock);
    return 0;
  }

  inode->being_written++;
  lock_release(&inode->writer_lock);
  while (size > 0)
  {
    /* Sector to write, starting byte offset within sector. */
    // block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = (off_t)INODE_MAX_LENGTH - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;
    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
    {
      break;
    }

    struct cache_line *cl;
    if (!read_block(inode, offset, true, &cl))
    {
      break;
    }
    uint8_t *data = cache_get_data(cl);
    memcpy(data + sector_ofs, buffer + bytes_written, chunk_size);
    cache_set_dirty(cl);
    cache_wake(cl, true);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  /* Extend File. */
  struct cache_line *ce1 = cache_allocate(inode->sector, true);
  struct inode_disk *disk_inode1 = cache_get_data(ce1);
  if (offset > disk_inode1->length)
  {
    disk_inode1->length = offset;
    cache_set_dirty(ce1);
  }
  cache_wake(ce1, true);

  /* Finish writing, others can deny write now. */
  lock_acquire(&inode->writer_lock);
  if (--inode->being_written == 0)
    cond_signal(&inode->writer_cond, &inode->writer_lock);
  lock_release(&inode->writer_lock);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode *inode)
{
  lock_acquire(&inode->writer_lock);

  /* Only can deny write when there's no writer. */
  while (inode->being_written > 0)
    cond_wait(&inode->writer_cond, &inode->writer_lock);
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  lock_release(&inode->writer_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode *inode)
{
  lock_acquire(&inode->writer_lock);
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release(&inode->writer_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode *inode)
{
  struct cache_line *cl = cache_allocate(inode->sector, false);
  struct inode_disk *disk_inode = cache_get_data(cl);

  off_t length = disk_inode->length;
  cache_wake(cl, false);
  return length;
}

void inode_acquire_lock(struct inode *inode)
{
  lock_acquire(&inode->inode_lock);
}

void inode_release_lock(struct inode *inode)
{
  lock_release(&inode->inode_lock);
}