#include <stdio.h>
#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define SECTOR_PTR_CNT (BLOCK_SECTOR_SIZE / sizeof(block_sector_t))
/* Number of meta data. */
#define META_PTR_CNT (SECTOR_PTR_CNT - BLOCK_PTR_CNT)
/* Number of data sectors. */
#define BLOCK_PTR_CNT 12
/* Number of indirect data sectors. */
#define INDIRECT_BLOCK_CNT 1
/* Number of double indirect data sectors. */
#define DOUBLE_INDIRECT_BLOCK_CNT 1
/* Number of direct data sectors. */
#define DATA_BLOCK_CNT (BLOCK_PTR_CNT - INDIRECT_BLOCK_CNT - DOUBLE_INDIRECT_BLOCK_CNT)
/* Max length of inode, in bytes .*/
#define INODE_MAX_LENGTH ((DATA_BLOCK_CNT + \
                           SECTOR_PTR_CNT * INDIRECT_BLOCK_CNT + \
                           SECTOR_PTR_CNT * SECTOR_PTR_CNT * DOUBLE_INDIRECT_BLOCK_CNT) * \
                          BLOCK_SECTOR_SIZE)

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  block_sector_t sectors[BLOCK_PTR_CNT]; /* Sectors. */
  off_t length;                          /* File size in bytes. */
  int is_dir;                              /* File : 0 ; dir : 1 */
  unsigned magic;                        /* Magic number. */
  uint32_t unused[META_PTR_CNT - 3];
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors(off_t size)
{
  return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
{
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  struct lock inode_lock; /* Lock used for directory. */

  int being_written;            /* 0: writes ok, >0: deny writes. */
  struct lock writing_lock;     /* Lock for deny write. */
  struct condition writer_cond; /* Condition indicating no writers. */
  int writers;                  /* Can only deny write when there's no writer. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static void remove_inode(struct inode *inode);
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
struct inode *inode_create(block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode;
  struct cache_line *cl;

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  cl = cache_allocate(sector, true);
  disk_inode = cache_get_zero(cl);
  /* We give the new inode a length of 0 because we will extend it later when we want to write it beyond current EOF */
  disk_inode->length = 0;
  disk_inode->is_dir = is_dir ? 1 : 0;
  disk_inode->magic = INODE_MAGIC;
  cache_set_dirty(cl);
  cache_wake(cl, true);

  /* Here we open the node that we just created and allocate new sapce in memory for it. */
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
  int is_dir = disk_inode->is_dir;
  cache_wake(cl, false);
  return (is_dir == 1);
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
      inode->open_cnt++;
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
  inode->being_written = 0;
  inode->writers = 0;
  inode->removed = false;

  lock_init(&inode->inode_lock);
  lock_init(&inode->writing_lock);
  cond_init(&inode->writer_cond);

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

  lock_acquire(&lock_open_inodes);
  inode->open_cnt--;

  /* Release resources if this was the last opener. */
  if (inode->open_cnt == 0)
  {
    /* Remove from inode list and release lock.
    And write the dirty cache line into the disk. */
    list_remove(&inode->elem);
    lock_release(&lock_open_inodes);

    /* Deallocate blocks if removed. */
    if (inode->removed)
      remove_inode(inode);

    free(inode);
  }
  else
    lock_release(&lock_open_inodes);
}

/* Remove the inode when the inode is closed and removed. */
static void
remove_inode(struct inode *inode)
{
  struct cache_line *cl = cache_allocate(inode->sector, true);
  struct inode_disk *disk_inode = cache_get_data(cl);
  for (int i = 0; i < (int)BLOCK_PTR_CNT; i++)
  {
    block_sector_t sector = disk_inode->sectors[i];
    int level = 0;
    if (i == 10)
      level = 1;
    else if (i == 11)
      level = 2;

    if (sector != 0)
    {
      switch (level)
      {
      case 0:
      {
        /* Deallocate data block. */
        cache_free(sector);
        free_map_release(sector, 1);
        break;
      }
      case 1:
      {
        /* Deallocate indirect block. */
        struct cache_line *indirect_cl = cache_allocate(sector, true);
        block_sector_t *indirect_disk_inode = cache_get_data(indirect_cl);
        for (int j = 0; j < (int)SECTOR_PTR_CNT; j++)
        {
          block_sector_t direct_sector = indirect_disk_inode[j];
          if (direct_sector != 0)
          {
            cache_free(direct_sector);
            free_map_release(direct_sector, 1);
          }
        }
        cache_wake(indirect_cl, true);
        cache_free(sector);
        free_map_release(sector, 1);
        break;
      }
      case 2:
      {
        /* Deallocate double indirect block. */
        struct cache_line *double_indirect_cl = cache_allocate(sector, true);
        block_sector_t *double_indirect_disk_inode = cache_get_data(double_indirect_cl);
        for (int k = 0; k < (int)SECTOR_PTR_CNT; k++)
        {
          block_sector_t indirect_sector = double_indirect_disk_inode[k];
          if (indirect_sector != 0)
          {
            struct cache_line *indirect_cl = cache_allocate(indirect_sector, true);
            block_sector_t *indirect_disk_inode = cache_get_data(indirect_cl);
            for (int l = 0; l < (int)SECTOR_PTR_CNT; l++)
            {
              block_sector_t direct_sector = indirect_disk_inode[l];
              if (direct_sector != 0)
              {
                cache_free(direct_sector);
                free_map_release(direct_sector, 1);
              }
            }
            cache_wake(indirect_cl, true);
            cache_free(indirect_sector);
            free_map_release(indirect_sector, 1);
          }
        }
        cache_wake(double_indirect_cl, true);
        cache_free(sector);
        free_map_release(sector, 1);
        break;
      }
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

/* Right now, the data stored in an inode, which is also the data store in its disk_inode, is no longer contigeous, and needs to be located by some calculation due to the length of direct/indirect/double_indirect blocks. 
Read the data from inode at the sector where offset locates into cl_result.
is_write indicates if this functions is called by the write function so that we need to put some zeros in bewteen if go beyond EOF.*/
static bool
read_block(struct inode *inode, off_t offset,
           bool is_write, struct cache_line **cl_result)
{
  ASSERT(inode != NULL);
  ASSERT(offset >= 0);
  ASSERT(offset <= (off_t)INODE_MAX_LENGTH);

  /* First calculate offsets in different levels. */
  off_t sector_offs[3];
  int level;

  /* The total offsets in sector # of input offset */
  off_t sector_off = offset / BLOCK_SECTOR_SIZE;
  /* The largest number of sectors of direct data block ptr. */
  off_t bound0 = (off_t)DATA_BLOCK_CNT;
  /* The largest number of sector of direct and indirect block ptrs. */
  off_t bound1 = (off_t)(SECTOR_PTR_CNT * INDIRECT_BLOCK_CNT + DATA_BLOCK_CNT);

  if (sector_off < bound0)
  {
    /* Direct data block. */
    sector_offs[0] = sector_off;
    level = 1;
  }
  else if (sector_off < bound1)
  {
    /* Indirect block. */
    sector_off -= bound0;
    /* [0] indicates the off＃ in disk_inode array  */
    sector_offs[0] = DATA_BLOCK_CNT + sector_off / SECTOR_PTR_CNT;
    /* [1] indicates the off # in the block disk_inode which the indirect ptr points to*/
    sector_offs[1] = sector_off % SECTOR_PTR_CNT;
    level = 2;
  }
  else
  {
    sector_off -= bound0;
    /* Double indirect block. */
    sector_off -= SECTOR_PTR_CNT * INDIRECT_BLOCK_CNT;
    /* [0] indicates the off＃ in disk_inode array  */
    sector_offs[0] = DATA_BLOCK_CNT + INDIRECT_BLOCK_CNT +
                     sector_off / (SECTOR_PTR_CNT * SECTOR_PTR_CNT);
    /* [1] indicates the off # in the indirect block disk_inode array which the double_ indirect ptr points to*/
    sector_offs[1] = sector_off / SECTOR_PTR_CNT;
    /* [2] indicates the off # in the final exact disk_inode */
    sector_offs[2] = sector_off % SECTOR_PTR_CNT;
    level = 3;
  }

  level--;
  int this_level = 0;
  block_sector_t sector = inode->sector;
  struct cache_line *cl;
  uint32_t *data;
  block_sector_t *next_sector;
  struct cache_line *next_cl;
  while (1)
  {
    cl = cache_allocate(sector, false);
    data = cache_get_data(cl);
    next_sector = &data[sector_offs[this_level]];

    /* Next_sector == 0 indicates that there is no data in the returned  cache_line pointing inode*/
    if (*next_sector != 0)
    {
      if (this_level == level)
      {
        /* We find the block we need. */
        /* Do read ahead. */
        /* Make sure that at the current level of blocks there is at least on left in the disk_inode for us to do the read ahead. */
        if ((this_level == 0 && sector_offs[this_level] < (off_t)DATA_BLOCK_CNT - 1) || (this_level > 0 && sector_offs[this_level] < (off_t)SECTOR_PTR_CNT - 1))
        {
          block_sector_t readahead_sector = data[sector_offs[this_level] + 1];
          if (readahead_sector && readahead_sector < block_size(fs_device))
            add_to_prepare(readahead_sector);
        }

        cache_wake(cl, false);
        *cl_result = cache_allocate(*next_sector, is_write);
        return true;
      }

      /* So now, we didn't see the level of blocks we need, we start from the current block in current level and go one level deeper. */
      sector = *next_sector;
      cache_wake(cl, false);
      this_level++;
      continue;
    }

    cache_wake(cl, false);
    /* Now we dicover that at the block we are looking for, or during the way we are looking for it, there is no data at current level of block. */

    /* If read calls this function, then now the no_data indicates that we are beyond EOF so we return NULL in the result. */
    if (!is_write)
    {
      *cl_result = NULL;
      return true;
    }

    /* If we are in write and we are wrting to some EOF place, we allocate new place for it.
    We need to allocate a new sector. */
    cl = cache_allocate(sector, true);
    data = cache_get_data(cl);

    next_sector = &data[sector_offs[this_level]];
    /* Others may just allocate this sector, double check. */
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

    next_cl = cache_allocate(*next_sector, true);
    /* Zero out the new sector. */
    cache_get_zero(next_cl);

    cache_wake(cl, true);

    /* If this is the final level, return the new sector. */
    if (this_level == level)
    {
      *cl_result = next_cl;
      return true;
    }

    /* Not the final level, continue. */
    sector = *next_sector;
    cache_wake(next_cl, true);
    this_level++;
  }
}
/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  ASSERT(inode != NULL);
  ASSERT(offset >= 0);
  ASSERT(size >= 0);
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  while (size > 0)
  {
    /* Disk sector to read, starting byte offset within sector. */
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
    {
      break;
    }
    struct cache_line *cl;
    if (!read_block(inode, offset, false, &cl))
    {
      break;
    }

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
  ASSERT(inode != NULL);
  ASSERT(offset >= 0);
  ASSERT(size >= 0);
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  /* Check whether write is allowed. */
  lock_acquire(&inode->writing_lock);
  if (inode->being_written > 0)
  {
    lock_release(&inode->writing_lock);
    return 0;
  }

  inode->writers++;
  lock_release(&inode->writing_lock);

  while (size > 0)
  {
    /* Sector to write, starting byte offset within sector. */
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = (off_t)INODE_MAX_LENGTH - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;

    if (chunk_size <= 0)
      break;

    struct cache_line *cl;
    if (!read_block(inode, offset, true, &cl))
      break;
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
  struct cache_line *cl1 = cache_allocate(inode->sector, true);
  struct inode_disk *disk_inode1 = cache_get_data(cl1);
  if (offset > disk_inode1->length)
  {
    disk_inode1->length = offset;
    cache_set_dirty(cl1);
  }
  cache_wake(cl1, true);

  /* Finish writing, others can deny write now. */
  lock_acquire(&inode->writing_lock);
  if (--inode->writers == 0)
    cond_signal(&inode->writer_cond, &inode->writing_lock);
  lock_release(&inode->writing_lock);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode *inode)
{
  lock_acquire(&inode->writing_lock);
  /* Only can deny write when there's no writer. */
  while (inode->writers > 0)
    cond_wait(&inode->writer_cond, &inode->writing_lock);
  inode->being_written++;
  ASSERT(inode->being_written <= inode->open_cnt);
  lock_release(&inode->writing_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode *inode)
{
  lock_acquire(&inode->writing_lock);
  ASSERT(inode->being_written > 0);
  ASSERT(inode->being_written <= inode->open_cnt);
  inode->being_written--;
  lock_release(&inode->writing_lock);
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

bool  is_inode_open(struct inode *inode)
{
  int value;
  lock_acquire(&lock_open_inodes);
  value = inode->open_cnt;
  lock_release(&lock_open_inodes);
  return (value <= 1);
}