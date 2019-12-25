#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
/* Sector pointer number per block_sector_size, the size of struct disk_inode.  */
#define NUM_BLOCK_PTR_PER_INODE (BLOCK_SECTOR_SIZE / sizeof(block_sector_t))
/* Number of other mata property except the arrary in disk_inode. */
#define NUM_META_EXCEPT_ARRARY 3
/* Number of direct data sectors in arrary */
#define NUM_DATA_SECTOR 10
/* Number of 1st order indirect sectors */
#define NUM_INDIRECT_SECTOR 1
/* Number of 2nd order double indirect sectors */
#define NUM_DOUBLE_INDIRECT_SECTOR 1
/* Used to set the size of the array  */
#define NUM_TOTAL_SECTOR_IN_ARRAY (NUM_DATA_SECTOR + NUM_INDIRECT_SECTOR + NUM_DOUBLE_INDIRECT_SECTOR)
/* Number of unused space in disk_inode to align with BLOCK_SECTOR_SIZE.*/
#define NUM_UNUSED_SECOTR (NUM_BLOCK_PTR_PER_INODE - NUM_META_EXCEPT_ARRARY - NUM_TOTAL_SECTOR_IN_ARRAY)
/* Max length of inode, in bytes .*/
#define INODE_MAX_LENGTH ((NUM_DATA_SECTOR +                                                                 \
                           NUM_BLOCK_PTR_PER_INODE * NUM_INDIRECT_SECTOR +                                   \
                           NUM_BLOCK_PTR_PER_INODE * NUM_BLOCK_PTR_PER_INODE * NUM_DOUBLE_INDIRECT_SECTOR) * \
                          BLOCK_SECTOR_SIZE)

struct bitmap;
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  // block_sector_t start;               /* First data sector. */
  off_t length;                       /* File size in bytes. */
  unsigned magic;                     /* Magic number. */
  bool is_dir;                        /* Dir: True File: False */
  uint32_t unused[NUM_UNUSED_SECOTR]; /* Not used to align. */
  /* Below are self defined properties */
  block_sector_t blocks[NUM_TOTAL_SECTOR_IN_ARRAY]; /* Array of blocks for data, 10+1+1. */
};

/* In-memory inode. */
struct inode
{
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */

  /* Below are self defined properties */
  struct lock inode_lock;       /* A node needed to acquire before any operation. */
  struct lock writer_lock;      /* Lock correspond to the cond var. */
  struct condition writer_cond; /* The conditions to raise all writers when no wrtier. */
  int being_written;            /* Indicate if the inode is being modified. */
};

void inode_init (void);
struct inode* inode_create(block_sector_t, off_t, bool);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);

/* self-defined */
bool inode_is_dir (struct inode*);
void inode_acquire_lock(struct inode*);
void inode_acquire_lock(struct inode*);

#endif /* filesys/inode.h */