// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/pxt4/balloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  Enhanced block allocation by Stephen Tweedie (sct@redhat.com), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/time.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include "pxt4.h"
#include "pxt4_jbd3.h"
#include "mballoc.h"

#include <trace/events/pxt4.h>

static unsigned pxt4_num_base_meta_clusters(struct super_block *sb,
					    pxt4_group_t block_group);
/*
 * balloc.c contains the blocks allocation and deallocation routines
 */

/*
 * Calculate block group number for a given block number
 */
pxt4_group_t pxt4_get_group_number(struct super_block *sb,
				   pxt4_fsblk_t block)
{
	pxt4_group_t group;

	if (test_opt2(sb, STD_GROUP_SIZE))
		group = (block -
			 le32_to_cpu(PXT4_SB(sb)->s_es->s_first_data_block)) >>
			(PXT4_BLOCK_SIZE_BITS(sb) + PXT4_CLUSTER_BITS(sb) + 3);
	else
		pxt4_get_group_no_and_offset(sb, block, &group, NULL);
	return group;
}

/*
 * Calculate the block group number and offset into the block/cluster
 * allocation bitmap, given a block number
 */
void pxt4_get_group_no_and_offset(struct super_block *sb, pxt4_fsblk_t blocknr,
		pxt4_group_t *blockgrpp, pxt4_grpblk_t *offsetp)
{
	struct pxt4_super_block *es = PXT4_SB(sb)->s_es;
	pxt4_grpblk_t offset;

	blocknr = blocknr - le32_to_cpu(es->s_first_data_block);
	offset = do_div(blocknr, PXT4_BLOCKS_PER_GROUP(sb)) >>
		PXT4_SB(sb)->s_cluster_bits;
	if (offsetp)
		*offsetp = offset;
	if (blockgrpp)
		*blockgrpp = blocknr;

}

/*
 * Check whether the 'block' lives within the 'block_group'. Returns 1 if so
 * and 0 otherwise.
 */
static inline int pxt4_block_in_group(struct super_block *sb,
				      pxt4_fsblk_t block,
				      pxt4_group_t block_group)
{
	pxt4_group_t actual_group;

	actual_group = pxt4_get_group_number(sb, block);
	return (actual_group == block_group) ? 1 : 0;
}

/* Return the number of clusters used for file system metadata; this
 * represents the overhead needed by the file system.
 */
static unsigned pxt4_num_overhead_clusters(struct super_block *sb,
					   pxt4_group_t block_group,
					   struct pxt4_group_desc *gdp)
{
	unsigned num_clusters;
	int block_cluster = -1, inode_cluster = -1, itbl_cluster = -1, i, c;
	pxt4_fsblk_t start = pxt4_group_first_block_no(sb, block_group);
	pxt4_fsblk_t itbl_blk;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);

	/* This is the number of clusters used by the superblock,
	 * block group descriptors, and reserved block group
	 * descriptor blocks */
	num_clusters = pxt4_num_base_meta_clusters(sb, block_group);

	/*
	 * For the allocation bitmaps and inode table, we first need
	 * to check to see if the block is in the block group.  If it
	 * is, then check to see if the cluster is already accounted
	 * for in the clusters used for the base metadata cluster, or
	 * if we can increment the base metadata cluster to include
	 * that block.  Otherwise, we will have to track the cluster
	 * used for the allocation bitmap or inode table explicitly.
	 * Normally all of these blocks are contiguous, so the special
	 * case handling shouldn't be necessary except for *very*
	 * unusual file system layouts.
	 */
	if (pxt4_block_in_group(sb, pxt4_block_bitmap(sb, gdp), block_group)) {
		block_cluster = PXT4_B2C(sbi,
					 pxt4_block_bitmap(sb, gdp) - start);
		if (block_cluster < num_clusters)
			block_cluster = -1;
		else if (block_cluster == num_clusters) {
			num_clusters++;
			block_cluster = -1;
		}
	}

	if (pxt4_block_in_group(sb, pxt4_inode_bitmap(sb, gdp), block_group)) {
		inode_cluster = PXT4_B2C(sbi,
					 pxt4_inode_bitmap(sb, gdp) - start);
		if (inode_cluster < num_clusters)
			inode_cluster = -1;
		else if (inode_cluster == num_clusters) {
			num_clusters++;
			inode_cluster = -1;
		}
	}

	itbl_blk = pxt4_inode_table(sb, gdp);
	for (i = 0; i < sbi->s_itb_per_group; i++) {
		if (pxt4_block_in_group(sb, itbl_blk + i, block_group)) {
			c = PXT4_B2C(sbi, itbl_blk + i - start);
			if ((c < num_clusters) || (c == inode_cluster) ||
			    (c == block_cluster) || (c == itbl_cluster))
				continue;
			if (c == num_clusters) {
				num_clusters++;
				continue;
			}
			num_clusters++;
			itbl_cluster = c;
		}
	}

	if (block_cluster != -1)
		num_clusters++;
	if (inode_cluster != -1)
		num_clusters++;

	return num_clusters;
}

static unsigned int num_clusters_in_group(struct super_block *sb,
					  pxt4_group_t block_group)
{
	unsigned int blocks;

	if (block_group == pxt4_get_groups_count(sb) - 1) {
		/*
		 * Even though mke2fs always initializes the first and
		 * last group, just in case some other tool was used,
		 * we need to make sure we calculate the right free
		 * blocks.
		 */
		blocks = pxt4_blocks_count(PXT4_SB(sb)->s_es) -
			pxt4_group_first_block_no(sb, block_group);
	} else
		blocks = PXT4_BLOCKS_PER_GROUP(sb);
	return PXT4_NUM_B2C(PXT4_SB(sb), blocks);
}

/* Initializes an uninitialized block bitmap */
static int pxt4_init_block_bitmap(struct super_block *sb,
				   struct buffer_head *bh,
				   pxt4_group_t block_group,
				   struct pxt4_group_desc *gdp)
{
	unsigned int bit, bit_max;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	pxt4_fsblk_t start, tmp;

	J_ASSERT_BH(bh, buffer_locked(bh));

	/* If checksum is bad mark all blocks used to prevent allocation
	 * essentially implementing a per-group read-only flag. */
	if (!pxt4_group_desc_csum_verify(sb, block_group, gdp)) {
		pxt4_mark_group_bitmap_corrupted(sb, block_group,
					PXT4_GROUP_INFO_BBITMAP_CORRUPT |
					PXT4_GROUP_INFO_IBITMAP_CORRUPT);
		return -EFSBADCRC;
	}
	memset(bh->b_data, 0, sb->s_blocksize);

	bit_max = pxt4_num_base_meta_clusters(sb, block_group);
	if ((bit_max >> 3) >= bh->b_size)
		return -EFSCORRUPTED;

	for (bit = 0; bit < bit_max; bit++)
		pxt4_set_bit(bit, bh->b_data);

	start = pxt4_group_first_block_no(sb, block_group);

	/* Set bits for block and inode bitmaps, and inode table */
	tmp = pxt4_block_bitmap(sb, gdp);
	if (pxt4_block_in_group(sb, tmp, block_group))
		pxt4_set_bit(PXT4_B2C(sbi, tmp - start), bh->b_data);

	tmp = pxt4_inode_bitmap(sb, gdp);
	if (pxt4_block_in_group(sb, tmp, block_group))
		pxt4_set_bit(PXT4_B2C(sbi, tmp - start), bh->b_data);

	tmp = pxt4_inode_table(sb, gdp);
	for (; tmp < pxt4_inode_table(sb, gdp) +
		     sbi->s_itb_per_group; tmp++) {
		if (pxt4_block_in_group(sb, tmp, block_group))
			pxt4_set_bit(PXT4_B2C(sbi, tmp - start), bh->b_data);
	}

	/*
	 * Also if the number of blocks within the group is less than
	 * the blocksize * 8 ( which is the size of bitmap ), set rest
	 * of the block bitmap to 1
	 */
	pxt4_mark_bitmap_end(num_clusters_in_group(sb, block_group),
			     sb->s_blocksize * 8, bh->b_data);
	return 0;
}

/* Return the number of free blocks in a block group.  It is used when
 * the block bitmap is uninitialized, so we can't just count the bits
 * in the bitmap. */
unsigned pxt4_free_clusters_after_init(struct super_block *sb,
				       pxt4_group_t block_group,
				       struct pxt4_group_desc *gdp)
{
	return num_clusters_in_group(sb, block_group) - 
		pxt4_num_overhead_clusters(sb, block_group, gdp);
}

/*
 * The free blocks are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.  The descriptors are loaded in memory
 * when a file system is mounted (see pxt4_fill_super).
 */

/**
 * pxt4_get_group_desc() -- load group descriptor from disk
 * @sb:			super block
 * @block_group:	given block group
 * @bh:			pointer to the buffer head to store the block
 *			group descriptor
 */
struct pxt4_group_desc * pxt4_get_group_desc(struct super_block *sb,
					     pxt4_group_t block_group,
					     struct buffer_head **bh)
{
	unsigned int group_desc;
	unsigned int offset;
	pxt4_group_t ngroups = pxt4_get_groups_count(sb);
	struct pxt4_group_desc *desc;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct buffer_head *bh_p;

	if (block_group >= ngroups) {
		pxt4_error(sb, "block_group >= groups_count - block_group = %u,"
			   " groups_count = %u", block_group, ngroups);

		return NULL;
	}

	group_desc = block_group >> PXT4_DESC_PER_BLOCK_BITS(sb);
	offset = block_group & (PXT4_DESC_PER_BLOCK(sb) - 1);
	bh_p = sbi_array_rcu_deref(sbi, s_group_desc, group_desc);
	/*
	 * sbi_array_rcu_deref returns with rcu unlocked, this is ok since
	 * the pointer being dereferenced won't be dereferenced again. By
	 * looking at the usage in add_new_gdb() the value isn't modified,
	 * just the pointer, and so it remains valid.
	 */
	if (!bh_p) {
		pxt4_error(sb, "Group descriptor not loaded - "
			   "block_group = %u, group_desc = %u, desc = %u",
			   block_group, group_desc, offset);
		return NULL;
	}

	desc = (struct pxt4_group_desc *)(
		(__u8 *)bh_p->b_data +
		offset * PXT4_DESC_SIZE(sb));
	if (bh)
		*bh = bh_p;
	return desc;
}

/*
 * Return the block number which was discovered to be invalid, or 0 if
 * the block bitmap is valid.
 */
static pxt4_fsblk_t pxt4_valid_block_bitmap(struct super_block *sb,
					    struct pxt4_group_desc *desc,
					    pxt4_group_t block_group,
					    struct buffer_head *bh)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	pxt4_grpblk_t offset;
	pxt4_grpblk_t next_zero_bit;
	pxt4_grpblk_t max_bit = PXT4_CLUSTERS_PER_GROUP(sb);
	pxt4_fsblk_t blk;
	pxt4_fsblk_t group_first_block;

	if (pxt4_has_feature_flex_bg(sb)) {
		/* with FLEX_BG, the inode/block bitmaps and itable
		 * blocks may not be in the group at all
		 * so the bitmap validation will be skipped for those groups
		 * or it has to also read the block group where the bitmaps
		 * are located to verify they are set.
		 */
		return 0;
	}
	group_first_block = pxt4_group_first_block_no(sb, block_group);

	/* check whether block bitmap block number is set */
	blk = pxt4_block_bitmap(sb, desc);
	offset = blk - group_first_block;
	if (offset < 0 || PXT4_B2C(sbi, offset) >= max_bit ||
	    !pxt4_test_bit(PXT4_B2C(sbi, offset), bh->b_data))
		/* bad block bitmap */
		return blk;

	/* check whether the inode bitmap block number is set */
	blk = pxt4_inode_bitmap(sb, desc);
	offset = blk - group_first_block;
	if (offset < 0 || PXT4_B2C(sbi, offset) >= max_bit ||
	    !pxt4_test_bit(PXT4_B2C(sbi, offset), bh->b_data))
		/* bad block bitmap */
		return blk;

	/* check whether the inode table block number is set */
	blk = pxt4_inode_table(sb, desc);
	offset = blk - group_first_block;
	if (offset < 0 || PXT4_B2C(sbi, offset) >= max_bit ||
	    PXT4_B2C(sbi, offset + sbi->s_itb_per_group) >= max_bit)
		return blk;
	next_zero_bit = pxt4_find_next_zero_bit(bh->b_data,
			PXT4_B2C(sbi, offset + sbi->s_itb_per_group),
			PXT4_B2C(sbi, offset));
	if (next_zero_bit <
	    PXT4_B2C(sbi, offset + sbi->s_itb_per_group))
		/* bad bitmap for inode tables */
		return blk;
	return 0;
}

static int pxt4_validate_block_bitmap(struct super_block *sb,
				      struct pxt4_group_desc *desc,
				      pxt4_group_t block_group,
				      struct buffer_head *bh)
{
	pxt4_fsblk_t	blk;
	struct pxt4_group_info *grp = pxt4_get_group_info(sb, block_group);

	if (buffer_verified(bh))
		return 0;
	if (PXT4_MB_GRP_BBITMAP_CORRUPT(grp))
		return -EFSCORRUPTED;

	pxt4_lock_group(sb, block_group);
	if (buffer_verified(bh))
		goto verified;
	if (unlikely(!pxt4_block_bitmap_csum_verify(sb, block_group,
			desc, bh))) {
		pxt4_unlock_group(sb, block_group);
		pxt4_error(sb, "bg %u: bad block bitmap checksum", block_group);
		pxt4_mark_group_bitmap_corrupted(sb, block_group,
					PXT4_GROUP_INFO_BBITMAP_CORRUPT);
		return -EFSBADCRC;
	}
	blk = pxt4_valid_block_bitmap(sb, desc, block_group, bh);
	if (unlikely(blk != 0)) {
		pxt4_unlock_group(sb, block_group);
		pxt4_error(sb, "bg %u: block %llu: invalid block bitmap",
			   block_group, blk);
		pxt4_mark_group_bitmap_corrupted(sb, block_group,
					PXT4_GROUP_INFO_BBITMAP_CORRUPT);
		return -EFSCORRUPTED;
	}
	set_buffer_verified(bh);
verified:
	pxt4_unlock_group(sb, block_group);
	return 0;
}

/**
 * pxt4_read_block_bitmap_nowait()
 * @sb:			super block
 * @block_group:	given block group
 *
 * Read the bitmap for a given block_group,and validate the
 * bits for block/inode/inode tables are set in the bitmaps
 *
 * Return buffer_head on success or NULL in case of failure.
 */
struct buffer_head *
pxt4_read_block_bitmap_nowait(struct super_block *sb, pxt4_group_t block_group)
{
	struct pxt4_group_desc *desc;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct buffer_head *bh;
	pxt4_fsblk_t bitmap_blk;
	int err;

	desc = pxt4_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return ERR_PTR(-EFSCORRUPTED);
	bitmap_blk = pxt4_block_bitmap(sb, desc);
	if ((bitmap_blk <= le32_to_cpu(sbi->s_es->s_first_data_block)) ||
	    (bitmap_blk >= pxt4_blocks_count(sbi->s_es))) {
		pxt4_error(sb, "Invalid block bitmap block %llu in "
			   "block_group %u", bitmap_blk, block_group);
		pxt4_mark_group_bitmap_corrupted(sb, block_group,
					PXT4_GROUP_INFO_BBITMAP_CORRUPT);
		return ERR_PTR(-EFSCORRUPTED);
	}
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		pxt4_warning(sb, "Cannot get buffer for block bitmap - "
			     "block_group = %u, block_bitmap = %llu",
			     block_group, bitmap_blk);
		return ERR_PTR(-ENOMEM);
	}

	if (bitmap_uptodate(bh))
		goto verify;

	lock_buffer(bh);
	if (bitmap_uptodate(bh)) {
		unlock_buffer(bh);
		goto verify;
	}
	pxt4_lock_group(sb, block_group);
	if (pxt4_has_group_desc_csum(sb) &&
	    (desc->bg_flags & cpu_to_le16(PXT4_BG_BLOCK_UNINIT))) {
		if (block_group == 0) {
			pxt4_unlock_group(sb, block_group);
			unlock_buffer(bh);
			pxt4_error(sb, "Block bitmap for bg 0 marked "
				   "uninitialized");
			err = -EFSCORRUPTED;
			goto out;
		}
		err = pxt4_init_block_bitmap(sb, bh, block_group, desc);
		set_bitmap_uptodate(bh);
		set_buffer_uptodate(bh);
		set_buffer_verified(bh);
		pxt4_unlock_group(sb, block_group);
		unlock_buffer(bh);
		if (err) {
			pxt4_error(sb, "Failed to init block bitmap for group "
				   "%u: %d", block_group, err);
			goto out;
		}
		goto verify;
	}
	pxt4_unlock_group(sb, block_group);
	if (buffer_uptodate(bh)) {
		/*
		 * if not uninit if bh is uptodate,
		 * bitmap is also uptodate
		 */
		set_bitmap_uptodate(bh);
		unlock_buffer(bh);
		goto verify;
	}
	/*
	 * submit the buffer_head for reading
	 */
	set_buffer_new(bh);
	trace_pxt4_read_block_bitmap_load(sb, block_group);
	bh->b_end_io = pxt4_end_bitmap_read;
	get_bh(bh);
	submit_bh(REQ_OP_READ, REQ_META | REQ_PRIO, bh);
	return bh;
verify:
	err = pxt4_validate_block_bitmap(sb, desc, block_group, bh);
	if (err)
		goto out;
	return bh;
out:
	put_bh(bh);
	return ERR_PTR(err);
}

/* Returns 0 on success, 1 on error */
int pxt4_wait_block_bitmap(struct super_block *sb, pxt4_group_t block_group,
			   struct buffer_head *bh)
{
	struct pxt4_group_desc *desc;

	if (!buffer_new(bh))
		return 0;
	desc = pxt4_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return -EFSCORRUPTED;
	wait_on_buffer(bh);
	if (!buffer_uptodate(bh)) {
		pxt4_error(sb, "Cannot read block bitmap - "
			   "block_group = %u, block_bitmap = %llu",
			   block_group, (unsigned long long) bh->b_blocknr);
		pxt4_mark_group_bitmap_corrupted(sb, block_group,
					PXT4_GROUP_INFO_BBITMAP_CORRUPT);
		return -EIO;
	}
	clear_buffer_new(bh);
	/* Panic or remount fs read-only if block bitmap is invalid */
	return pxt4_validate_block_bitmap(sb, desc, block_group, bh);
}

struct buffer_head *
pxt4_read_block_bitmap(struct super_block *sb, pxt4_group_t block_group)
{
	struct buffer_head *bh;
	int err;

	bh = pxt4_read_block_bitmap_nowait(sb, block_group);
	if (IS_ERR(bh))
		return bh;
	err = pxt4_wait_block_bitmap(sb, block_group, bh);
	if (err) {
		put_bh(bh);
		return ERR_PTR(err);
	}
	return bh;
}

/**
 * pxt4_has_free_clusters()
 * @sbi:	in-core super block structure.
 * @nclusters:	number of needed blocks
 * @flags:	flags from pxt4_mb_new_blocks()
 *
 * Check if filesystem has nclusters free & available for allocation.
 * On success return 1, return 0 on failure.
 */
static int pxt4_has_free_clusters(struct pxt4_sb_info *sbi,
				  s64 nclusters, unsigned int flags)
{
	s64 free_clusters, dirty_clusters, rsv, resv_clusters;
	struct percpu_counter *fcc = &sbi->s_freeclusters_counter;
	struct percpu_counter *dcc = &sbi->s_dirtyclusters_counter;

	free_clusters  = percpu_counter_read_positive(fcc);
	dirty_clusters = percpu_counter_read_positive(dcc);
	resv_clusters = atomic64_read(&sbi->s_resv_clusters);

	/*
	 * r_blocks_count should always be multiple of the cluster ratio so
	 * we are safe to do a plane bit shift only.
	 */
	rsv = (pxt4_r_blocks_count(sbi->s_es) >> sbi->s_cluster_bits) +
	      resv_clusters;

	if (free_clusters - (nclusters + rsv + dirty_clusters) <
					PXT4_FREECLUSTERS_WATERMARK) {
		free_clusters  = percpu_counter_sum_positive(fcc);
		dirty_clusters = percpu_counter_sum_positive(dcc);
	}
	/* Check whether we have space after accounting for current
	 * dirty clusters & root reserved clusters.
	 */
	if (free_clusters >= (rsv + nclusters + dirty_clusters))
		return 1;

	/* Hm, nope.  Are (enough) root reserved clusters available? */
	if (uid_eq(sbi->s_resuid, current_fsuid()) ||
	    (!gid_eq(sbi->s_resgid, GLOBAL_ROOT_GID) && in_group_p(sbi->s_resgid)) ||
	    capable(CAP_SYS_RESOURCE) ||
	    (flags & PXT4_MB_USE_ROOT_BLOCKS)) {

		if (free_clusters >= (nclusters + dirty_clusters +
				      resv_clusters))
			return 1;
	}
	/* No free blocks. Let's see if we can dip into reserved pool */
	if (flags & PXT4_MB_USE_RESERVED) {
		if (free_clusters >= (nclusters + dirty_clusters))
			return 1;
	}

	return 0;
}

int pxt4_claim_free_clusters(struct pxt4_sb_info *sbi,
			     s64 nclusters, unsigned int flags)
{
	if (pxt4_has_free_clusters(sbi, nclusters, flags)) {
		percpu_counter_add(&sbi->s_dirtyclusters_counter, nclusters);
		return 0;
	} else
		return -ENOSPC;
}

/**
 * pxt4_should_retry_alloc() - check if a block allocation should be retried
 * @sb:			super block
 * @retries:		number of attemps has been made
 *
 * pxt4_should_retry_alloc() is called when ENOSPC is returned, and if
 * it is profitable to retry the operation, this function will wait
 * for the current or committing transaction to complete, and then
 * return TRUE.  We will only retry once.
 */
int pxt4_should_retry_alloc(struct super_block *sb, int *retries)
{
	if (!pxt4_has_free_clusters(PXT4_SB(sb), 1, 0) ||
	    (*retries)++ > 1 ||
	    !PXT4_SB(sb)->s_journal)
		return 0;

	smp_mb();
	if (PXT4_SB(sb)->s_mb_free_pending == 0)
		return 0;

	jbd_debug(1, "%s: retrying operation after ENOSPC\n", sb->s_id);
	jbd3_journal_force_commit_nested(PXT4_SB(sb)->s_journal);
	return 1;
}

/*
 * pxt4_new_meta_blocks() -- allocate block for meta data (indexing) blocks
 *
 * @handle:             handle to this transaction
 * @inode:              file inode
 * @goal:               given target block(filesystem wide)
 * @count:		pointer to total number of clusters needed
 * @errp:               error code
 *
 * Return 1st allocated block number on success, *count stores total account
 * error stores in errp pointer
 */
pxt4_fsblk_t pxt4_new_meta_blocks(handle_t *handle, struct inode *inode,
				  pxt4_fsblk_t goal, unsigned int flags,
				  unsigned long *count, int *errp)
{
	struct pxt4_allocation_request ar;
	pxt4_fsblk_t ret;

	memset(&ar, 0, sizeof(ar));
	/* Fill with neighbour allocated blocks */
	ar.inode = inode;
	ar.goal = goal;
	ar.len = count ? *count : 1;
	ar.flags = flags;

	ret = pxt4_mb_new_blocks(handle, &ar, errp);
	if (count)
		*count = ar.len;
	/*
	 * Account for the allocated meta blocks.  We will never
	 * fail EDQUOT for metdata, but we do account for it.
	 */
	if (!(*errp) && (flags & PXT4_MB_DELALLOC_RESERVED)) {
		dquot_alloc_block_nofail(inode,
				PXT4_C2B(PXT4_SB(inode->i_sb), ar.len));
	}
	return ret;
}

/**
 * pxt4_count_free_clusters() -- count filesystem free clusters
 * @sb:		superblock
 *
 * Adds up the number of free clusters from each block group.
 */
pxt4_fsblk_t pxt4_count_free_clusters(struct super_block *sb)
{
	pxt4_fsblk_t desc_count;
	struct pxt4_group_desc *gdp;
	pxt4_group_t i;
	pxt4_group_t ngroups = pxt4_get_groups_count(sb);
	struct pxt4_group_info *grp;
#ifdef PXT4FS_DEBUG
	struct pxt4_super_block *es;
	pxt4_fsblk_t bitmap_count;
	unsigned int x;
	struct buffer_head *bitmap_bh = NULL;

	es = PXT4_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;

	for (i = 0; i < ngroups; i++) {
		gdp = pxt4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		grp = NULL;
		if (PXT4_SB(sb)->s_group_info)
			grp = pxt4_get_group_info(sb, i);
		if (!grp || !PXT4_MB_GRP_BBITMAP_CORRUPT(grp))
			desc_count += pxt4_free_group_clusters(sb, gdp);
		brelse(bitmap_bh);
		bitmap_bh = pxt4_read_block_bitmap(sb, i);
		if (IS_ERR(bitmap_bh)) {
			bitmap_bh = NULL;
			continue;
		}

		x = pxt4_count_free(bitmap_bh->b_data,
				    PXT4_CLUSTERS_PER_GROUP(sb) / 8);
		printk(KERN_DEBUG "group %u: stored = %d, counted = %u\n",
			i, pxt4_free_group_clusters(sb, gdp), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk(KERN_DEBUG "pxt4_count_free_clusters: stored = %llu"
	       ", computed = %llu, %llu\n",
	       PXT4_NUM_B2C(PXT4_SB(sb), pxt4_free_blocks_count(es)),
	       desc_count, bitmap_count);
	return bitmap_count;
#else
	desc_count = 0;
	for (i = 0; i < ngroups; i++) {
		gdp = pxt4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		grp = NULL;
		if (PXT4_SB(sb)->s_group_info)
			grp = pxt4_get_group_info(sb, i);
		if (!grp || !PXT4_MB_GRP_BBITMAP_CORRUPT(grp))
			desc_count += pxt4_free_group_clusters(sb, gdp);
	}

	return desc_count;
#endif
}

static inline int test_root(pxt4_group_t a, int b)
{
	while (1) {
		if (a < b)
			return 0;
		if (a == b)
			return 1;
		if ((a % b) != 0)
			return 0;
		a = a / b;
	}
}

/**
 *	pxt4_bg_has_super - number of blocks used by the superblock in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the superblock (primary or backup)
 *	in this group.  Currently this will be only 0 or 1.
 */
int pxt4_bg_has_super(struct super_block *sb, pxt4_group_t group)
{
	struct pxt4_super_block *es = PXT4_SB(sb)->s_es;

	if (group == 0)
		return 1;
	if (pxt4_has_feature_sparse_super2(sb)) {
		if (group == le32_to_cpu(es->s_backup_bgs[0]) ||
		    group == le32_to_cpu(es->s_backup_bgs[1]))
			return 1;
		return 0;
	}
	if ((group <= 1) || !pxt4_has_feature_sparse_super(sb))
		return 1;
	if (!(group & 1))
		return 0;
	if (test_root(group, 3) || (test_root(group, 5)) ||
	    test_root(group, 7))
		return 1;

	return 0;
}

static unsigned long pxt4_bg_num_gdb_meta(struct super_block *sb,
					pxt4_group_t group)
{
	unsigned long metagroup = group / PXT4_DESC_PER_BLOCK(sb);
	pxt4_group_t first = metagroup * PXT4_DESC_PER_BLOCK(sb);
	pxt4_group_t last = first + PXT4_DESC_PER_BLOCK(sb) - 1;

	if (group == first || group == first + 1 || group == last)
		return 1;
	return 0;
}

static unsigned long pxt4_bg_num_gdb_nometa(struct super_block *sb,
					pxt4_group_t group)
{
	if (!pxt4_bg_has_super(sb, group))
		return 0;

	if (pxt4_has_feature_meta_bg(sb))
		return le32_to_cpu(PXT4_SB(sb)->s_es->s_first_meta_bg);
	else
		return PXT4_SB(sb)->s_gdb_count;
}

/**
 *	pxt4_bg_num_gdb - number of blocks used by the group table in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the group descriptor table
 *	(primary or backup) in this group.  In the future there may be a
 *	different number of descriptor blocks in each group.
 */
unsigned long pxt4_bg_num_gdb(struct super_block *sb, pxt4_group_t group)
{
	unsigned long first_meta_bg =
			le32_to_cpu(PXT4_SB(sb)->s_es->s_first_meta_bg);
	unsigned long metagroup = group / PXT4_DESC_PER_BLOCK(sb);

	if (!pxt4_has_feature_meta_bg(sb) || metagroup < first_meta_bg)
		return pxt4_bg_num_gdb_nometa(sb, group);

	return pxt4_bg_num_gdb_meta(sb,group);

}

/*
 * This function returns the number of file system metadata clusters at
 * the beginning of a block group, including the reserved gdt blocks.
 */
static unsigned pxt4_num_base_meta_clusters(struct super_block *sb,
				     pxt4_group_t block_group)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	unsigned num;

	/* Check for superblock and gdt backups in this group */
	num = pxt4_bg_has_super(sb, block_group);

	if (!pxt4_has_feature_meta_bg(sb) ||
	    block_group < le32_to_cpu(sbi->s_es->s_first_meta_bg) *
			  sbi->s_desc_per_block) {
		if (num) {
			num += pxt4_bg_num_gdb(sb, block_group);
			num += le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks);
		}
	} else { /* For META_BG_BLOCK_GROUPS */
		num += pxt4_bg_num_gdb(sb, block_group);
	}
	return PXT4_NUM_B2C(sbi, num);
}
/**
 *	pxt4_inode_to_goal_block - return a hint for block allocation
 *	@inode: inode for block allocation
 *
 *	Return the ideal location to start allocating blocks for a
 *	newly created inode.
 */
pxt4_fsblk_t pxt4_inode_to_goal_block(struct inode *inode)
{
	struct pxt4_inode_info *ei = PXT4_I(inode);
	pxt4_group_t block_group;
	pxt4_grpblk_t colour;
	int flex_size = pxt4_flex_bg_size(PXT4_SB(inode->i_sb));
	pxt4_fsblk_t bg_start;
	pxt4_fsblk_t last_block;

	block_group = ei->i_block_group;
	if (flex_size >= PXT4_FLEX_SIZE_DIR_ALLOC_SCHEME) {
		/*
		 * If there are at least PXT4_FLEX_SIZE_DIR_ALLOC_SCHEME
		 * block groups per flexgroup, reserve the first block
		 * group for directories and special files.  Regular
		 * files will start at the second block group.  This
		 * tends to speed up directory access and improves
		 * fsck times.
		 */
		block_group &= ~(flex_size-1);
		if (S_ISREG(inode->i_mode))
			block_group++;
	}
	bg_start = pxt4_group_first_block_no(inode->i_sb, block_group);
	last_block = pxt4_blocks_count(PXT4_SB(inode->i_sb)->s_es) - 1;

	/*
	 * If we are doing delayed allocation, we don't need take
	 * colour into account.
	 */
	if (test_opt(inode->i_sb, DELALLOC))
		return bg_start;

	if (bg_start + PXT4_BLOCKS_PER_GROUP(inode->i_sb) <= last_block)
		colour = (current->pid % 16) *
			(PXT4_BLOCKS_PER_GROUP(inode->i_sb) / 16);
	else
		colour = (current->pid % 16) * ((last_block - bg_start) / 16);
	return bg_start + colour;
}

