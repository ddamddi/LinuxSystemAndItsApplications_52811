// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/pxt4/super.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/parser.h>
#include <linux/buffer_head.h>
#include <linux/exportfs.h>
#include <linux/vfs.h>
#include <linux/random.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/quotaops.h>
#include <linux/seq_file.h>
#include <linux/ctype.h>
#include <linux/log2.h>
#include <linux/crc16.h>
#include <linux/dax.h>
#include <linux/cleancache.h>
#include <linux/uaccess.h>
#include <linux/iversion.h>
#include <linux/unicode.h>

#include <linux/kthread.h>
#include <linux/freezer.h>

#include "pxt4.h"
#include "pxt4_extents.h"	/* Needed for trace points definition */
#include "pxt4_jbd3.h"
#include "xattr.h"
#include "acl.h"
#include "mballoc.h"
#include "fsmap.h"

#define CREATE_TRACE_POINTS
#include <trace/events/pxt4.h>

static struct pxt4_lazy_init *pxt4_li_info;
static struct mutex pxt4_li_mtx;
static struct ratelimit_state pxt4_mount_msg_ratelimit;

static int pxt4_load_journal(struct super_block *, struct pxt4_super_block *,
			     unsigned long journal_devnum);
static int pxt4_show_options(struct seq_file *seq, struct dentry *root);
static int pxt4_commit_super(struct super_block *sb, int sync);
static int pxt4_mark_recovery_complete(struct super_block *sb,
					struct pxt4_super_block *es);
static int pxt4_clear_journal_err(struct super_block *sb,
				  struct pxt4_super_block *es);
static int pxt4_sync_fs(struct super_block *sb, int wait);
static int pxt4_remount(struct super_block *sb, int *flags, char *data);
static int pxt4_statfs(struct dentry *dentry, struct kstatfs *buf);
static int pxt4_unfreeze(struct super_block *sb);
static int pxt4_freeze(struct super_block *sb);
static struct dentry *pxt4_mount(struct file_system_type *fs_type, int flags,
		       const char *dev_name, void *data);
static inline int pxt2_feature_set_ok(struct super_block *sb);
static inline int ext3_feature_set_ok(struct super_block *sb);
static int pxt4_feature_set_ok(struct super_block *sb, int readonly);
static void pxt4_destroy_lazyinit_thread(void);
static void pxt4_unregister_li_request(struct super_block *sb);
static void pxt4_clear_request_list(void);
static struct inode *pxt4_get_journal_inode(struct super_block *sb,
					    unsigned int journal_inum);

/*
 * Lock ordering
 *
 * Note the difference between i_mmap_sem (PXT4_I(inode)->i_mmap_sem) and
 * i_mmap_rwsem (inode->i_mmap_rwsem)!
 *
 * page fault path:
 * mmap_sem -> sb_start_pagefault -> i_mmap_sem (r) -> transaction start ->
 *   page lock -> i_data_sem (rw)
 *
 * buffered write path:
 * sb_start_write -> i_mutex -> mmap_sem
 * sb_start_write -> i_mutex -> transaction start -> page lock ->
 *   i_data_sem (rw)
 *
 * truncate:
 * sb_start_write -> i_mutex -> i_mmap_sem (w) -> i_mmap_rwsem (w) -> page lock
 * sb_start_write -> i_mutex -> i_mmap_sem (w) -> transaction start ->
 *   i_data_sem (rw)
 *
 * direct IO:
 * sb_start_write -> i_mutex -> mmap_sem
 * sb_start_write -> i_mutex -> transaction start -> i_data_sem (rw)
 *
 * writepages:
 * transaction start -> page lock(s) -> i_data_sem (rw)
 */

#if !defined(CONFIG_PXT2_FS) && !defined(CONFIG_PXT2_FS_MODULE) && defined(CONFIG_PXT4_USE_FOR_PXT2)
static struct file_system_type pxt2_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "pxt2",
	.mount		= pxt4_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("pxt2");
MODULE_ALIAS("pxt2");
#define IS_PXT2_SB(sb) ((sb)->s_bdev->bd_holder == &pxt2_fs_type)
#else
#define IS_PXT2_SB(sb) (0)
#endif


static struct file_system_type ext3_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ext3",
	.mount		= pxt4_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("ext3");
MODULE_ALIAS("ext3");
#define IS_EXT3_SB(sb) ((sb)->s_bdev->bd_holder == &ext3_fs_type)

/*
 * This works like sb_bread() except it uses ERR_PTR for error
 * returns.  Currently with sb_bread it's impossible to distinguish
 * between ENOMEM and EIO situations (since both result in a NULL
 * return.
 */
struct buffer_head *
pxt4_sb_bread(struct super_block *sb, sector_t block, int op_flags)
{
	struct buffer_head *bh = sb_getblk(sb, block);

	if (bh == NULL)
		return ERR_PTR(-ENOMEM);
	if (buffer_uptodate(bh))
		return bh;
	ll_rw_block(REQ_OP_READ, REQ_META | op_flags, 1, &bh);
	wait_on_buffer(bh);
	if (buffer_uptodate(bh))
		return bh;
	put_bh(bh);
	return ERR_PTR(-EIO);
}

static int pxt4_verify_csum_type(struct super_block *sb,
				 struct pxt4_super_block *es)
{
	if (!pxt4_has_feature_metadata_csum(sb))
		return 1;

	return es->s_checksum_type == PXT4_CRC32C_CHKSUM;
}

static __le32 pxt4_superblock_csum(struct super_block *sb,
				   struct pxt4_super_block *es)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	int offset = offsetof(struct pxt4_super_block, s_checksum);
	__u32 csum;

	csum = pxt4_chksum(sbi, ~0, (char *)es, offset);

	return cpu_to_le32(csum);
}

static int pxt4_superblock_csum_verify(struct super_block *sb,
				       struct pxt4_super_block *es)
{
	if (!pxt4_has_metadata_csum(sb))
		return 1;

	return es->s_checksum == pxt4_superblock_csum(sb, es);
}

void pxt4_superblock_csum_set(struct super_block *sb)
{
	struct pxt4_super_block *es = PXT4_SB(sb)->s_es;

	if (!pxt4_has_metadata_csum(sb))
		return;

	es->s_checksum = pxt4_superblock_csum(sb, es);
}

void *pxt4_kvmalloc(size_t size, gfp_t flags)
{
	void *ret;

	ret = kmalloc(size, flags | __GFP_NOWARN);
	if (!ret)
		ret = __vmalloc(size, flags, PAGE_KERNEL);
	return ret;
}

void *pxt4_kvzalloc(size_t size, gfp_t flags)
{
	void *ret;

	ret = kzalloc(size, flags | __GFP_NOWARN);
	if (!ret)
		ret = __vmalloc(size, flags | __GFP_ZERO, PAGE_KERNEL);
	return ret;
}

pxt4_fsblk_t pxt4_block_bitmap(struct super_block *sb,
			       struct pxt4_group_desc *bg)
{
	return le32_to_cpu(bg->bg_block_bitmap_lo) |
		(PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT ?
		 (pxt4_fsblk_t)le32_to_cpu(bg->bg_block_bitmap_hi) << 32 : 0);
}

pxt4_fsblk_t pxt4_inode_bitmap(struct super_block *sb,
			       struct pxt4_group_desc *bg)
{
	return le32_to_cpu(bg->bg_inode_bitmap_lo) |
		(PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT ?
		 (pxt4_fsblk_t)le32_to_cpu(bg->bg_inode_bitmap_hi) << 32 : 0);
}

pxt4_fsblk_t pxt4_inode_table(struct super_block *sb,
			      struct pxt4_group_desc *bg)
{
	return le32_to_cpu(bg->bg_inode_table_lo) |
		(PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT ?
		 (pxt4_fsblk_t)le32_to_cpu(bg->bg_inode_table_hi) << 32 : 0);
}

__u32 pxt4_free_group_clusters(struct super_block *sb,
			       struct pxt4_group_desc *bg)
{
	return le16_to_cpu(bg->bg_free_blocks_count_lo) |
		(PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT ?
		 (__u32)le16_to_cpu(bg->bg_free_blocks_count_hi) << 16 : 0);
}

__u32 pxt4_free_inodes_count(struct super_block *sb,
			      struct pxt4_group_desc *bg)
{
	return le16_to_cpu(bg->bg_free_inodes_count_lo) |
		(PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT ?
		 (__u32)le16_to_cpu(bg->bg_free_inodes_count_hi) << 16 : 0);
}

__u32 pxt4_used_dirs_count(struct super_block *sb,
			      struct pxt4_group_desc *bg)
{
	return le16_to_cpu(bg->bg_used_dirs_count_lo) |
		(PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT ?
		 (__u32)le16_to_cpu(bg->bg_used_dirs_count_hi) << 16 : 0);
}

__u32 pxt4_itable_unused_count(struct super_block *sb,
			      struct pxt4_group_desc *bg)
{
	return le16_to_cpu(bg->bg_itable_unused_lo) |
		(PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT ?
		 (__u32)le16_to_cpu(bg->bg_itable_unused_hi) << 16 : 0);
}

void pxt4_block_bitmap_set(struct super_block *sb,
			   struct pxt4_group_desc *bg, pxt4_fsblk_t blk)
{
	bg->bg_block_bitmap_lo = cpu_to_le32((u32)blk);
	if (PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_block_bitmap_hi = cpu_to_le32(blk >> 32);
}

void pxt4_inode_bitmap_set(struct super_block *sb,
			   struct pxt4_group_desc *bg, pxt4_fsblk_t blk)
{
	bg->bg_inode_bitmap_lo  = cpu_to_le32((u32)blk);
	if (PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_inode_bitmap_hi = cpu_to_le32(blk >> 32);
}

void pxt4_inode_table_set(struct super_block *sb,
			  struct pxt4_group_desc *bg, pxt4_fsblk_t blk)
{
	bg->bg_inode_table_lo = cpu_to_le32((u32)blk);
	if (PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_inode_table_hi = cpu_to_le32(blk >> 32);
}

void pxt4_free_group_clusters_set(struct super_block *sb,
				  struct pxt4_group_desc *bg, __u32 count)
{
	bg->bg_free_blocks_count_lo = cpu_to_le16((__u16)count);
	if (PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_free_blocks_count_hi = cpu_to_le16(count >> 16);
}

void pxt4_free_inodes_set(struct super_block *sb,
			  struct pxt4_group_desc *bg, __u32 count)
{
	bg->bg_free_inodes_count_lo = cpu_to_le16((__u16)count);
	if (PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_free_inodes_count_hi = cpu_to_le16(count >> 16);
}

void pxt4_used_dirs_set(struct super_block *sb,
			  struct pxt4_group_desc *bg, __u32 count)
{
	bg->bg_used_dirs_count_lo = cpu_to_le16((__u16)count);
	if (PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_used_dirs_count_hi = cpu_to_le16(count >> 16);
}

void pxt4_itable_unused_set(struct super_block *sb,
			  struct pxt4_group_desc *bg, __u32 count)
{
	bg->bg_itable_unused_lo = cpu_to_le16((__u16)count);
	if (PXT4_DESC_SIZE(sb) >= PXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_itable_unused_hi = cpu_to_le16(count >> 16);
}

static void __pxt4_update_tstamp(__le32 *lo, __u8 *hi)
{
	time64_t now = ktime_get_real_seconds();

	now = clamp_val(now, 0, (1ull << 40) - 1);

	*lo = cpu_to_le32(lower_32_bits(now));
	*hi = upper_32_bits(now);
}

static time64_t __pxt4_get_tstamp(__le32 *lo, __u8 *hi)
{
	return ((time64_t)(*hi) << 32) + le32_to_cpu(*lo);
}
#define pxt4_update_tstamp(es, tstamp) \
	__pxt4_update_tstamp(&(es)->tstamp, &(es)->tstamp ## _hi)
#define pxt4_get_tstamp(es, tstamp) \
	__pxt4_get_tstamp(&(es)->tstamp, &(es)->tstamp ## _hi)

static void __save_error_info(struct super_block *sb, const char *func,
			    unsigned int line)
{
	struct pxt4_super_block *es = PXT4_SB(sb)->s_es;

	PXT4_SB(sb)->s_mount_state |= PXT4_ERROR_FS;
	if (bdev_read_only(sb->s_bdev))
		return;
	es->s_state |= cpu_to_le16(PXT4_ERROR_FS);
	pxt4_update_tstamp(es, s_last_error_time);
	strncpy(es->s_last_error_func, func, sizeof(es->s_last_error_func));
	es->s_last_error_line = cpu_to_le32(line);
	if (!es->s_first_error_time) {
		es->s_first_error_time = es->s_last_error_time;
		es->s_first_error_time_hi = es->s_last_error_time_hi;
		strncpy(es->s_first_error_func, func,
			sizeof(es->s_first_error_func));
		es->s_first_error_line = cpu_to_le32(line);
		es->s_first_error_ino = es->s_last_error_ino;
		es->s_first_error_block = es->s_last_error_block;
	}
	/*
	 * Start the daily error reporting function if it hasn't been
	 * started already
	 */
	if (!es->s_error_count)
		mod_timer(&PXT4_SB(sb)->s_err_report, jiffies + 24*60*60*HZ);
	le32_add_cpu(&es->s_error_count, 1);
}

static void save_error_info(struct super_block *sb, const char *func,
			    unsigned int line)
{
	__save_error_info(sb, func, line);
	if (!bdev_read_only(sb->s_bdev))
		pxt4_commit_super(sb, 1);
}

/*
 * The del_gendisk() function uninitializes the disk-specific data
 * structures, including the bdi structure, without telling anyone
 * else.  Once this happens, any attempt to call mark_buffer_dirty()
 * (for example, by pxt4_commit_super), will cause a kernel OOPS.
 * This is a kludge to prevent these oops until we can put in a proper
 * hook in del_gendisk() to inform the VFS and file system layers.
 */
static int block_device_ejected(struct super_block *sb)
{
	struct inode *bd_inode = sb->s_bdev->bd_inode;
	struct backing_dev_info *bdi = inode_to_bdi(bd_inode);

	return bdi->dev == NULL;
}

static void pxt4_journal_commit_callback(journal_t *journal, transaction_t *txn)
{
	struct super_block		*sb = journal->j_private;
	struct pxt4_sb_info		*sbi = PXT4_SB(sb);
	int				error = is_journal_aborted(journal);
	struct pxt4_journal_cb_entry	*jce;

	BUG_ON(txn->t_state == T_FINISHED);

	pxt4_process_freed_data(sb, txn->t_tid);

	spin_lock(&sbi->s_md_lock);
	while (!list_empty(&txn->t_private_list)) {
		jce = list_entry(txn->t_private_list.next,
				 struct pxt4_journal_cb_entry, jce_list);
		list_del_init(&jce->jce_list);
		spin_unlock(&sbi->s_md_lock);
		jce->jce_func(sb, jce, error);
		spin_lock(&sbi->s_md_lock);
	}
	spin_unlock(&sbi->s_md_lock);
}

static bool system_going_down(void)
{
	return system_state == SYSTEM_HALT || system_state == SYSTEM_POWER_OFF
		|| system_state == SYSTEM_RESTART;
}

/* Deal with the reporting of failure conditions on a filesystem such as
 * inconsistencies detected or read IO failures.
 *
 * On pxt2, we can store the error state of the filesystem in the
 * superblock.  That is not possible on pxt4, because we may have other
 * write ordering constraints on the superblock which prevent us from
 * writing it out straight away; and given that the journal is about to
 * be aborted, we can't rely on the current, or future, transactions to
 * write out the superblock safely.
 *
 * We'll just use the jbd3_journal_abort() error code to record an error in
 * the journal instead.  On recovery, the journal will complain about
 * that error until we've noted it down and cleared it.
 */

static void pxt4_handle_error(struct super_block *sb)
{
	if (test_opt(sb, WARN_ON_ERROR))
		WARN_ON_ONCE(1);

	if (sb_rdonly(sb))
		return;

	if (!test_opt(sb, ERRORS_CONT)) {
		journal_t *journal = PXT4_SB(sb)->s_journal;

		PXT4_SB(sb)->s_mount_flags |= PXT4_MF_FS_ABORTED;
		if (journal)
			jbd3_journal_abort(journal, -EIO);
	}
	/*
	 * We force ERRORS_RO behavior when system is rebooting. Otherwise we
	 * could panic during 'reboot -f' as the underlying device got already
	 * disabled.
	 */
	if (test_opt(sb, ERRORS_RO) || system_going_down()) {
		pxt4_msg(sb, KERN_CRIT, "Remounting filesystem read-only");
		/*
		 * Make sure updated value of ->s_mount_flags will be visible
		 * before ->s_flags update
		 */
		smp_wmb();
		sb->s_flags |= SB_RDONLY;
	} else if (test_opt(sb, ERRORS_PANIC)) {
		if (PXT4_SB(sb)->s_journal &&
		  !(PXT4_SB(sb)->s_journal->j_flags & JBD3_REC_ERR))
			return;
		panic("PXT4-fs (device %s): panic forced after error\n",
			sb->s_id);
	}
}

#define pxt4_error_ratelimit(sb)					\
		___ratelimit(&(PXT4_SB(sb)->s_err_ratelimit_state),	\
			     "PXT4-fs error")

void __pxt4_error(struct super_block *sb, const char *function,
		  unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (unlikely(pxt4_forced_shutdown(PXT4_SB(sb))))
		return;

	trace_pxt4_error(sb, function, line);
	if (pxt4_error_ratelimit(sb)) {
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		printk(KERN_CRIT
		       "PXT4-fs error (device %s): %s:%d: comm %s: %pV\n",
		       sb->s_id, function, line, current->comm, &vaf);
		va_end(args);
	}
	save_error_info(sb, function, line);
	pxt4_handle_error(sb);
}

void __pxt4_error_inode(struct inode *inode, const char *function,
			unsigned int line, pxt4_fsblk_t block,
			const char *fmt, ...)
{
	va_list args;
	struct va_format vaf;
	struct pxt4_super_block *es = PXT4_SB(inode->i_sb)->s_es;

	if (unlikely(pxt4_forced_shutdown(PXT4_SB(inode->i_sb))))
		return;

	trace_pxt4_error(inode->i_sb, function, line);
	es->s_last_error_ino = cpu_to_le32(inode->i_ino);
	es->s_last_error_block = cpu_to_le64(block);
	if (pxt4_error_ratelimit(inode->i_sb)) {
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		if (block)
			printk(KERN_CRIT "PXT4-fs error (device %s): %s:%d: "
			       "inode #%lu: block %llu: comm %s: %pV\n",
			       inode->i_sb->s_id, function, line, inode->i_ino,
			       block, current->comm, &vaf);
		else
			printk(KERN_CRIT "PXT4-fs error (device %s): %s:%d: "
			       "inode #%lu: comm %s: %pV\n",
			       inode->i_sb->s_id, function, line, inode->i_ino,
			       current->comm, &vaf);
		va_end(args);
	}
	save_error_info(inode->i_sb, function, line);
	pxt4_handle_error(inode->i_sb);
}

void __pxt4_error_file(struct file *file, const char *function,
		       unsigned int line, pxt4_fsblk_t block,
		       const char *fmt, ...)
{
	va_list args;
	struct va_format vaf;
	struct pxt4_super_block *es;
	struct inode *inode = file_inode(file);
	char pathname[80], *path;

	if (unlikely(pxt4_forced_shutdown(PXT4_SB(inode->i_sb))))
		return;

	trace_pxt4_error(inode->i_sb, function, line);
	es = PXT4_SB(inode->i_sb)->s_es;
	es->s_last_error_ino = cpu_to_le32(inode->i_ino);
	if (pxt4_error_ratelimit(inode->i_sb)) {
		path = file_path(file, pathname, sizeof(pathname));
		if (IS_ERR(path))
			path = "(unknown)";
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		if (block)
			printk(KERN_CRIT
			       "PXT4-fs error (device %s): %s:%d: inode #%lu: "
			       "block %llu: comm %s: path %s: %pV\n",
			       inode->i_sb->s_id, function, line, inode->i_ino,
			       block, current->comm, path, &vaf);
		else
			printk(KERN_CRIT
			       "PXT4-fs error (device %s): %s:%d: inode #%lu: "
			       "comm %s: path %s: %pV\n",
			       inode->i_sb->s_id, function, line, inode->i_ino,
			       current->comm, path, &vaf);
		va_end(args);
	}
	save_error_info(inode->i_sb, function, line);
	pxt4_handle_error(inode->i_sb);
}

const char *pxt4_decode_error(struct super_block *sb, int errno,
			      char nbuf[16])
{
	char *errstr = NULL;

	switch (errno) {
	case -EFSCORRUPTED:
		errstr = "Corrupt filesystem";
		break;
	case -EFSBADCRC:
		errstr = "Filesystem failed CRC";
		break;
	case -EIO:
		errstr = "IO failure";
		break;
	case -ENOMEM:
		errstr = "Out of memory";
		break;
	case -EROFS:
		if (!sb || (PXT4_SB(sb)->s_journal &&
			    PXT4_SB(sb)->s_journal->j_flags & JBD3_ABORT))
			errstr = "Journal has aborted";
		else
			errstr = "Readonly filesystem";
		break;
	default:
		/* If the caller passed in an extra buffer for unknown
		 * errors, textualise them now.  Else we just return
		 * NULL. */
		if (nbuf) {
			/* Check for truncated error codes... */
			if (snprintf(nbuf, 16, "error %d", -errno) >= 0)
				errstr = nbuf;
		}
		break;
	}

	return errstr;
}

/* __pxt4_std_error decodes expected errors from journaling functions
 * automatically and invokes the appropriate error response.  */

void __pxt4_std_error(struct super_block *sb, const char *function,
		      unsigned int line, int errno)
{
	char nbuf[16];
	const char *errstr;

	if (unlikely(pxt4_forced_shutdown(PXT4_SB(sb))))
		return;

	/* Special case: if the error is EROFS, and we're not already
	 * inside a transaction, then there's really no point in logging
	 * an error. */
	if (errno == -EROFS && journal_current_handle() == NULL && sb_rdonly(sb))
		return;

	if (pxt4_error_ratelimit(sb)) {
		errstr = pxt4_decode_error(sb, errno, nbuf);
		printk(KERN_CRIT "PXT4-fs error (device %s) in %s:%d: %s\n",
		       sb->s_id, function, line, errstr);
	}

	save_error_info(sb, function, line);
	pxt4_handle_error(sb);
}

/*
 * pxt4_abort is a much stronger failure handler than pxt4_error.  The
 * abort function may be used to deal with unrecoverable failures such
 * as journal IO errors or ENOMEM at a critical moment in log management.
 *
 * We unconditionally force the filesystem into an ABORT|READONLY state,
 * unless the error response on the fs has been set to panic in which
 * case we take the easy way out and panic immediately.
 */

void __pxt4_abort(struct super_block *sb, const char *function,
		unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (unlikely(pxt4_forced_shutdown(PXT4_SB(sb))))
		return;

	save_error_info(sb, function, line);
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk(KERN_CRIT "PXT4-fs error (device %s): %s:%d: %pV\n",
	       sb->s_id, function, line, &vaf);
	va_end(args);

	if (sb_rdonly(sb) == 0) {
		pxt4_msg(sb, KERN_CRIT, "Remounting filesystem read-only");
		PXT4_SB(sb)->s_mount_flags |= PXT4_MF_FS_ABORTED;
		/*
		 * Make sure updated value of ->s_mount_flags will be visible
		 * before ->s_flags update
		 */
		smp_wmb();
		sb->s_flags |= SB_RDONLY;
		if (PXT4_SB(sb)->s_journal)
			jbd3_journal_abort(PXT4_SB(sb)->s_journal, -EIO);
		save_error_info(sb, function, line);
	}
	if (test_opt(sb, ERRORS_PANIC) && !system_going_down()) {
		if (PXT4_SB(sb)->s_journal &&
		  !(PXT4_SB(sb)->s_journal->j_flags & JBD3_REC_ERR))
			return;
		panic("PXT4-fs panic from previous error\n");
	}
}

void __pxt4_msg(struct super_block *sb,
		const char *prefix, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (!___ratelimit(&(PXT4_SB(sb)->s_msg_ratelimit_state), "PXT4-fs"))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk("%sPXT4-fs (%s): %pV\n", prefix, sb->s_id, &vaf);
	va_end(args);
}

#define pxt4_warning_ratelimit(sb)					\
		___ratelimit(&(PXT4_SB(sb)->s_warning_ratelimit_state),	\
			     "PXT4-fs warning")

void __pxt4_warning(struct super_block *sb, const char *function,
		    unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (!pxt4_warning_ratelimit(sb))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk(KERN_WARNING "PXT4-fs warning (device %s): %s:%d: %pV\n",
	       sb->s_id, function, line, &vaf);
	va_end(args);
}

void __pxt4_warning_inode(const struct inode *inode, const char *function,
			  unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (!pxt4_warning_ratelimit(inode->i_sb))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk(KERN_WARNING "PXT4-fs warning (device %s): %s:%d: "
	       "inode #%lu: comm %s: %pV\n", inode->i_sb->s_id,
	       function, line, inode->i_ino, current->comm, &vaf);
	va_end(args);
}

void __pxt4_grp_locked_error(const char *function, unsigned int line,
			     struct super_block *sb, pxt4_group_t grp,
			     unsigned long ino, pxt4_fsblk_t block,
			     const char *fmt, ...)
__releases(bitlock)
__acquires(bitlock)
{
	struct va_format vaf;
	va_list args;
	struct pxt4_super_block *es = PXT4_SB(sb)->s_es;

	if (unlikely(pxt4_forced_shutdown(PXT4_SB(sb))))
		return;

	trace_pxt4_error(sb, function, line);
	es->s_last_error_ino = cpu_to_le32(ino);
	es->s_last_error_block = cpu_to_le64(block);
	__save_error_info(sb, function, line);

	if (pxt4_error_ratelimit(sb)) {
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		printk(KERN_CRIT "PXT4-fs error (device %s): %s:%d: group %u, ",
		       sb->s_id, function, line, grp);
		if (ino)
			printk(KERN_CONT "inode %lu: ", ino);
		if (block)
			printk(KERN_CONT "block %llu:",
			       (unsigned long long) block);
		printk(KERN_CONT "%pV\n", &vaf);
		va_end(args);
	}

	if (test_opt(sb, WARN_ON_ERROR))
		WARN_ON_ONCE(1);

	if (test_opt(sb, ERRORS_CONT)) {
		pxt4_commit_super(sb, 0);
		return;
	}

	pxt4_unlock_group(sb, grp);
	pxt4_commit_super(sb, 1);
	pxt4_handle_error(sb);
	/*
	 * We only get here in the ERRORS_RO case; relocking the group
	 * may be dangerous, but nothing bad will happen since the
	 * filesystem will have already been marked read/only and the
	 * journal has been aborted.  We return 1 as a hint to callers
	 * who might what to use the return value from
	 * pxt4_grp_locked_error() to distinguish between the
	 * ERRORS_CONT and ERRORS_RO case, and perhaps return more
	 * aggressively from the pxt4 function in question, with a
	 * more appropriate error code.
	 */
	pxt4_lock_group(sb, grp);
	return;
}

void pxt4_mark_group_bitmap_corrupted(struct super_block *sb,
				     pxt4_group_t group,
				     unsigned int flags)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_group_info *grp = pxt4_get_group_info(sb, group);
	struct pxt4_group_desc *gdp = pxt4_get_group_desc(sb, group, NULL);
	int ret;

	if (flags & PXT4_GROUP_INFO_BBITMAP_CORRUPT) {
		ret = pxt4_test_and_set_bit(PXT4_GROUP_INFO_BBITMAP_CORRUPT_BIT,
					    &grp->bb_state);
		if (!ret)
			percpu_counter_sub(&sbi->s_freeclusters_counter,
					   grp->bb_free);
	}

	if (flags & PXT4_GROUP_INFO_IBITMAP_CORRUPT) {
		ret = pxt4_test_and_set_bit(PXT4_GROUP_INFO_IBITMAP_CORRUPT_BIT,
					    &grp->bb_state);
		if (!ret && gdp) {
			int count;

			count = pxt4_free_inodes_count(sb, gdp);
			percpu_counter_sub(&sbi->s_freeinodes_counter,
					   count);
		}
	}
}

void pxt4_update_dynamic_rev(struct super_block *sb)
{
	struct pxt4_super_block *es = PXT4_SB(sb)->s_es;

	if (le32_to_cpu(es->s_rev_level) > PXT4_GOOD_OLD_REV)
		return;

	pxt4_warning(sb,
		     "updating to rev %d because of new feature flag, "
		     "running e2fsck is recommended",
		     PXT4_DYNAMIC_REV);

	es->s_first_ino = cpu_to_le32(PXT4_GOOD_OLD_FIRST_INO);
	es->s_inode_size = cpu_to_le16(PXT4_GOOD_OLD_INODE_SIZE);
	es->s_rev_level = cpu_to_le32(PXT4_DYNAMIC_REV);
	/* leave es->s_feature_*compat flags alone */
	/* es->s_uuid will be set by e2fsck if empty */

	/*
	 * The rest of the superblock fields should be zero, and if not it
	 * means they are likely already in use, so leave them alone.  We
	 * can leave it up to e2fsck to clean up any inconsistencies there.
	 */
}

/*
 * Open the external journal device
 */
static struct block_device *pxt4_blkdev_get(dev_t dev, struct super_block *sb)
{
	struct block_device *bdev;
	char b[BDEVNAME_SIZE];

	bdev = blkdev_get_by_dev(dev, FMODE_READ|FMODE_WRITE|FMODE_EXCL, sb);
	if (IS_ERR(bdev))
		goto fail;
	return bdev;

fail:
	pxt4_msg(sb, KERN_ERR, "failed to open journal device %s: %ld",
			__bdevname(dev, b), PTR_ERR(bdev));
	return NULL;
}

/*
 * Release the journal device
 */
static void pxt4_blkdev_put(struct block_device *bdev)
{
	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
}

static void pxt4_blkdev_remove(struct pxt4_sb_info *sbi)
{
	struct block_device *bdev;
	bdev = sbi->journal_bdev;
	if (bdev) {
		pxt4_blkdev_put(bdev);
		sbi->journal_bdev = NULL;
	}
}

static inline struct inode *orphan_list_entry(struct list_head *l)
{
	return &list_entry(l, struct pxt4_inode_info, i_orphan)->vfs_inode;
}

static void dump_orphan_list(struct super_block *sb, struct pxt4_sb_info *sbi)
{
	struct list_head *l;

	pxt4_msg(sb, KERN_ERR, "sb orphan head is %d",
		 le32_to_cpu(sbi->s_es->s_last_orphan));

	printk(KERN_ERR "sb_info orphan list:\n");
	list_for_each(l, &sbi->s_orphan) {
		struct inode *inode = orphan_list_entry(l);
		printk(KERN_ERR "  "
		       "inode %s:%lu at %p: mode %o, nlink %d, next %d\n",
		       inode->i_sb->s_id, inode->i_ino, inode,
		       inode->i_mode, inode->i_nlink,
		       NEXT_ORPHAN(inode));
	}
}

#ifdef CONFIG_QUOTA
static int pxt4_quota_off(struct super_block *sb, int type);

static inline void pxt4_quota_off_umount(struct super_block *sb)
{
	int type;

	/* Use our quota_off function to clear inode flags etc. */
	for (type = 0; type < PXT4_MAXQUOTAS; type++)
		pxt4_quota_off(sb, type);
}

/*
 * This is a helper function which is used in the mount/remount
 * codepaths (which holds s_umount) to fetch the quota file name.
 */
static inline char *get_qf_name(struct super_block *sb,
				struct pxt4_sb_info *sbi,
				int type)
{
	return rcu_dereference_protected(sbi->s_qf_names[type],
					 lockdep_is_held(&sb->s_umount));
}
#else
static inline void pxt4_quota_off_umount(struct super_block *sb)
{
}
#endif

static void pxt4_put_super(struct super_block *sb)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_super_block *es = sbi->s_es;
	struct buffer_head **group_desc;
	struct flex_groups **flex_groups;
	int aborted = 0;
	int i, err;

	pxt4_unregister_li_request(sb);
	pxt4_quota_off_umount(sb);

	destroy_workqueue(sbi->rsv_conversion_wq);

	if (sbi->s_journal) {
		aborted = is_journal_aborted(sbi->s_journal);
		err = jbd3_journal_destroy(sbi->s_journal);
		sbi->s_journal = NULL;
		if ((err < 0) && !aborted)
			pxt4_abort(sb, "Couldn't clean up the journal");
	}

	pxt4_unregister_sysfs(sb);
	pxt4_es_unregister_shrinker(sbi);
	del_timer_sync(&sbi->s_err_report);
	pxt4_release_system_zone(sb);
	pxt4_mb_release(sb);
	pxt4_ext_release(sb);

	if (!sb_rdonly(sb) && !aborted) {
		pxt4_clear_feature_journal_needs_recovery(sb);
		es->s_state = cpu_to_le16(sbi->s_mount_state);
	}
	if (!sb_rdonly(sb))
		pxt4_commit_super(sb, 1);

	rcu_read_lock();
	group_desc = rcu_dereference(sbi->s_group_desc);
	for (i = 0; i < sbi->s_gdb_count; i++)
		brelse(group_desc[i]);
	kvfree(group_desc);
	flex_groups = rcu_dereference(sbi->s_flex_groups);
	if (flex_groups) {
		for (i = 0; i < sbi->s_flex_groups_allocated; i++)
			kvfree(flex_groups[i]);
		kvfree(flex_groups);
	}
	rcu_read_unlock();
	percpu_counter_destroy(&sbi->s_freeclusters_counter);
	percpu_counter_destroy(&sbi->s_freeinodes_counter);
	percpu_counter_destroy(&sbi->s_dirs_counter);
	percpu_counter_destroy(&sbi->s_dirtyclusters_counter);
	percpu_free_rwsem(&sbi->s_writepages_rwsem);
#ifdef CONFIG_QUOTA
	for (i = 0; i < PXT4_MAXQUOTAS; i++)
		kfree(get_qf_name(sb, sbi, i));
#endif

	/* Debugging code just in case the in-memory inode orphan list
	 * isn't empty.  The on-disk one can be non-empty if we've
	 * detected an error and taken the fs readonly, but the
	 * in-memory list had better be clean by this point. */
	if (!list_empty(&sbi->s_orphan))
		dump_orphan_list(sb, sbi);
	J_ASSERT(list_empty(&sbi->s_orphan));

	sync_blockdev(sb->s_bdev);
	invalidate_bdev(sb->s_bdev);
	if (sbi->journal_bdev && sbi->journal_bdev != sb->s_bdev) {
		/*
		 * Invalidate the journal device's buffers.  We don't want them
		 * floating about in memory - the physical journal device may
		 * hotswapped, and it breaks the `ro-after' testing code.
		 */
		sync_blockdev(sbi->journal_bdev);
		invalidate_bdev(sbi->journal_bdev);
		pxt4_blkdev_remove(sbi);
	}

	pxt4_xattr_destroy_cache(sbi->s_ea_inode_cache);
	sbi->s_ea_inode_cache = NULL;

	pxt4_xattr_destroy_cache(sbi->s_ea_block_cache);
	sbi->s_ea_block_cache = NULL;

	if (sbi->s_mmp_tsk)
		kthread_stop(sbi->s_mmp_tsk);
	brelse(sbi->s_sbh);
	sb->s_fs_info = NULL;
	/*
	 * Now that we are completely done shutting down the
	 * superblock, we need to actually destroy the kobject.
	 */
	kobject_put(&sbi->s_kobj);
	wait_for_completion(&sbi->s_kobj_unregister);
	if (sbi->s_chksum_driver)
		crypto_free_shash(sbi->s_chksum_driver);
	kfree(sbi->s_blockgroup_lock);
	fs_put_dax(sbi->s_daxdev);
#ifdef CONFIG_UNICODE
	utf8_unload(sbi->s_encoding);
#endif
	kfree(sbi);
}

static struct kmem_cache *pxt4_inode_cachep;

/*
 * Called inside transaction, so use GFP_NOFS
 */
static struct inode *pxt4_alloc_inode(struct super_block *sb)
{
	struct pxt4_inode_info *ei;

	ei = kmem_cache_alloc(pxt4_inode_cachep, GFP_NOFS);
	if (!ei)
		return NULL;

	inode_set_iversion(&ei->vfs_inode, 1);
	spin_lock_init(&ei->i_raw_lock);
	INIT_LIST_HEAD(&ei->i_prealloc_list);
	spin_lock_init(&ei->i_prealloc_lock);
	pxt4_es_init_tree(&ei->i_es_tree);
	rwlock_init(&ei->i_es_lock);
	INIT_LIST_HEAD(&ei->i_es_list);
	ei->i_es_all_nr = 0;
	ei->i_es_shk_nr = 0;
	ei->i_es_shrink_lblk = 0;
	ei->i_reserved_data_blocks = 0;
	ei->i_da_metadata_calc_len = 0;
	ei->i_da_metadata_calc_last_lblock = 0;
	spin_lock_init(&(ei->i_block_reservation_lock));
	pxt4_init_pending_tree(&ei->i_pending_tree);
#ifdef CONFIG_QUOTA
	ei->i_reserved_quota = 0;
	memset(&ei->i_dquot, 0, sizeof(ei->i_dquot));
#endif
	ei->jinode = NULL;
	INIT_LIST_HEAD(&ei->i_rsv_conversion_list);
	spin_lock_init(&ei->i_completed_io_lock);
	ei->i_sync_tid = 0;
	ei->i_datasync_tid = 0;
	atomic_set(&ei->i_unwritten, 0);
	INIT_WORK(&ei->i_rsv_conversion_work, pxt4_end_io_rsv_work);
	return &ei->vfs_inode;
}

static int pxt4_drop_inode(struct inode *inode)
{
	int drop = generic_drop_inode(inode);

	if (!drop)
		drop = fscrypt_drop_inode(inode);

	trace_pxt4_drop_inode(inode, drop);
	return drop;
}

static void pxt4_free_in_core_inode(struct inode *inode)
{
	fscrypt_free_inode(inode);
	kmem_cache_free(pxt4_inode_cachep, PXT4_I(inode));
}

static void pxt4_destroy_inode(struct inode *inode)
{
	if (!list_empty(&(PXT4_I(inode)->i_orphan))) {
		pxt4_msg(inode->i_sb, KERN_ERR,
			 "Inode %lu (%p): orphan list check failed!",
			 inode->i_ino, PXT4_I(inode));
		print_hex_dump(KERN_INFO, "", DUMP_PREFIX_ADDRESS, 16, 4,
				PXT4_I(inode), sizeof(struct pxt4_inode_info),
				true);
		dump_stack();
	}
}

static void init_once(void *foo)
{
	struct pxt4_inode_info *ei = (struct pxt4_inode_info *) foo;

	INIT_LIST_HEAD(&ei->i_orphan);
	init_rwsem(&ei->xattr_sem);
	init_rwsem(&ei->i_data_sem);
	init_rwsem(&ei->i_mmap_sem);
	inode_init_once(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
	pxt4_inode_cachep = kmem_cache_create_usercopy("pxt4_inode_cache",
				sizeof(struct pxt4_inode_info), 0,
				(SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD|
					SLAB_ACCOUNT),
				offsetof(struct pxt4_inode_info, i_data),
				sizeof_field(struct pxt4_inode_info, i_data),
				init_once);
	if (pxt4_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(pxt4_inode_cachep);
}

void pxt4_clear_inode(struct inode *inode)
{
	invalidate_inode_buffers(inode);
	clear_inode(inode);
	pxt4_discard_preallocations(inode);
	pxt4_es_remove_extent(inode, 0, EXT_MAX_BLOCKS);
	dquot_drop(inode);
	if (PXT4_I(inode)->jinode) {
		jbd3_journal_release_jbd_inode(PXT4_JOURNAL(inode),
					       PXT4_I(inode)->jinode);
		jbd3_free_inode(PXT4_I(inode)->jinode);
		PXT4_I(inode)->jinode = NULL;
	}
	fscrypt_put_encryption_info(inode);
	fsverity_cleanup_inode(inode);
}

static struct inode *pxt4_nfs_get_inode(struct super_block *sb,
					u64 ino, u32 generation)
{
	struct inode *inode;

	/*
	 * Currently we don't know the generation for parent directory, so
	 * a generation of 0 means "accept any"
	 */
	inode = pxt4_iget(sb, ino, PXT4_IGET_HANDLE);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (generation && inode->i_generation != generation) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}

	return inode;
}

static struct dentry *pxt4_fh_to_dentry(struct super_block *sb, struct fid *fid,
					int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    pxt4_nfs_get_inode);
}

static struct dentry *pxt4_fh_to_parent(struct super_block *sb, struct fid *fid,
					int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    pxt4_nfs_get_inode);
}

static int pxt4_nfs_commit_metadata(struct inode *inode)
{
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL
	};

	trace_pxt4_nfs_commit_metadata(inode);
	return pxt4_write_inode(inode, &wbc);
}

/*
 * Try to release metadata pages (indirect blocks, directories) which are
 * mapped via the block device.  Since these pages could have journal heads
 * which would prevent try_to_free_buffers() from freeing them, we must use
 * jbd3 layer's try_to_free_buffers() function to release them.
 */
static int bdev_try_to_free_page(struct super_block *sb, struct page *page,
				 gfp_t wait)
{
	journal_t *journal = PXT4_SB(sb)->s_journal;

	WARN_ON(PageChecked(page));
	if (!page_has_buffers(page))
		return 0;
	if (journal)
		return jbd3_journal_try_to_free_buffers(journal, page,
						wait & ~__GFP_DIRECT_RECLAIM);
	return try_to_free_buffers(page);
}

#ifdef CONFIG_FS_ENCRYPTION
static int pxt4_get_context(struct inode *inode, void *ctx, size_t len)
{
	return pxt4_xattr_get(inode, PXT4_XATTR_INDEX_ENCRYPTION,
				 PXT4_XATTR_NAME_ENCRYPTION_CONTEXT, ctx, len);
}

static int pxt4_set_context(struct inode *inode, const void *ctx, size_t len,
							void *fs_data)
{
	handle_t *handle = fs_data;
	int res, res2, credits, retries = 0;

	/*
	 * Encrypting the root directory is not allowed because e2fsck expects
	 * lost+found to exist and be unencrypted, and encrypting the root
	 * directory would imply encrypting the lost+found directory as well as
	 * the filename "lost+found" itself.
	 */
	if (inode->i_ino == PXT4_ROOT_INO)
		return -EPERM;

	if (WARN_ON_ONCE(IS_DAX(inode) && i_size_read(inode)))
		return -EINVAL;

	res = pxt4_convert_inline_data(inode);
	if (res)
		return res;

	/*
	 * If a journal handle was specified, then the encryption context is
	 * being set on a new inode via inheritance and is part of a larger
	 * transaction to create the inode.  Otherwise the encryption context is
	 * being set on an existing inode in its own transaction.  Only in the
	 * latter case should the "retry on ENOSPC" logic be used.
	 */

	if (handle) {
		res = pxt4_xattr_set_handle(handle, inode,
					    PXT4_XATTR_INDEX_ENCRYPTION,
					    PXT4_XATTR_NAME_ENCRYPTION_CONTEXT,
					    ctx, len, 0);
		if (!res) {
			pxt4_set_inode_flag(inode, PXT4_INODE_ENCRYPT);
			pxt4_clear_inode_state(inode,
					PXT4_STATE_MAY_INLINE_DATA);
			/*
			 * Update inode->i_flags - S_ENCRYPTED will be enabled,
			 * S_DAX may be disabled
			 */
			pxt4_set_inode_flags(inode);
		}
		return res;
	}

	res = dquot_initialize(inode);
	if (res)
		return res;
retry:
	res = pxt4_xattr_set_credits(inode, len, false /* is_create */,
				     &credits);
	if (res)
		return res;

	handle = pxt4_journal_start(inode, PXT4_HT_MISC, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	res = pxt4_xattr_set_handle(handle, inode, PXT4_XATTR_INDEX_ENCRYPTION,
				    PXT4_XATTR_NAME_ENCRYPTION_CONTEXT,
				    ctx, len, 0);
	if (!res) {
		pxt4_set_inode_flag(inode, PXT4_INODE_ENCRYPT);
		/*
		 * Update inode->i_flags - S_ENCRYPTED will be enabled,
		 * S_DAX may be disabled
		 */
		pxt4_set_inode_flags(inode);
		res = pxt4_mark_inode_dirty(handle, inode);
		if (res)
			PXT4_ERROR_INODE(inode, "Failed to mark inode dirty");
	}
	res2 = pxt4_journal_stop(handle);

	if (res == -ENOSPC && pxt4_should_retry_alloc(inode->i_sb, &retries))
		goto retry;
	if (!res)
		res = res2;
	return res;
}

static bool pxt4_dummy_context(struct inode *inode)
{
	return DUMMY_ENCRYPTION_ENABLED(PXT4_SB(inode->i_sb));
}

static const struct fscrypt_operations pxt4_cryptops = {
	.key_prefix		= "pxt4:",
	.get_context		= pxt4_get_context,
	.set_context		= pxt4_set_context,
	.dummy_context		= pxt4_dummy_context,
	.empty_dir		= pxt4_empty_dir,
	.max_namelen		= PXT4_NAME_LEN,
};
#endif

#ifdef CONFIG_QUOTA
static const char * const quotatypes[] = INITQFNAMES;
#define QTYPE2NAME(t) (quotatypes[t])

static int pxt4_write_dquot(struct dquot *dquot);
static int pxt4_acquire_dquot(struct dquot *dquot);
static int pxt4_release_dquot(struct dquot *dquot);
static int pxt4_mark_dquot_dirty(struct dquot *dquot);
static int pxt4_write_info(struct super_block *sb, int type);
static int pxt4_quota_on(struct super_block *sb, int type, int format_id,
			 const struct path *path);
static int pxt4_quota_on_mount(struct super_block *sb, int type);
static ssize_t pxt4_quota_read(struct super_block *sb, int type, char *data,
			       size_t len, loff_t off);
static ssize_t pxt4_quota_write(struct super_block *sb, int type,
				const char *data, size_t len, loff_t off);
static int pxt4_quota_enable(struct super_block *sb, int type, int format_id,
			     unsigned int flags);
static int pxt4_enable_quotas(struct super_block *sb);
static int pxt4_get_next_id(struct super_block *sb, struct kqid *qid);

static struct dquot **pxt4_get_dquots(struct inode *inode)
{
	return PXT4_I(inode)->i_dquot;
}

static const struct dquot_operations pxt4_quota_operations = {
	.get_reserved_space	= pxt4_get_reserved_space,
	.write_dquot		= pxt4_write_dquot,
	.acquire_dquot		= pxt4_acquire_dquot,
	.release_dquot		= pxt4_release_dquot,
	.mark_dirty		= pxt4_mark_dquot_dirty,
	.write_info		= pxt4_write_info,
	.alloc_dquot		= dquot_alloc,
	.destroy_dquot		= dquot_destroy,
	.get_projid		= pxt4_get_projid,
	.get_inode_usage	= pxt4_get_inode_usage,
	.get_next_id		= pxt4_get_next_id,
};

static const struct quotactl_ops pxt4_qctl_operations = {
	.quota_on	= pxt4_quota_on,
	.quota_off	= pxt4_quota_off,
	.quota_sync	= dquot_quota_sync,
	.get_state	= dquot_get_state,
	.set_info	= dquot_set_dqinfo,
	.get_dqblk	= dquot_get_dqblk,
	.set_dqblk	= dquot_set_dqblk,
	.get_nextdqblk	= dquot_get_next_dqblk,
};
#endif

static const struct super_operations pxt4_sops = {
	.alloc_inode	= pxt4_alloc_inode,
	.free_inode	= pxt4_free_in_core_inode,
	.destroy_inode	= pxt4_destroy_inode,
	.write_inode	= pxt4_write_inode,
	.dirty_inode	= pxt4_dirty_inode,
	.drop_inode	= pxt4_drop_inode,
	.evict_inode	= pxt4_evict_inode,
	.put_super	= pxt4_put_super,
	.sync_fs	= pxt4_sync_fs,
	.freeze_fs	= pxt4_freeze,
	.unfreeze_fs	= pxt4_unfreeze,
	.statfs		= pxt4_statfs,
	.remount_fs	= pxt4_remount,
	.show_options	= pxt4_show_options,
#ifdef CONFIG_QUOTA
	.quota_read	= pxt4_quota_read,
	.quota_write	= pxt4_quota_write,
	.get_dquots	= pxt4_get_dquots,
#endif
	.bdev_try_to_free_page = bdev_try_to_free_page,
};

static const struct export_operations pxt4_export_ops = {
	.fh_to_dentry = pxt4_fh_to_dentry,
	.fh_to_parent = pxt4_fh_to_parent,
	.get_parent = pxt4_get_parent,
	.commit_metadata = pxt4_nfs_commit_metadata,
};

enum {
	Opt_bsd_df, Opt_minix_df, Opt_grpid, Opt_nogrpid,
	Opt_resgid, Opt_resuid, Opt_sb, Opt_err_cont, Opt_err_panic, Opt_err_ro,
	Opt_nouid32, Opt_debug, Opt_removed,
	Opt_user_xattr, Opt_nouser_xattr, Opt_acl, Opt_noacl,
	Opt_auto_da_alloc, Opt_noauto_da_alloc, Opt_noload,
	Opt_commit, Opt_min_batch_time, Opt_max_batch_time, Opt_journal_dev,
	Opt_journal_path, Opt_journal_checksum, Opt_journal_async_commit,
	Opt_abort, Opt_data_journal, Opt_data_ordered, Opt_data_writeback,
	Opt_data_err_abort, Opt_data_err_ignore, Opt_test_dummy_encryption,
	Opt_usrjquota, Opt_grpjquota, Opt_offusrjquota, Opt_offgrpjquota,
	Opt_jqfmt_vfsold, Opt_jqfmt_vfsv0, Opt_jqfmt_vfsv1, Opt_quota,
	Opt_noquota, Opt_barrier, Opt_nobarrier, Opt_err,
	Opt_usrquota, Opt_grpquota, Opt_prjquota, Opt_i_version, Opt_dax,
	Opt_stripe, Opt_delalloc, Opt_nodelalloc, Opt_warn_on_error,
	Opt_nowarn_on_error, Opt_mblk_io_submit,
	Opt_lazytime, Opt_nolazytime, Opt_debug_want_extra_isize,
	Opt_nomblk_io_submit, Opt_block_validity, Opt_noblock_validity,
	Opt_inode_readahead_blks, Opt_journal_ioprio,
	Opt_dioread_nolock, Opt_dioread_lock,
	Opt_discard, Opt_nodiscard, Opt_init_itable, Opt_noinit_itable,
	Opt_max_dir_size_kb, Opt_nojournal_checksum, Opt_nombcache,
};

static const match_table_t tokens = {
	{Opt_bsd_df, "bsddf"},
	{Opt_minix_df, "minixdf"},
	{Opt_grpid, "grpid"},
	{Opt_grpid, "bsdgroups"},
	{Opt_nogrpid, "nogrpid"},
	{Opt_nogrpid, "sysvgroups"},
	{Opt_resgid, "resgid=%u"},
	{Opt_resuid, "resuid=%u"},
	{Opt_sb, "sb=%u"},
	{Opt_err_cont, "errors=continue"},
	{Opt_err_panic, "errors=panic"},
	{Opt_err_ro, "errors=remount-ro"},
	{Opt_nouid32, "nouid32"},
	{Opt_debug, "debug"},
	{Opt_removed, "oldalloc"},
	{Opt_removed, "orlov"},
	{Opt_user_xattr, "user_xattr"},
	{Opt_nouser_xattr, "nouser_xattr"},
	{Opt_acl, "acl"},
	{Opt_noacl, "noacl"},
	{Opt_noload, "norecovery"},
	{Opt_noload, "noload"},
	{Opt_removed, "nobh"},
	{Opt_removed, "bh"},
	{Opt_commit, "commit=%u"},
	{Opt_min_batch_time, "min_batch_time=%u"},
	{Opt_max_batch_time, "max_batch_time=%u"},
	{Opt_journal_dev, "journal_dev=%u"},
	{Opt_journal_path, "journal_path=%s"},
	{Opt_journal_checksum, "journal_checksum"},
	{Opt_nojournal_checksum, "nojournal_checksum"},
	{Opt_journal_async_commit, "journal_async_commit"},
	{Opt_abort, "abort"},
	{Opt_data_journal, "data=journal"},
	{Opt_data_ordered, "data=ordered"},
	{Opt_data_writeback, "data=writeback"},
	{Opt_data_err_abort, "data_err=abort"},
	{Opt_data_err_ignore, "data_err=ignore"},
	{Opt_offusrjquota, "usrjquota="},
	{Opt_usrjquota, "usrjquota=%s"},
	{Opt_offgrpjquota, "grpjquota="},
	{Opt_grpjquota, "grpjquota=%s"},
	{Opt_jqfmt_vfsold, "jqfmt=vfsold"},
	{Opt_jqfmt_vfsv0, "jqfmt=vfsv0"},
	{Opt_jqfmt_vfsv1, "jqfmt=vfsv1"},
	{Opt_grpquota, "grpquota"},
	{Opt_noquota, "noquota"},
	{Opt_quota, "quota"},
	{Opt_usrquota, "usrquota"},
	{Opt_prjquota, "prjquota"},
	{Opt_barrier, "barrier=%u"},
	{Opt_barrier, "barrier"},
	{Opt_nobarrier, "nobarrier"},
	{Opt_i_version, "i_version"},
	{Opt_dax, "dax"},
	{Opt_stripe, "stripe=%u"},
	{Opt_delalloc, "delalloc"},
	{Opt_warn_on_error, "warn_on_error"},
	{Opt_nowarn_on_error, "nowarn_on_error"},
	{Opt_lazytime, "lazytime"},
	{Opt_nolazytime, "nolazytime"},
	{Opt_debug_want_extra_isize, "debug_want_extra_isize=%u"},
	{Opt_nodelalloc, "nodelalloc"},
	{Opt_removed, "mblk_io_submit"},
	{Opt_removed, "nomblk_io_submit"},
	{Opt_block_validity, "block_validity"},
	{Opt_noblock_validity, "noblock_validity"},
	{Opt_inode_readahead_blks, "inode_readahead_blks=%u"},
	{Opt_journal_ioprio, "journal_ioprio=%u"},
	{Opt_auto_da_alloc, "auto_da_alloc=%u"},
	{Opt_auto_da_alloc, "auto_da_alloc"},
	{Opt_noauto_da_alloc, "noauto_da_alloc"},
	{Opt_dioread_nolock, "dioread_nolock"},
	{Opt_dioread_lock, "dioread_lock"},
	{Opt_discard, "discard"},
	{Opt_nodiscard, "nodiscard"},
	{Opt_init_itable, "init_itable=%u"},
	{Opt_init_itable, "init_itable"},
	{Opt_noinit_itable, "noinit_itable"},
	{Opt_max_dir_size_kb, "max_dir_size_kb=%u"},
	{Opt_test_dummy_encryption, "test_dummy_encryption"},
	{Opt_nombcache, "nombcache"},
	{Opt_nombcache, "no_mbcache"},	/* for backward compatibility */
	{Opt_removed, "check=none"},	/* mount option from pxt2/3 */
	{Opt_removed, "nocheck"},	/* mount option from pxt2/3 */
	{Opt_removed, "reservation"},	/* mount option from pxt2/3 */
	{Opt_removed, "noreservation"}, /* mount option from pxt2/3 */
	{Opt_removed, "journal=%u"},	/* mount option from pxt2/3 */
	{Opt_err, NULL},
};

static pxt4_fsblk_t get_sb_block(void **data)
{
	pxt4_fsblk_t	sb_block;
	char		*options = (char *) *data;

	if (!options || strncmp(options, "sb=", 3) != 0)
		return 1;	/* Default location */

	options += 3;
	/* TODO: use simple_strtoll with >32bit pxt4 */
	sb_block = simple_strtoul(options, &options, 0);
	if (*options && *options != ',') {
		printk(KERN_ERR "PXT4-fs: Invalid sb specification: %s\n",
		       (char *) *data);
		return 1;
	}
	if (*options == ',')
		options++;
	*data = (void *) options;

	return sb_block;
}

#define DEFAULT_JOURNAL_IOPRIO (IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 3))
static const char deprecated_msg[] =
	"Mount option \"%s\" will be removed by %s\n"
	"Contact linux-pxt4@vger.kernel.org if you think we should keep it.\n";

#ifdef CONFIG_QUOTA
static int set_qf_name(struct super_block *sb, int qtype, substring_t *args)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	char *qname, *old_qname = get_qf_name(sb, sbi, qtype);
	int ret = -1;

	if (sb_any_quota_loaded(sb) && !old_qname) {
		pxt4_msg(sb, KERN_ERR,
			"Cannot change journaled "
			"quota options when quota turned on");
		return -1;
	}
	if (pxt4_has_feature_quota(sb)) {
		pxt4_msg(sb, KERN_INFO, "Journaled quota options "
			 "ignored when QUOTA feature is enabled");
		return 1;
	}
	qname = match_strdup(args);
	if (!qname) {
		pxt4_msg(sb, KERN_ERR,
			"Not enough memory for storing quotafile name");
		return -1;
	}
	if (old_qname) {
		if (strcmp(old_qname, qname) == 0)
			ret = 1;
		else
			pxt4_msg(sb, KERN_ERR,
				 "%s quota file already specified",
				 QTYPE2NAME(qtype));
		goto errout;
	}
	if (strchr(qname, '/')) {
		pxt4_msg(sb, KERN_ERR,
			"quotafile must be on filesystem root");
		goto errout;
	}
	rcu_assign_pointer(sbi->s_qf_names[qtype], qname);
	set_opt(sb, QUOTA);
	return 1;
errout:
	kfree(qname);
	return ret;
}

static int clear_qf_name(struct super_block *sb, int qtype)
{

	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	char *old_qname = get_qf_name(sb, sbi, qtype);

	if (sb_any_quota_loaded(sb) && old_qname) {
		pxt4_msg(sb, KERN_ERR, "Cannot change journaled quota options"
			" when quota turned on");
		return -1;
	}
	rcu_assign_pointer(sbi->s_qf_names[qtype], NULL);
	synchronize_rcu();
	kfree(old_qname);
	return 1;
}
#endif

#define MOPT_SET	0x0001
#define MOPT_CLEAR	0x0002
#define MOPT_NOSUPPORT	0x0004
#define MOPT_EXPLICIT	0x0008
#define MOPT_CLEAR_ERR	0x0010
#define MOPT_GTE0	0x0020
#ifdef CONFIG_QUOTA
#define MOPT_Q		0
#define MOPT_QFMT	0x0040
#else
#define MOPT_Q		MOPT_NOSUPPORT
#define MOPT_QFMT	MOPT_NOSUPPORT
#endif
#define MOPT_DATAJ	0x0080
#define MOPT_NO_PXT2	0x0100
#define MOPT_NO_EXT3	0x0200
#define MOPT_PXT4_ONLY	(MOPT_NO_PXT2 | MOPT_NO_EXT3)
#define MOPT_STRING	0x0400

static const struct mount_opts {
	int	token;
	int	mount_opt;
	int	flags;
} pxt4_mount_opts[] = {
	{Opt_minix_df, PXT4_MOUNT_MINIX_DF, MOPT_SET},
	{Opt_bsd_df, PXT4_MOUNT_MINIX_DF, MOPT_CLEAR},
	{Opt_grpid, PXT4_MOUNT_GRPID, MOPT_SET},
	{Opt_nogrpid, PXT4_MOUNT_GRPID, MOPT_CLEAR},
	{Opt_block_validity, PXT4_MOUNT_BLOCK_VALIDITY, MOPT_SET},
	{Opt_noblock_validity, PXT4_MOUNT_BLOCK_VALIDITY, MOPT_CLEAR},
	{Opt_dioread_nolock, PXT4_MOUNT_DIOREAD_NOLOCK,
	 MOPT_PXT4_ONLY | MOPT_SET},
	{Opt_dioread_lock, PXT4_MOUNT_DIOREAD_NOLOCK,
	 MOPT_PXT4_ONLY | MOPT_CLEAR},
	{Opt_discard, PXT4_MOUNT_DISCARD, MOPT_SET},
	{Opt_nodiscard, PXT4_MOUNT_DISCARD, MOPT_CLEAR},
	{Opt_delalloc, PXT4_MOUNT_DELALLOC,
	 MOPT_PXT4_ONLY | MOPT_SET | MOPT_EXPLICIT},
	{Opt_nodelalloc, PXT4_MOUNT_DELALLOC,
	 MOPT_PXT4_ONLY | MOPT_CLEAR},
	{Opt_warn_on_error, PXT4_MOUNT_WARN_ON_ERROR, MOPT_SET},
	{Opt_nowarn_on_error, PXT4_MOUNT_WARN_ON_ERROR, MOPT_CLEAR},
	{Opt_nojournal_checksum, PXT4_MOUNT_JOURNAL_CHECKSUM,
	 MOPT_PXT4_ONLY | MOPT_CLEAR},
	{Opt_journal_checksum, PXT4_MOUNT_JOURNAL_CHECKSUM,
	 MOPT_PXT4_ONLY | MOPT_SET | MOPT_EXPLICIT},
	{Opt_journal_async_commit, (PXT4_MOUNT_JOURNAL_ASYNC_COMMIT |
				    PXT4_MOUNT_JOURNAL_CHECKSUM),
	 MOPT_PXT4_ONLY | MOPT_SET | MOPT_EXPLICIT},
	{Opt_noload, PXT4_MOUNT_NOLOAD, MOPT_NO_PXT2 | MOPT_SET},
	{Opt_err_panic, PXT4_MOUNT_ERRORS_PANIC, MOPT_SET | MOPT_CLEAR_ERR},
	{Opt_err_ro, PXT4_MOUNT_ERRORS_RO, MOPT_SET | MOPT_CLEAR_ERR},
	{Opt_err_cont, PXT4_MOUNT_ERRORS_CONT, MOPT_SET | MOPT_CLEAR_ERR},
	{Opt_data_err_abort, PXT4_MOUNT_DATA_ERR_ABORT,
	 MOPT_NO_PXT2},
	{Opt_data_err_ignore, PXT4_MOUNT_DATA_ERR_ABORT,
	 MOPT_NO_PXT2},
	{Opt_barrier, PXT4_MOUNT_BARRIER, MOPT_SET},
	{Opt_nobarrier, PXT4_MOUNT_BARRIER, MOPT_CLEAR},
	{Opt_noauto_da_alloc, PXT4_MOUNT_NO_AUTO_DA_ALLOC, MOPT_SET},
	{Opt_auto_da_alloc, PXT4_MOUNT_NO_AUTO_DA_ALLOC, MOPT_CLEAR},
	{Opt_noinit_itable, PXT4_MOUNT_INIT_INODE_TABLE, MOPT_CLEAR},
	{Opt_commit, 0, MOPT_GTE0},
	{Opt_max_batch_time, 0, MOPT_GTE0},
	{Opt_min_batch_time, 0, MOPT_GTE0},
	{Opt_inode_readahead_blks, 0, MOPT_GTE0},
	{Opt_init_itable, 0, MOPT_GTE0},
	{Opt_dax, PXT4_MOUNT_DAX, MOPT_SET},
	{Opt_stripe, 0, MOPT_GTE0},
	{Opt_resuid, 0, MOPT_GTE0},
	{Opt_resgid, 0, MOPT_GTE0},
	{Opt_journal_dev, 0, MOPT_NO_PXT2 | MOPT_GTE0},
	{Opt_journal_path, 0, MOPT_NO_PXT2 | MOPT_STRING},
	{Opt_journal_ioprio, 0, MOPT_NO_PXT2 | MOPT_GTE0},
	{Opt_data_journal, PXT4_MOUNT_JOURNAL_DATA, MOPT_NO_PXT2 | MOPT_DATAJ},
	{Opt_data_ordered, PXT4_MOUNT_ORDERED_DATA, MOPT_NO_PXT2 | MOPT_DATAJ},
	{Opt_data_writeback, PXT4_MOUNT_WRITEBACK_DATA,
	 MOPT_NO_PXT2 | MOPT_DATAJ},
	{Opt_user_xattr, PXT4_MOUNT_XATTR_USER, MOPT_SET},
	{Opt_nouser_xattr, PXT4_MOUNT_XATTR_USER, MOPT_CLEAR},
#ifdef CONFIG_PXT4_FS_POSIX_ACL
	{Opt_acl, PXT4_MOUNT_POSIX_ACL, MOPT_SET},
	{Opt_noacl, PXT4_MOUNT_POSIX_ACL, MOPT_CLEAR},
#else
	{Opt_acl, 0, MOPT_NOSUPPORT},
	{Opt_noacl, 0, MOPT_NOSUPPORT},
#endif
	{Opt_nouid32, PXT4_MOUNT_NO_UID32, MOPT_SET},
	{Opt_debug, PXT4_MOUNT_DEBUG, MOPT_SET},
	{Opt_debug_want_extra_isize, 0, MOPT_GTE0},
	{Opt_quota, PXT4_MOUNT_QUOTA | PXT4_MOUNT_USRQUOTA, MOPT_SET | MOPT_Q},
	{Opt_usrquota, PXT4_MOUNT_QUOTA | PXT4_MOUNT_USRQUOTA,
							MOPT_SET | MOPT_Q},
	{Opt_grpquota, PXT4_MOUNT_QUOTA | PXT4_MOUNT_GRPQUOTA,
							MOPT_SET | MOPT_Q},
	{Opt_prjquota, PXT4_MOUNT_QUOTA | PXT4_MOUNT_PRJQUOTA,
							MOPT_SET | MOPT_Q},
	{Opt_noquota, (PXT4_MOUNT_QUOTA | PXT4_MOUNT_USRQUOTA |
		       PXT4_MOUNT_GRPQUOTA | PXT4_MOUNT_PRJQUOTA),
							MOPT_CLEAR | MOPT_Q},
	{Opt_usrjquota, 0, MOPT_Q},
	{Opt_grpjquota, 0, MOPT_Q},
	{Opt_offusrjquota, 0, MOPT_Q},
	{Opt_offgrpjquota, 0, MOPT_Q},
	{Opt_jqfmt_vfsold, QFMT_VFS_OLD, MOPT_QFMT},
	{Opt_jqfmt_vfsv0, QFMT_VFS_V0, MOPT_QFMT},
	{Opt_jqfmt_vfsv1, QFMT_VFS_V1, MOPT_QFMT},
	{Opt_max_dir_size_kb, 0, MOPT_GTE0},
	{Opt_test_dummy_encryption, 0, MOPT_GTE0},
	{Opt_nombcache, PXT4_MOUNT_NO_MBCACHE, MOPT_SET},
	{Opt_err, 0, 0}
};

#ifdef CONFIG_UNICODE
static const struct pxt4_sb_encodings {
	__u16 magic;
	char *name;
	char *version;
} pxt4_sb_encoding_map[] = {
	{PXT4_ENC_UTF8_12_1, "utf8", "12.1.0"},
};

static int pxt4_sb_read_encoding(const struct pxt4_super_block *es,
				 const struct pxt4_sb_encodings **encoding,
				 __u16 *flags)
{
	__u16 magic = le16_to_cpu(es->s_encoding);
	int i;

	for (i = 0; i < ARRAY_SIZE(pxt4_sb_encoding_map); i++)
		if (magic == pxt4_sb_encoding_map[i].magic)
			break;

	if (i >= ARRAY_SIZE(pxt4_sb_encoding_map))
		return -EINVAL;

	*encoding = &pxt4_sb_encoding_map[i];
	*flags = le16_to_cpu(es->s_encoding_flags);

	return 0;
}
#endif

static int handle_mount_opt(struct super_block *sb, char *opt, int token,
			    substring_t *args, unsigned long *journal_devnum,
			    unsigned int *journal_ioprio, int is_remount)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	const struct mount_opts *m;
	kuid_t uid;
	kgid_t gid;
	int arg = 0;

#ifdef CONFIG_QUOTA
	if (token == Opt_usrjquota)
		return set_qf_name(sb, USRQUOTA, &args[0]);
	else if (token == Opt_grpjquota)
		return set_qf_name(sb, GRPQUOTA, &args[0]);
	else if (token == Opt_offusrjquota)
		return clear_qf_name(sb, USRQUOTA);
	else if (token == Opt_offgrpjquota)
		return clear_qf_name(sb, GRPQUOTA);
#endif
	switch (token) {
	case Opt_noacl:
	case Opt_nouser_xattr:
		pxt4_msg(sb, KERN_WARNING, deprecated_msg, opt, "3.5");
		break;
	case Opt_sb:
		return 1;	/* handled by get_sb_block() */
	case Opt_removed:
		pxt4_msg(sb, KERN_WARNING, "Ignoring removed %s option", opt);
		return 1;
	case Opt_abort:
		sbi->s_mount_flags |= PXT4_MF_FS_ABORTED;
		return 1;
	case Opt_i_version:
		sb->s_flags |= SB_I_VERSION;
		return 1;
	case Opt_lazytime:
		sb->s_flags |= SB_LAZYTIME;
		return 1;
	case Opt_nolazytime:
		sb->s_flags &= ~SB_LAZYTIME;
		return 1;
	}

	for (m = pxt4_mount_opts; m->token != Opt_err; m++)
		if (token == m->token)
			break;

	if (m->token == Opt_err) {
		pxt4_msg(sb, KERN_ERR, "Unrecognized mount option \"%s\" "
			 "or missing value", opt);
		return -1;
	}

	if ((m->flags & MOPT_NO_PXT2) && IS_PXT2_SB(sb)) {
		pxt4_msg(sb, KERN_ERR,
			 "Mount option \"%s\" incompatible with pxt2", opt);
		return -1;
	}
	if ((m->flags & MOPT_NO_EXT3) && IS_EXT3_SB(sb)) {
		pxt4_msg(sb, KERN_ERR,
			 "Mount option \"%s\" incompatible with ext3", opt);
		return -1;
	}

	if (args->from && !(m->flags & MOPT_STRING) && match_int(args, &arg))
		return -1;
	if (args->from && (m->flags & MOPT_GTE0) && (arg < 0))
		return -1;
	if (m->flags & MOPT_EXPLICIT) {
		if (m->mount_opt & PXT4_MOUNT_DELALLOC) {
			set_opt2(sb, EXPLICIT_DELALLOC);
		} else if (m->mount_opt & PXT4_MOUNT_JOURNAL_CHECKSUM) {
			set_opt2(sb, EXPLICIT_JOURNAL_CHECKSUM);
		} else
			return -1;
	}
	if (m->flags & MOPT_CLEAR_ERR)
		clear_opt(sb, ERRORS_MASK);
	if (token == Opt_noquota && sb_any_quota_loaded(sb)) {
		pxt4_msg(sb, KERN_ERR, "Cannot change quota "
			 "options when quota turned on");
		return -1;
	}

	if (m->flags & MOPT_NOSUPPORT) {
		pxt4_msg(sb, KERN_ERR, "%s option not supported", opt);
	} else if (token == Opt_commit) {
		if (arg == 0)
			arg = JBD3_DEFAULT_MAX_COMMIT_AGE;
		else if (arg > INT_MAX / HZ) {
			pxt4_msg(sb, KERN_ERR,
				 "Invalid commit interval %d, "
				 "must be smaller than %d",
				 arg, INT_MAX / HZ);
			return -1;
		}
		sbi->s_commit_interval = HZ * arg;
	} else if (token == Opt_debug_want_extra_isize) {
		if ((arg & 1) ||
		    (arg < 4) ||
		    (arg > (sbi->s_inode_size - PXT4_GOOD_OLD_INODE_SIZE))) {
			pxt4_msg(sb, KERN_ERR,
				 "Invalid want_extra_isize %d", arg);
			return -1;
		}
		sbi->s_want_extra_isize = arg;
	} else if (token == Opt_max_batch_time) {
		sbi->s_max_batch_time = arg;
	} else if (token == Opt_min_batch_time) {
		sbi->s_min_batch_time = arg;
	} else if (token == Opt_inode_readahead_blks) {
		if (arg && (arg > (1 << 30) || !is_power_of_2(arg))) {
			pxt4_msg(sb, KERN_ERR,
				 "PXT4-fs: inode_readahead_blks must be "
				 "0 or a power of 2 smaller than 2^31");
			return -1;
		}
		sbi->s_inode_readahead_blks = arg;
	} else if (token == Opt_init_itable) {
		set_opt(sb, INIT_INODE_TABLE);
		if (!args->from)
			arg = PXT4_DEF_LI_WAIT_MULT;
		sbi->s_li_wait_mult = arg;
	} else if (token == Opt_max_dir_size_kb) {
		sbi->s_max_dir_size_kb = arg;
	} else if (token == Opt_stripe) {
		sbi->s_stripe = arg;
	} else if (token == Opt_resuid) {
		uid = make_kuid(current_user_ns(), arg);
		if (!uid_valid(uid)) {
			pxt4_msg(sb, KERN_ERR, "Invalid uid value %d", arg);
			return -1;
		}
		sbi->s_resuid = uid;
	} else if (token == Opt_resgid) {
		gid = make_kgid(current_user_ns(), arg);
		if (!gid_valid(gid)) {
			pxt4_msg(sb, KERN_ERR, "Invalid gid value %d", arg);
			return -1;
		}
		sbi->s_resgid = gid;
	} else if (token == Opt_journal_dev) {
		if (is_remount) {
			pxt4_msg(sb, KERN_ERR,
				 "Cannot specify journal on remount");
			return -1;
		}
		*journal_devnum = arg;
	} else if (token == Opt_journal_path) {
		char *journal_path;
		struct inode *journal_inode;
		struct path path;
		int error;

		if (is_remount) {
			pxt4_msg(sb, KERN_ERR,
				 "Cannot specify journal on remount");
			return -1;
		}
		journal_path = match_strdup(&args[0]);
		if (!journal_path) {
			pxt4_msg(sb, KERN_ERR, "error: could not dup "
				"journal device string");
			return -1;
		}

		error = kern_path(journal_path, LOOKUP_FOLLOW, &path);
		if (error) {
			pxt4_msg(sb, KERN_ERR, "error: could not find "
				"journal device path: error %d", error);
			kfree(journal_path);
			return -1;
		}

		journal_inode = d_inode(path.dentry);
		if (!S_ISBLK(journal_inode->i_mode)) {
			pxt4_msg(sb, KERN_ERR, "error: journal path %s "
				"is not a block device", journal_path);
			path_put(&path);
			kfree(journal_path);
			return -1;
		}

		*journal_devnum = new_encode_dev(journal_inode->i_rdev);
		path_put(&path);
		kfree(journal_path);
	} else if (token == Opt_journal_ioprio) {
		if (arg > 7) {
			pxt4_msg(sb, KERN_ERR, "Invalid journal IO priority"
				 " (must be 0-7)");
			return -1;
		}
		*journal_ioprio =
			IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, arg);
	} else if (token == Opt_test_dummy_encryption) {
#ifdef CONFIG_FS_ENCRYPTION
		sbi->s_mount_flags |= PXT4_MF_TEST_DUMMY_ENCRYPTION;
		pxt4_msg(sb, KERN_WARNING,
			 "Test dummy encryption mode enabled");
#else
		pxt4_msg(sb, KERN_WARNING,
			 "Test dummy encryption mount option ignored");
#endif
	} else if (m->flags & MOPT_DATAJ) {
		if (is_remount) {
			if (!sbi->s_journal)
				pxt4_msg(sb, KERN_WARNING, "Remounting file system with no journal so ignoring journalled data option");
			else if (test_opt(sb, DATA_FLAGS) != m->mount_opt) {
				pxt4_msg(sb, KERN_ERR,
					 "Cannot change data mode on remount");
				return -1;
			}
		} else {
			clear_opt(sb, DATA_FLAGS);
			sbi->s_mount_opt |= m->mount_opt;
		}
#ifdef CONFIG_QUOTA
	} else if (m->flags & MOPT_QFMT) {
		if (sb_any_quota_loaded(sb) &&
		    sbi->s_jquota_fmt != m->mount_opt) {
			pxt4_msg(sb, KERN_ERR, "Cannot change journaled "
				 "quota options when quota turned on");
			return -1;
		}
		if (pxt4_has_feature_quota(sb)) {
			pxt4_msg(sb, KERN_INFO,
				 "Quota format mount options ignored "
				 "when QUOTA feature is enabled");
			return 1;
		}
		sbi->s_jquota_fmt = m->mount_opt;
#endif
	} else if (token == Opt_dax) {
#ifdef CONFIG_FS_DAX
		if (is_remount && test_opt(sb, DAX)) {
			pxt4_msg(sb, KERN_ERR, "can't mount with "
				"both data=journal and dax");
			return -1;
		}
		if (is_remount && !(sbi->s_mount_opt & PXT4_MOUNT_DAX)) {
			pxt4_msg(sb, KERN_ERR, "can't change "
					"dax mount option while remounting");
			return -1;
		}
		pxt4_msg(sb, KERN_WARNING,
		"DAX enabled. Warning: EXPERIMENTAL, use at your own risk");
		sbi->s_mount_opt |= m->mount_opt;
#else
		pxt4_msg(sb, KERN_INFO, "dax option not supported");
		return -1;
#endif
	} else if (token == Opt_data_err_abort) {
		sbi->s_mount_opt |= m->mount_opt;
	} else if (token == Opt_data_err_ignore) {
		sbi->s_mount_opt &= ~m->mount_opt;
	} else {
		if (!args->from)
			arg = 1;
		if (m->flags & MOPT_CLEAR)
			arg = !arg;
		else if (unlikely(!(m->flags & MOPT_SET))) {
			pxt4_msg(sb, KERN_WARNING,
				 "buggy handling of option %s", opt);
			WARN_ON(1);
			return -1;
		}
		if (arg != 0)
			sbi->s_mount_opt |= m->mount_opt;
		else
			sbi->s_mount_opt &= ~m->mount_opt;
	}
	return 1;
}

static int parse_options(char *options, struct super_block *sb,
			 unsigned long *journal_devnum,
			 unsigned int *journal_ioprio,
			 int is_remount)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	char *p, __maybe_unused *usr_qf_name, __maybe_unused *grp_qf_name;
	substring_t args[MAX_OPT_ARGS];
	int token;

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;
		/*
		 * Initialize args struct so we know whether arg was
		 * found; some options take optional arguments.
		 */
		args[0].to = args[0].from = NULL;
		token = match_token(p, tokens, args);
		if (handle_mount_opt(sb, p, token, args, journal_devnum,
				     journal_ioprio, is_remount) < 0)
			return 0;
	}
#ifdef CONFIG_QUOTA
	/*
	 * We do the test below only for project quotas. 'usrquota' and
	 * 'grpquota' mount options are allowed even without quota feature
	 * to support legacy quotas in quota files.
	 */
	if (test_opt(sb, PRJQUOTA) && !pxt4_has_feature_project(sb)) {
		pxt4_msg(sb, KERN_ERR, "Project quota feature not enabled. "
			 "Cannot enable project quota enforcement.");
		return 0;
	}
	usr_qf_name = get_qf_name(sb, sbi, USRQUOTA);
	grp_qf_name = get_qf_name(sb, sbi, GRPQUOTA);
	if (usr_qf_name || grp_qf_name) {
		if (test_opt(sb, USRQUOTA) && usr_qf_name)
			clear_opt(sb, USRQUOTA);

		if (test_opt(sb, GRPQUOTA) && grp_qf_name)
			clear_opt(sb, GRPQUOTA);

		if (test_opt(sb, GRPQUOTA) || test_opt(sb, USRQUOTA)) {
			pxt4_msg(sb, KERN_ERR, "old and new quota "
					"format mixing");
			return 0;
		}

		if (!sbi->s_jquota_fmt) {
			pxt4_msg(sb, KERN_ERR, "journaled quota format "
					"not specified");
			return 0;
		}
	}
#endif
	if (test_opt(sb, DIOREAD_NOLOCK)) {
		int blocksize =
			BLOCK_SIZE << le32_to_cpu(sbi->s_es->s_log_block_size);

		if (blocksize < PAGE_SIZE) {
			pxt4_msg(sb, KERN_ERR, "can't mount with "
				 "dioread_nolock if block size != PAGE_SIZE");
			return 0;
		}
	}
	return 1;
}

static inline void pxt4_show_quota_options(struct seq_file *seq,
					   struct super_block *sb)
{
#if defined(CONFIG_QUOTA)
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	char *usr_qf_name, *grp_qf_name;

	if (sbi->s_jquota_fmt) {
		char *fmtname = "";

		switch (sbi->s_jquota_fmt) {
		case QFMT_VFS_OLD:
			fmtname = "vfsold";
			break;
		case QFMT_VFS_V0:
			fmtname = "vfsv0";
			break;
		case QFMT_VFS_V1:
			fmtname = "vfsv1";
			break;
		}
		seq_printf(seq, ",jqfmt=%s", fmtname);
	}

	rcu_read_lock();
	usr_qf_name = rcu_dereference(sbi->s_qf_names[USRQUOTA]);
	grp_qf_name = rcu_dereference(sbi->s_qf_names[GRPQUOTA]);
	if (usr_qf_name)
		seq_show_option(seq, "usrjquota", usr_qf_name);
	if (grp_qf_name)
		seq_show_option(seq, "grpjquota", grp_qf_name);
	rcu_read_unlock();
#endif
}

static const char *token2str(int token)
{
	const struct match_token *t;

	for (t = tokens; t->token != Opt_err; t++)
		if (t->token == token && !strchr(t->pattern, '='))
			break;
	return t->pattern;
}

/*
 * Show an option if
 *  - it's set to a non-default value OR
 *  - if the per-sb default is different from the global default
 */
static int _pxt4_show_options(struct seq_file *seq, struct super_block *sb,
			      int nodefs)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_super_block *es = sbi->s_es;
	int def_errors, def_mount_opt = sbi->s_def_mount_opt;
	const struct mount_opts *m;
	char sep = nodefs ? '\n' : ',';

#define SEQ_OPTS_PUTS(str) seq_printf(seq, "%c" str, sep)
#define SEQ_OPTS_PRINT(str, arg) seq_printf(seq, "%c" str, sep, arg)

	if (sbi->s_sb_block != 1)
		SEQ_OPTS_PRINT("sb=%llu", sbi->s_sb_block);

	for (m = pxt4_mount_opts; m->token != Opt_err; m++) {
		int want_set = m->flags & MOPT_SET;
		if (((m->flags & (MOPT_SET|MOPT_CLEAR)) == 0) ||
		    (m->flags & MOPT_CLEAR_ERR))
			continue;
		if (!nodefs && !(m->mount_opt & (sbi->s_mount_opt ^ def_mount_opt)))
			continue; /* skip if same as the default */
		if ((want_set &&
		     (sbi->s_mount_opt & m->mount_opt) != m->mount_opt) ||
		    (!want_set && (sbi->s_mount_opt & m->mount_opt)))
			continue; /* select Opt_noFoo vs Opt_Foo */
		SEQ_OPTS_PRINT("%s", token2str(m->token));
	}

	if (nodefs || !uid_eq(sbi->s_resuid, make_kuid(&init_user_ns, PXT4_DEF_RESUID)) ||
	    le16_to_cpu(es->s_def_resuid) != PXT4_DEF_RESUID)
		SEQ_OPTS_PRINT("resuid=%u",
				from_kuid_munged(&init_user_ns, sbi->s_resuid));
	if (nodefs || !gid_eq(sbi->s_resgid, make_kgid(&init_user_ns, PXT4_DEF_RESGID)) ||
	    le16_to_cpu(es->s_def_resgid) != PXT4_DEF_RESGID)
		SEQ_OPTS_PRINT("resgid=%u",
				from_kgid_munged(&init_user_ns, sbi->s_resgid));
	def_errors = nodefs ? -1 : le16_to_cpu(es->s_errors);
	if (test_opt(sb, ERRORS_RO) && def_errors != PXT4_ERRORS_RO)
		SEQ_OPTS_PUTS("errors=remount-ro");
	if (test_opt(sb, ERRORS_CONT) && def_errors != PXT4_ERRORS_CONTINUE)
		SEQ_OPTS_PUTS("errors=continue");
	if (test_opt(sb, ERRORS_PANIC) && def_errors != PXT4_ERRORS_PANIC)
		SEQ_OPTS_PUTS("errors=panic");
	if (nodefs || sbi->s_commit_interval != JBD3_DEFAULT_MAX_COMMIT_AGE*HZ)
		SEQ_OPTS_PRINT("commit=%lu", sbi->s_commit_interval / HZ);
	if (nodefs || sbi->s_min_batch_time != PXT4_DEF_MIN_BATCH_TIME)
		SEQ_OPTS_PRINT("min_batch_time=%u", sbi->s_min_batch_time);
	if (nodefs || sbi->s_max_batch_time != PXT4_DEF_MAX_BATCH_TIME)
		SEQ_OPTS_PRINT("max_batch_time=%u", sbi->s_max_batch_time);
	if (sb->s_flags & SB_I_VERSION)
		SEQ_OPTS_PUTS("i_version");
	if (nodefs || sbi->s_stripe)
		SEQ_OPTS_PRINT("stripe=%lu", sbi->s_stripe);
	if (nodefs || PXT4_MOUNT_DATA_FLAGS &
			(sbi->s_mount_opt ^ def_mount_opt)) {
		if (test_opt(sb, DATA_FLAGS) == PXT4_MOUNT_JOURNAL_DATA)
			SEQ_OPTS_PUTS("data=journal");
		else if (test_opt(sb, DATA_FLAGS) == PXT4_MOUNT_ORDERED_DATA)
			SEQ_OPTS_PUTS("data=ordered");
		else if (test_opt(sb, DATA_FLAGS) == PXT4_MOUNT_WRITEBACK_DATA)
			SEQ_OPTS_PUTS("data=writeback");
	}
	if (nodefs ||
	    sbi->s_inode_readahead_blks != PXT4_DEF_INODE_READAHEAD_BLKS)
		SEQ_OPTS_PRINT("inode_readahead_blks=%u",
			       sbi->s_inode_readahead_blks);

	if (test_opt(sb, INIT_INODE_TABLE) && (nodefs ||
		       (sbi->s_li_wait_mult != PXT4_DEF_LI_WAIT_MULT)))
		SEQ_OPTS_PRINT("init_itable=%u", sbi->s_li_wait_mult);
	if (nodefs || sbi->s_max_dir_size_kb)
		SEQ_OPTS_PRINT("max_dir_size_kb=%u", sbi->s_max_dir_size_kb);
	if (test_opt(sb, DATA_ERR_ABORT))
		SEQ_OPTS_PUTS("data_err=abort");
	if (DUMMY_ENCRYPTION_ENABLED(sbi))
		SEQ_OPTS_PUTS("test_dummy_encryption");

	pxt4_show_quota_options(seq, sb);
	return 0;
}

static int pxt4_show_options(struct seq_file *seq, struct dentry *root)
{
	return _pxt4_show_options(seq, root->d_sb, 0);
}

int pxt4_seq_options_show(struct seq_file *seq, void *offset)
{
	struct super_block *sb = seq->private;
	int rc;

	seq_puts(seq, sb_rdonly(sb) ? "ro" : "rw");
	rc = _pxt4_show_options(seq, sb, 1);
	seq_puts(seq, "\n");
	return rc;
}

static int pxt4_setup_super(struct super_block *sb, struct pxt4_super_block *es,
			    int read_only)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	int err = 0;

	if (le32_to_cpu(es->s_rev_level) > PXT4_MAX_SUPP_REV) {
		pxt4_msg(sb, KERN_ERR, "revision level too high, "
			 "forcing read-only mode");
		err = -EROFS;
		goto done;
	}
	if (read_only)
		goto done;
	if (!(sbi->s_mount_state & PXT4_VALID_FS))
		pxt4_msg(sb, KERN_WARNING, "warning: mounting unchecked fs, "
			 "running e2fsck is recommended");
	else if (sbi->s_mount_state & PXT4_ERROR_FS)
		pxt4_msg(sb, KERN_WARNING,
			 "warning: mounting fs with errors, "
			 "running e2fsck is recommended");
	else if ((__s16) le16_to_cpu(es->s_max_mnt_count) > 0 &&
		 le16_to_cpu(es->s_mnt_count) >=
		 (unsigned short) (__s16) le16_to_cpu(es->s_max_mnt_count))
		pxt4_msg(sb, KERN_WARNING,
			 "warning: maximal mount count reached, "
			 "running e2fsck is recommended");
	else if (le32_to_cpu(es->s_checkinterval) &&
		 (pxt4_get_tstamp(es, s_lastcheck) +
		  le32_to_cpu(es->s_checkinterval) <= ktime_get_real_seconds()))
		pxt4_msg(sb, KERN_WARNING,
			 "warning: checktime reached, "
			 "running e2fsck is recommended");
	if (!sbi->s_journal)
		es->s_state &= cpu_to_le16(~PXT4_VALID_FS);
	if (!(__s16) le16_to_cpu(es->s_max_mnt_count))
		es->s_max_mnt_count = cpu_to_le16(PXT4_DFL_MAX_MNT_COUNT);
	le16_add_cpu(&es->s_mnt_count, 1);
	pxt4_update_tstamp(es, s_mtime);
	if (sbi->s_journal)
		pxt4_set_feature_journal_needs_recovery(sb);

	err = pxt4_commit_super(sb, 1);
done:
	if (test_opt(sb, DEBUG))
		printk(KERN_INFO "[PXT4 FS bs=%lu, gc=%u, "
				"bpg=%lu, ipg=%lu, mo=%04x, mo2=%04x]\n",
			sb->s_blocksize,
			sbi->s_groups_count,
			PXT4_BLOCKS_PER_GROUP(sb),
			PXT4_INODES_PER_GROUP(sb),
			sbi->s_mount_opt, sbi->s_mount_opt2);

	cleancache_init_fs(sb);
	return err;
}

int pxt4_alloc_flex_bg_array(struct super_block *sb, pxt4_group_t ngroup)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct flex_groups **old_groups, **new_groups;
	int size, i, j;

	if (!sbi->s_log_groups_per_flex)
		return 0;

	size = pxt4_flex_group(sbi, ngroup - 1) + 1;
	if (size <= sbi->s_flex_groups_allocated)
		return 0;

	new_groups = kvzalloc(roundup_pow_of_two(size *
			      sizeof(*sbi->s_flex_groups)), GFP_KERNEL);
	if (!new_groups) {
		pxt4_msg(sb, KERN_ERR,
			 "not enough memory for %d flex group pointers", size);
		return -ENOMEM;
	}
	for (i = sbi->s_flex_groups_allocated; i < size; i++) {
		new_groups[i] = kvzalloc(roundup_pow_of_two(
					 sizeof(struct flex_groups)),
					 GFP_KERNEL);
		if (!new_groups[i]) {
			for (j = sbi->s_flex_groups_allocated; j < i; j++)
				kvfree(new_groups[j]);
			kvfree(new_groups);
			pxt4_msg(sb, KERN_ERR,
				 "not enough memory for %d flex groups", size);
			return -ENOMEM;
		}
	}
	rcu_read_lock();
	old_groups = rcu_dereference(sbi->s_flex_groups);
	if (old_groups)
		memcpy(new_groups, old_groups,
		       (sbi->s_flex_groups_allocated *
			sizeof(struct flex_groups *)));
	rcu_read_unlock();
	rcu_assign_pointer(sbi->s_flex_groups, new_groups);
	sbi->s_flex_groups_allocated = size;
	if (old_groups)
		pxt4_kvfree_array_rcu(old_groups);
	return 0;
}

static int pxt4_fill_flex_info(struct super_block *sb)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_group_desc *gdp = NULL;
	struct flex_groups *fg;
	pxt4_group_t flex_group;
	int i, err;

	sbi->s_log_groups_per_flex = sbi->s_es->s_log_groups_per_flex;
	if (sbi->s_log_groups_per_flex < 1 || sbi->s_log_groups_per_flex > 31) {
		sbi->s_log_groups_per_flex = 0;
		return 1;
	}

	err = pxt4_alloc_flex_bg_array(sb, sbi->s_groups_count);
	if (err)
		goto failed;

	for (i = 0; i < sbi->s_groups_count; i++) {
		gdp = pxt4_get_group_desc(sb, i, NULL);

		flex_group = pxt4_flex_group(sbi, i);
		fg = sbi_array_rcu_deref(sbi, s_flex_groups, flex_group);
		atomic_add(pxt4_free_inodes_count(sb, gdp), &fg->free_inodes);
		atomic64_add(pxt4_free_group_clusters(sb, gdp),
			     &fg->free_clusters);
		atomic_add(pxt4_used_dirs_count(sb, gdp), &fg->used_dirs);
	}

	return 1;
failed:
	return 0;
}

static __le16 pxt4_group_desc_csum(struct super_block *sb, __u32 block_group,
				   struct pxt4_group_desc *gdp)
{
	int offset = offsetof(struct pxt4_group_desc, bg_checksum);
	__u16 crc = 0;
	__le32 le_group = cpu_to_le32(block_group);
	struct pxt4_sb_info *sbi = PXT4_SB(sb);

	if (pxt4_has_metadata_csum(sbi->s_sb)) {
		/* Use new metadata_csum algorithm */
		__u32 csum32;
		__u16 dummy_csum = 0;

		csum32 = pxt4_chksum(sbi, sbi->s_csum_seed, (__u8 *)&le_group,
				     sizeof(le_group));
		csum32 = pxt4_chksum(sbi, csum32, (__u8 *)gdp, offset);
		csum32 = pxt4_chksum(sbi, csum32, (__u8 *)&dummy_csum,
				     sizeof(dummy_csum));
		offset += sizeof(dummy_csum);
		if (offset < sbi->s_desc_size)
			csum32 = pxt4_chksum(sbi, csum32, (__u8 *)gdp + offset,
					     sbi->s_desc_size - offset);

		crc = csum32 & 0xFFFF;
		goto out;
	}

	/* old crc16 code */
	if (!pxt4_has_feature_gdt_csum(sb))
		return 0;

	crc = crc16(~0, sbi->s_es->s_uuid, sizeof(sbi->s_es->s_uuid));
	crc = crc16(crc, (__u8 *)&le_group, sizeof(le_group));
	crc = crc16(crc, (__u8 *)gdp, offset);
	offset += sizeof(gdp->bg_checksum); /* skip checksum */
	/* for checksum of struct pxt4_group_desc do the rest...*/
	if (pxt4_has_feature_64bit(sb) &&
	    offset < le16_to_cpu(sbi->s_es->s_desc_size))
		crc = crc16(crc, (__u8 *)gdp + offset,
			    le16_to_cpu(sbi->s_es->s_desc_size) -
				offset);

out:
	return cpu_to_le16(crc);
}

int pxt4_group_desc_csum_verify(struct super_block *sb, __u32 block_group,
				struct pxt4_group_desc *gdp)
{
	if (pxt4_has_group_desc_csum(sb) &&
	    (gdp->bg_checksum != pxt4_group_desc_csum(sb, block_group, gdp)))
		return 0;

	return 1;
}

void pxt4_group_desc_csum_set(struct super_block *sb, __u32 block_group,
			      struct pxt4_group_desc *gdp)
{
	if (!pxt4_has_group_desc_csum(sb))
		return;
	gdp->bg_checksum = pxt4_group_desc_csum(sb, block_group, gdp);
}

/* Called at mount-time, super-block is locked */
static int pxt4_check_descriptors(struct super_block *sb,
				  pxt4_fsblk_t sb_block,
				  pxt4_group_t *first_not_zeroed)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	pxt4_fsblk_t first_block = le32_to_cpu(sbi->s_es->s_first_data_block);
	pxt4_fsblk_t last_block;
	pxt4_fsblk_t last_bg_block = sb_block + pxt4_bg_num_gdb(sb, 0);
	pxt4_fsblk_t block_bitmap;
	pxt4_fsblk_t inode_bitmap;
	pxt4_fsblk_t inode_table;
	int flexbg_flag = 0;
	pxt4_group_t i, grp = sbi->s_groups_count;

	if (pxt4_has_feature_flex_bg(sb))
		flexbg_flag = 1;

	pxt4_debug("Checking group descriptors");

	for (i = 0; i < sbi->s_groups_count; i++) {
		struct pxt4_group_desc *gdp = pxt4_get_group_desc(sb, i, NULL);

		if (i == sbi->s_groups_count - 1 || flexbg_flag)
			last_block = pxt4_blocks_count(sbi->s_es) - 1;
		else
			last_block = first_block +
				(PXT4_BLOCKS_PER_GROUP(sb) - 1);

		if ((grp == sbi->s_groups_count) &&
		   !(gdp->bg_flags & cpu_to_le16(PXT4_BG_INODE_ZEROED)))
			grp = i;

		block_bitmap = pxt4_block_bitmap(sb, gdp);
		if (block_bitmap == sb_block) {
			pxt4_msg(sb, KERN_ERR, "pxt4_check_descriptors: "
				 "Block bitmap for group %u overlaps "
				 "superblock", i);
			if (!sb_rdonly(sb))
				return 0;
		}
		if (block_bitmap >= sb_block + 1 &&
		    block_bitmap <= last_bg_block) {
			pxt4_msg(sb, KERN_ERR, "pxt4_check_descriptors: "
				 "Block bitmap for group %u overlaps "
				 "block group descriptors", i);
			if (!sb_rdonly(sb))
				return 0;
		}
		if (block_bitmap < first_block || block_bitmap > last_block) {
			pxt4_msg(sb, KERN_ERR, "pxt4_check_descriptors: "
			       "Block bitmap for group %u not in group "
			       "(block %llu)!", i, block_bitmap);
			return 0;
		}
		inode_bitmap = pxt4_inode_bitmap(sb, gdp);
		if (inode_bitmap == sb_block) {
			pxt4_msg(sb, KERN_ERR, "pxt4_check_descriptors: "
				 "Inode bitmap for group %u overlaps "
				 "superblock", i);
			if (!sb_rdonly(sb))
				return 0;
		}
		if (inode_bitmap >= sb_block + 1 &&
		    inode_bitmap <= last_bg_block) {
			pxt4_msg(sb, KERN_ERR, "pxt4_check_descriptors: "
				 "Inode bitmap for group %u overlaps "
				 "block group descriptors", i);
			if (!sb_rdonly(sb))
				return 0;
		}
		if (inode_bitmap < first_block || inode_bitmap > last_block) {
			pxt4_msg(sb, KERN_ERR, "pxt4_check_descriptors: "
			       "Inode bitmap for group %u not in group "
			       "(block %llu)!", i, inode_bitmap);
			return 0;
		}
		inode_table = pxt4_inode_table(sb, gdp);
		if (inode_table == sb_block) {
			pxt4_msg(sb, KERN_ERR, "pxt4_check_descriptors: "
				 "Inode table for group %u overlaps "
				 "superblock", i);
			if (!sb_rdonly(sb))
				return 0;
		}
		if (inode_table >= sb_block + 1 &&
		    inode_table <= last_bg_block) {
			pxt4_msg(sb, KERN_ERR, "pxt4_check_descriptors: "
				 "Inode table for group %u overlaps "
				 "block group descriptors", i);
			if (!sb_rdonly(sb))
				return 0;
		}
		if (inode_table < first_block ||
		    inode_table + sbi->s_itb_per_group - 1 > last_block) {
			pxt4_msg(sb, KERN_ERR, "pxt4_check_descriptors: "
			       "Inode table for group %u not in group "
			       "(block %llu)!", i, inode_table);
			return 0;
		}
		pxt4_lock_group(sb, i);
		if (!pxt4_group_desc_csum_verify(sb, i, gdp)) {
			pxt4_msg(sb, KERN_ERR, "pxt4_check_descriptors: "
				 "Checksum for group %u failed (%u!=%u)",
				 i, le16_to_cpu(pxt4_group_desc_csum(sb, i,
				     gdp)), le16_to_cpu(gdp->bg_checksum));
			if (!sb_rdonly(sb)) {
				pxt4_unlock_group(sb, i);
				return 0;
			}
		}
		pxt4_unlock_group(sb, i);
		if (!flexbg_flag)
			first_block += PXT4_BLOCKS_PER_GROUP(sb);
	}
	if (NULL != first_not_zeroed)
		*first_not_zeroed = grp;
	return 1;
}

/* pxt4_orphan_cleanup() walks a singly-linked list of inodes (starting at
 * the superblock) which were deleted from all directories, but held open by
 * a process at the time of a crash.  We walk the list and try to delete these
 * inodes at recovery time (only with a read-write filesystem).
 *
 * In order to keep the orphan inode chain consistent during traversal (in
 * case of crash during recovery), we link each inode into the superblock
 * orphan list_head and handle it the same way as an inode deletion during
 * normal operation (which journals the operations for us).
 *
 * We only do an iget() and an iput() on each inode, which is very safe if we
 * accidentally point at an in-use or already deleted inode.  The worst that
 * can happen in this case is that we get a "bit already cleared" message from
 * pxt4_free_inode().  The only reason we would point at a wrong inode is if
 * e2fsck was run on this filesystem, and it must have already done the orphan
 * inode cleanup for us, so we can safely abort without any further action.
 */
static void pxt4_orphan_cleanup(struct super_block *sb,
				struct pxt4_super_block *es)
{
	unsigned int s_flags = sb->s_flags;
	int ret, nr_orphans = 0, nr_truncates = 0;
#ifdef CONFIG_QUOTA
	int quota_update = 0;
	int i;
#endif
	if (!es->s_last_orphan) {
		jbd_debug(4, "no orphan inodes to clean up\n");
		return;
	}

	if (bdev_read_only(sb->s_bdev)) {
		pxt4_msg(sb, KERN_ERR, "write access "
			"unavailable, skipping orphan cleanup");
		return;
	}

	/* Check if feature set would not allow a r/w mount */
	if (!pxt4_feature_set_ok(sb, 0)) {
		pxt4_msg(sb, KERN_INFO, "Skipping orphan cleanup due to "
			 "unknown ROCOMPAT features");
		return;
	}

	if (PXT4_SB(sb)->s_mount_state & PXT4_ERROR_FS) {
		/* don't clear list on RO mount w/ errors */
		if (es->s_last_orphan && !(s_flags & SB_RDONLY)) {
			pxt4_msg(sb, KERN_INFO, "Errors on filesystem, "
				  "clearing orphan list.\n");
			es->s_last_orphan = 0;
		}
		jbd_debug(1, "Skipping orphan recovery on fs with errors.\n");
		return;
	}

	if (s_flags & SB_RDONLY) {
		pxt4_msg(sb, KERN_INFO, "orphan cleanup on readonly fs");
		sb->s_flags &= ~SB_RDONLY;
	}
#ifdef CONFIG_QUOTA
	/* Needed for iput() to work correctly and not trash data */
	sb->s_flags |= SB_ACTIVE;

	/*
	 * Turn on quotas which were not enabled for read-only mounts if
	 * filesystem has quota feature, so that they are updated correctly.
	 */
	if (pxt4_has_feature_quota(sb) && (s_flags & SB_RDONLY)) {
		int ret = pxt4_enable_quotas(sb);

		if (!ret)
			quota_update = 1;
		else
			pxt4_msg(sb, KERN_ERR,
				"Cannot turn on quotas: error %d", ret);
	}

	/* Turn on journaled quotas used for old sytle */
	for (i = 0; i < PXT4_MAXQUOTAS; i++) {
		if (PXT4_SB(sb)->s_qf_names[i]) {
			int ret = pxt4_quota_on_mount(sb, i);

			if (!ret)
				quota_update = 1;
			else
				pxt4_msg(sb, KERN_ERR,
					"Cannot turn on journaled "
					"quota: type %d: error %d", i, ret);
		}
	}
#endif

	while (es->s_last_orphan) {
		struct inode *inode;

		/*
		 * We may have encountered an error during cleanup; if
		 * so, skip the rest.
		 */
		if (PXT4_SB(sb)->s_mount_state & PXT4_ERROR_FS) {
			jbd_debug(1, "Skipping orphan recovery on fs with errors.\n");
			es->s_last_orphan = 0;
			break;
		}

		inode = pxt4_orphan_get(sb, le32_to_cpu(es->s_last_orphan));
		if (IS_ERR(inode)) {
			es->s_last_orphan = 0;
			break;
		}

		list_add(&PXT4_I(inode)->i_orphan, &PXT4_SB(sb)->s_orphan);
		dquot_initialize(inode);
		if (inode->i_nlink) {
			if (test_opt(sb, DEBUG))
				pxt4_msg(sb, KERN_DEBUG,
					"%s: truncating inode %lu to %lld bytes",
					__func__, inode->i_ino, inode->i_size);
			jbd_debug(2, "truncating inode %lu to %lld bytes\n",
				  inode->i_ino, inode->i_size);
			inode_lock(inode);
			truncate_inode_pages(inode->i_mapping, inode->i_size);
			ret = pxt4_truncate(inode);
			if (ret)
				pxt4_std_error(inode->i_sb, ret);
			inode_unlock(inode);
			nr_truncates++;
		} else {
			if (test_opt(sb, DEBUG))
				pxt4_msg(sb, KERN_DEBUG,
					"%s: deleting unreferenced inode %lu",
					__func__, inode->i_ino);
			jbd_debug(2, "deleting unreferenced inode %lu\n",
				  inode->i_ino);
			nr_orphans++;
		}
		iput(inode);  /* The delete magic happens here! */
	}

#define PLURAL(x) (x), ((x) == 1) ? "" : "s"

	if (nr_orphans)
		pxt4_msg(sb, KERN_INFO, "%d orphan inode%s deleted",
		       PLURAL(nr_orphans));
	if (nr_truncates)
		pxt4_msg(sb, KERN_INFO, "%d truncate%s cleaned up",
		       PLURAL(nr_truncates));
#ifdef CONFIG_QUOTA
	/* Turn off quotas if they were enabled for orphan cleanup */
	if (quota_update) {
		for (i = 0; i < PXT4_MAXQUOTAS; i++) {
			if (sb_dqopt(sb)->files[i])
				dquot_quota_off(sb, i);
		}
	}
#endif
	sb->s_flags = s_flags; /* Restore SB_RDONLY status */
}

/*
 * Maximal extent format file size.
 * Resulting logical blkno at s_maxbytes must fit in our on-disk
 * extent format containers, within a sector_t, and within i_blocks
 * in the vfs.  pxt4 inode has 48 bits of i_block in fsblock units,
 * so that won't be a limiting factor.
 *
 * However there is other limiting factor. We do store extents in the form
 * of starting block and length, hence the resulting length of the extent
 * covering maximum file size must fit into on-disk format containers as
 * well. Given that length is always by 1 unit bigger than max unit (because
 * we count 0 as well) we have to lower the s_maxbytes by one fs block.
 *
 * Note, this does *not* consider any metadata overhead for vfs i_blocks.
 */
static loff_t pxt4_max_size(int blkbits, int has_huge_files)
{
	loff_t res;
	loff_t upper_limit = MAX_LFS_FILESIZE;

	BUILD_BUG_ON(sizeof(blkcnt_t) < sizeof(u64));

	if (!has_huge_files) {
		upper_limit = (1LL << 32) - 1;

		/* total blocks in file system block size */
		upper_limit >>= (blkbits - 9);
		upper_limit <<= blkbits;
	}

	/*
	 * 32-bit extent-start container, ee_block. We lower the maxbytes
	 * by one fs block, so ee_len can cover the extent of maximum file
	 * size
	 */
	res = (1LL << 32) - 1;
	res <<= blkbits;

	/* Sanity check against vm- & vfs- imposed limits */
	if (res > upper_limit)
		res = upper_limit;

	return res;
}

/*
 * Maximal bitmap file size.  There is a direct, and {,double-,triple-}indirect
 * block limit, and also a limit of (2^48 - 1) 512-byte sectors in i_blocks.
 * We need to be 1 filesystem block less than the 2^48 sector limit.
 */
static loff_t pxt4_max_bitmap_size(int bits, int has_huge_files)
{
	loff_t res = PXT4_NDIR_BLOCKS;
	int meta_blocks;
	loff_t upper_limit;
	/* This is calculated to be the largest file size for a dense, block
	 * mapped file such that the file's total number of 512-byte sectors,
	 * including data and all indirect blocks, does not exceed (2^48 - 1).
	 *
	 * __u32 i_blocks_lo and _u16 i_blocks_high represent the total
	 * number of 512-byte sectors of the file.
	 */

	if (!has_huge_files) {
		/*
		 * !has_huge_files or implies that the inode i_block field
		 * represents total file blocks in 2^32 512-byte sectors ==
		 * size of vfs inode i_blocks * 8
		 */
		upper_limit = (1LL << 32) - 1;

		/* total blocks in file system block size */
		upper_limit >>= (bits - 9);

	} else {
		/*
		 * We use 48 bit pxt4_inode i_blocks
		 * With PXT4_HUGE_FILE_FL set the i_blocks
		 * represent total number of blocks in
		 * file system block size
		 */
		upper_limit = (1LL << 48) - 1;

	}

	/* indirect blocks */
	meta_blocks = 1;
	/* double indirect blocks */
	meta_blocks += 1 + (1LL << (bits-2));
	/* tripple indirect blocks */
	meta_blocks += 1 + (1LL << (bits-2)) + (1LL << (2*(bits-2)));

	upper_limit -= meta_blocks;
	upper_limit <<= bits;

	res += 1LL << (bits-2);
	res += 1LL << (2*(bits-2));
	res += 1LL << (3*(bits-2));
	res <<= bits;
	if (res > upper_limit)
		res = upper_limit;

	if (res > MAX_LFS_FILESIZE)
		res = MAX_LFS_FILESIZE;

	return res;
}

static pxt4_fsblk_t descriptor_loc(struct super_block *sb,
				   pxt4_fsblk_t logical_sb_block, int nr)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	pxt4_group_t bg, first_meta_bg;
	int has_super = 0;

	first_meta_bg = le32_to_cpu(sbi->s_es->s_first_meta_bg);

	if (!pxt4_has_feature_meta_bg(sb) || nr < first_meta_bg)
		return logical_sb_block + nr + 1;
	bg = sbi->s_desc_per_block * nr;
	if (pxt4_bg_has_super(sb, bg))
		has_super = 1;

	/*
	 * If we have a meta_bg fs with 1k blocks, group 0's GDT is at
	 * block 2, not 1.  If s_first_data_block == 0 (bigalloc is enabled
	 * on modern mke2fs or blksize > 1k on older mke2fs) then we must
	 * compensate.
	 */
	if (sb->s_blocksize == 1024 && nr == 0 &&
	    le32_to_cpu(sbi->s_es->s_first_data_block) == 0)
		has_super++;

	return (has_super + pxt4_group_first_block_no(sb, bg));
}

/**
 * pxt4_get_stripe_size: Get the stripe size.
 * @sbi: In memory super block info
 *
 * If we have specified it via mount option, then
 * use the mount option value. If the value specified at mount time is
 * greater than the blocks per group use the super block value.
 * If the super block value is greater than blocks per group return 0.
 * Allocator needs it be less than blocks per group.
 *
 */
static unsigned long pxt4_get_stripe_size(struct pxt4_sb_info *sbi)
{
	unsigned long stride = le16_to_cpu(sbi->s_es->s_raid_stride);
	unsigned long stripe_width =
			le32_to_cpu(sbi->s_es->s_raid_stripe_width);
	int ret;

	if (sbi->s_stripe && sbi->s_stripe <= sbi->s_blocks_per_group)
		ret = sbi->s_stripe;
	else if (stripe_width && stripe_width <= sbi->s_blocks_per_group)
		ret = stripe_width;
	else if (stride && stride <= sbi->s_blocks_per_group)
		ret = stride;
	else
		ret = 0;

	/*
	 * If the stripe width is 1, this makes no sense and
	 * we set it to 0 to turn off stripe handling code.
	 */
	if (ret <= 1)
		ret = 0;

	return ret;
}

/*
 * Check whether this filesystem can be mounted based on
 * the features present and the RDONLY/RDWR mount requested.
 * Returns 1 if this filesystem can be mounted as requested,
 * 0 if it cannot be.
 */
static int pxt4_feature_set_ok(struct super_block *sb, int readonly)
{
	if (pxt4_has_unknown_ext4_incompat_features(sb)) {
		pxt4_msg(sb, KERN_ERR,
			"Couldn't mount because of "
			"unsupported optional features (%x)",
			(le32_to_cpu(PXT4_SB(sb)->s_es->s_feature_incompat) &
			~PXT4_FEATURE_INCOMPAT_SUPP));
		return 0;
	}

#ifndef CONFIG_UNICODE
	if (pxt4_has_feature_casefold(sb)) {
		pxt4_msg(sb, KERN_ERR,
			 "Filesystem with casefold feature cannot be "
			 "mounted without CONFIG_UNICODE");
		return 0;
	}
#endif

	if (readonly)
		return 1;

	if (pxt4_has_feature_readonly(sb)) {
		pxt4_msg(sb, KERN_INFO, "filesystem is read-only");
		sb->s_flags |= SB_RDONLY;
		return 1;
	}

	/* Check that feature set is OK for a read-write mount */
	if (pxt4_has_unknown_ext4_ro_compat_features(sb)) {
		pxt4_msg(sb, KERN_ERR, "couldn't mount RDWR because of "
			 "unsupported optional features (%x)",
			 (le32_to_cpu(PXT4_SB(sb)->s_es->s_feature_ro_compat) &
				~PXT4_FEATURE_RO_COMPAT_SUPP));
		return 0;
	}
	if (pxt4_has_feature_bigalloc(sb) && !pxt4_has_feature_extents(sb)) {
		pxt4_msg(sb, KERN_ERR,
			 "Can't support bigalloc feature without "
			 "extents feature\n");
		return 0;
	}

#if !IS_ENABLED(CONFIG_QUOTA) || !IS_ENABLED(CONFIG_QFMT_V2)
	if (!readonly && (pxt4_has_feature_quota(sb) ||
			  pxt4_has_feature_project(sb))) {
		pxt4_msg(sb, KERN_ERR,
			 "The kernel was not built with CONFIG_QUOTA and CONFIG_QFMT_V2");
		return 0;
	}
#endif  /* CONFIG_QUOTA */
	return 1;
}

/*
 * This function is called once a day if we have errors logged
 * on the file system
 */
static void print_daily_error_info(struct timer_list *t)
{
	struct pxt4_sb_info *sbi = from_timer(sbi, t, s_err_report);
	struct super_block *sb = sbi->s_sb;
	struct pxt4_super_block *es = sbi->s_es;

	if (es->s_error_count)
		/* fsck newer than v1.41.13 is needed to clean this condition. */
		pxt4_msg(sb, KERN_NOTICE, "error count since last fsck: %u",
			 le32_to_cpu(es->s_error_count));
	if (es->s_first_error_time) {
		printk(KERN_NOTICE "PXT4-fs (%s): initial error at time %llu: %.*s:%d",
		       sb->s_id,
		       pxt4_get_tstamp(es, s_first_error_time),
		       (int) sizeof(es->s_first_error_func),
		       es->s_first_error_func,
		       le32_to_cpu(es->s_first_error_line));
		if (es->s_first_error_ino)
			printk(KERN_CONT ": inode %u",
			       le32_to_cpu(es->s_first_error_ino));
		if (es->s_first_error_block)
			printk(KERN_CONT ": block %llu", (unsigned long long)
			       le64_to_cpu(es->s_first_error_block));
		printk(KERN_CONT "\n");
	}
	if (es->s_last_error_time) {
		printk(KERN_NOTICE "PXT4-fs (%s): last error at time %llu: %.*s:%d",
		       sb->s_id,
		       pxt4_get_tstamp(es, s_last_error_time),
		       (int) sizeof(es->s_last_error_func),
		       es->s_last_error_func,
		       le32_to_cpu(es->s_last_error_line));
		if (es->s_last_error_ino)
			printk(KERN_CONT ": inode %u",
			       le32_to_cpu(es->s_last_error_ino));
		if (es->s_last_error_block)
			printk(KERN_CONT ": block %llu", (unsigned long long)
			       le64_to_cpu(es->s_last_error_block));
		printk(KERN_CONT "\n");
	}
	mod_timer(&sbi->s_err_report, jiffies + 24*60*60*HZ);  /* Once a day */
}

/* Find next suitable group and run pxt4_init_inode_table */
static int pxt4_run_li_request(struct pxt4_li_request *elr)
{
	struct pxt4_group_desc *gdp = NULL;
	pxt4_group_t group, ngroups;
	struct super_block *sb;
	unsigned long timeout = 0;
	int ret = 0;

	sb = elr->lr_super;
	ngroups = PXT4_SB(sb)->s_groups_count;

	for (group = elr->lr_next_group; group < ngroups; group++) {
		gdp = pxt4_get_group_desc(sb, group, NULL);
		if (!gdp) {
			ret = 1;
			break;
		}

		if (!(gdp->bg_flags & cpu_to_le16(PXT4_BG_INODE_ZEROED)))
			break;
	}

	if (group >= ngroups)
		ret = 1;

	if (!ret) {
		timeout = jiffies;
		ret = pxt4_init_inode_table(sb, group,
					    elr->lr_timeout ? 0 : 1);
		if (elr->lr_timeout == 0) {
			timeout = (jiffies - timeout) *
				  elr->lr_sbi->s_li_wait_mult;
			elr->lr_timeout = timeout;
		}
		elr->lr_next_sched = jiffies + elr->lr_timeout;
		elr->lr_next_group = group + 1;
	}
	return ret;
}

/*
 * Remove lr_request from the list_request and free the
 * request structure. Should be called with li_list_mtx held
 */
static void pxt4_remove_li_request(struct pxt4_li_request *elr)
{
	struct pxt4_sb_info *sbi;

	if (!elr)
		return;

	sbi = elr->lr_sbi;

	list_del(&elr->lr_request);
	sbi->s_li_request = NULL;
	kfree(elr);
}

static void pxt4_unregister_li_request(struct super_block *sb)
{
	mutex_lock(&pxt4_li_mtx);
	if (!pxt4_li_info) {
		mutex_unlock(&pxt4_li_mtx);
		return;
	}

	mutex_lock(&pxt4_li_info->li_list_mtx);
	pxt4_remove_li_request(PXT4_SB(sb)->s_li_request);
	mutex_unlock(&pxt4_li_info->li_list_mtx);
	mutex_unlock(&pxt4_li_mtx);
}

static struct task_struct *pxt4_lazyinit_task;

/*
 * This is the function where pxt4lazyinit thread lives. It walks
 * through the request list searching for next scheduled filesystem.
 * When such a fs is found, run the lazy initialization request
 * (pxt4_rn_li_request) and keep track of the time spend in this
 * function. Based on that time we compute next schedule time of
 * the request. When walking through the list is complete, compute
 * next waking time and put itself into sleep.
 */
static int pxt4_lazyinit_thread(void *arg)
{
	struct pxt4_lazy_init *eli = (struct pxt4_lazy_init *)arg;
	struct list_head *pos, *n;
	struct pxt4_li_request *elr;
	unsigned long next_wakeup, cur;

	BUG_ON(NULL == eli);

cont_thread:
	while (true) {
		next_wakeup = MAX_JIFFY_OFFSET;

		mutex_lock(&eli->li_list_mtx);
		if (list_empty(&eli->li_request_list)) {
			mutex_unlock(&eli->li_list_mtx);
			goto exit_thread;
		}
		list_for_each_safe(pos, n, &eli->li_request_list) {
			int err = 0;
			int progress = 0;
			elr = list_entry(pos, struct pxt4_li_request,
					 lr_request);

			if (time_before(jiffies, elr->lr_next_sched)) {
				if (time_before(elr->lr_next_sched, next_wakeup))
					next_wakeup = elr->lr_next_sched;
				continue;
			}
			if (down_read_trylock(&elr->lr_super->s_umount)) {
				if (sb_start_write_trylock(elr->lr_super)) {
					progress = 1;
					/*
					 * We hold sb->s_umount, sb can not
					 * be removed from the list, it is
					 * now safe to drop li_list_mtx
					 */
					mutex_unlock(&eli->li_list_mtx);
					err = pxt4_run_li_request(elr);
					sb_end_write(elr->lr_super);
					mutex_lock(&eli->li_list_mtx);
					n = pos->next;
				}
				up_read((&elr->lr_super->s_umount));
			}
			/* error, remove the lazy_init job */
			if (err) {
				pxt4_remove_li_request(elr);
				continue;
			}
			if (!progress) {
				elr->lr_next_sched = jiffies +
					(prandom_u32()
					 % (PXT4_DEF_LI_MAX_START_DELAY * HZ));
			}
			if (time_before(elr->lr_next_sched, next_wakeup))
				next_wakeup = elr->lr_next_sched;
		}
		mutex_unlock(&eli->li_list_mtx);

		try_to_freeze();

		cur = jiffies;
		if ((time_after_eq(cur, next_wakeup)) ||
		    (MAX_JIFFY_OFFSET == next_wakeup)) {
			cond_resched();
			continue;
		}

		schedule_timeout_interruptible(next_wakeup - cur);

		if (kthread_should_stop()) {
			pxt4_clear_request_list();
			goto exit_thread;
		}
	}

exit_thread:
	/*
	 * It looks like the request list is empty, but we need
	 * to check it under the li_list_mtx lock, to prevent any
	 * additions into it, and of course we should lock pxt4_li_mtx
	 * to atomically free the list and pxt4_li_info, because at
	 * this point another pxt4 filesystem could be registering
	 * new one.
	 */
	mutex_lock(&pxt4_li_mtx);
	mutex_lock(&eli->li_list_mtx);
	if (!list_empty(&eli->li_request_list)) {
		mutex_unlock(&eli->li_list_mtx);
		mutex_unlock(&pxt4_li_mtx);
		goto cont_thread;
	}
	mutex_unlock(&eli->li_list_mtx);
	kfree(pxt4_li_info);
	pxt4_li_info = NULL;
	mutex_unlock(&pxt4_li_mtx);

	return 0;
}

static void pxt4_clear_request_list(void)
{
	struct list_head *pos, *n;
	struct pxt4_li_request *elr;

	mutex_lock(&pxt4_li_info->li_list_mtx);
	list_for_each_safe(pos, n, &pxt4_li_info->li_request_list) {
		elr = list_entry(pos, struct pxt4_li_request,
				 lr_request);
		pxt4_remove_li_request(elr);
	}
	mutex_unlock(&pxt4_li_info->li_list_mtx);
}

static int pxt4_run_lazyinit_thread(void)
{
	pxt4_lazyinit_task = kthread_run(pxt4_lazyinit_thread,
					 pxt4_li_info, "pxt4lazyinit");
	if (IS_ERR(pxt4_lazyinit_task)) {
		int err = PTR_ERR(pxt4_lazyinit_task);
		pxt4_clear_request_list();
		kfree(pxt4_li_info);
		pxt4_li_info = NULL;
		printk(KERN_CRIT "PXT4-fs: error %d creating inode table "
				 "initialization thread\n",
				 err);
		return err;
	}
	pxt4_li_info->li_state |= PXT4_LAZYINIT_RUNNING;
	return 0;
}

/*
 * Check whether it make sense to run itable init. thread or not.
 * If there is at least one uninitialized inode table, return
 * corresponding group number, else the loop goes through all
 * groups and return total number of groups.
 */
static pxt4_group_t pxt4_has_uninit_itable(struct super_block *sb)
{
	pxt4_group_t group, ngroups = PXT4_SB(sb)->s_groups_count;
	struct pxt4_group_desc *gdp = NULL;

	if (!pxt4_has_group_desc_csum(sb))
		return ngroups;

	for (group = 0; group < ngroups; group++) {
		gdp = pxt4_get_group_desc(sb, group, NULL);
		if (!gdp)
			continue;

		if (!(gdp->bg_flags & cpu_to_le16(PXT4_BG_INODE_ZEROED)))
			break;
	}

	return group;
}

static int pxt4_li_info_new(void)
{
	struct pxt4_lazy_init *eli = NULL;

	eli = kzalloc(sizeof(*eli), GFP_KERNEL);
	if (!eli)
		return -ENOMEM;

	INIT_LIST_HEAD(&eli->li_request_list);
	mutex_init(&eli->li_list_mtx);

	eli->li_state |= PXT4_LAZYINIT_QUIT;

	pxt4_li_info = eli;

	return 0;
}

static struct pxt4_li_request *pxt4_li_request_new(struct super_block *sb,
					    pxt4_group_t start)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_li_request *elr;

	elr = kzalloc(sizeof(*elr), GFP_KERNEL);
	if (!elr)
		return NULL;

	elr->lr_super = sb;
	elr->lr_sbi = sbi;
	elr->lr_next_group = start;

	/*
	 * Randomize first schedule time of the request to
	 * spread the inode table initialization requests
	 * better.
	 */
	elr->lr_next_sched = jiffies + (prandom_u32() %
				(PXT4_DEF_LI_MAX_START_DELAY * HZ));
	return elr;
}

int pxt4_register_li_request(struct super_block *sb,
			     pxt4_group_t first_not_zeroed)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_li_request *elr = NULL;
	pxt4_group_t ngroups = sbi->s_groups_count;
	int ret = 0;

	mutex_lock(&pxt4_li_mtx);
	if (sbi->s_li_request != NULL) {
		/*
		 * Reset timeout so it can be computed again, because
		 * s_li_wait_mult might have changed.
		 */
		sbi->s_li_request->lr_timeout = 0;
		goto out;
	}

	if (first_not_zeroed == ngroups || sb_rdonly(sb) ||
	    !test_opt(sb, INIT_INODE_TABLE))
		goto out;

	elr = pxt4_li_request_new(sb, first_not_zeroed);
	if (!elr) {
		ret = -ENOMEM;
		goto out;
	}

	if (NULL == pxt4_li_info) {
		ret = pxt4_li_info_new();
		if (ret)
			goto out;
	}

	mutex_lock(&pxt4_li_info->li_list_mtx);
	list_add(&elr->lr_request, &pxt4_li_info->li_request_list);
	mutex_unlock(&pxt4_li_info->li_list_mtx);

	sbi->s_li_request = elr;
	/*
	 * set elr to NULL here since it has been inserted to
	 * the request_list and the removal and free of it is
	 * handled by pxt4_clear_request_list from now on.
	 */
	elr = NULL;

	if (!(pxt4_li_info->li_state & PXT4_LAZYINIT_RUNNING)) {
		ret = pxt4_run_lazyinit_thread();
		if (ret)
			goto out;
	}
out:
	mutex_unlock(&pxt4_li_mtx);
	if (ret)
		kfree(elr);
	return ret;
}

/*
 * We do not need to lock anything since this is called on
 * module unload.
 */
static void pxt4_destroy_lazyinit_thread(void)
{
	/*
	 * If thread exited earlier
	 * there's nothing to be done.
	 */
	if (!pxt4_li_info || !pxt4_lazyinit_task)
		return;

	kthread_stop(pxt4_lazyinit_task);
}

static int set_journal_csum_feature_set(struct super_block *sb)
{
	int ret = 1;
	int compat, incompat;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);

	if (pxt4_has_metadata_csum(sb)) {
		/* journal checksum v3 */
		compat = 0;
		incompat = JBD3_FEATURE_INCOMPAT_CSUM_V3;
	} else {
		/* journal checksum v1 */
		compat = JBD3_FEATURE_COMPAT_CHECKSUM;
		incompat = 0;
	}

	jbd3_journal_clear_features(sbi->s_journal,
			JBD3_FEATURE_COMPAT_CHECKSUM, 0,
			JBD3_FEATURE_INCOMPAT_CSUM_V3 |
			JBD3_FEATURE_INCOMPAT_CSUM_V2);
	if (test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
		ret = jbd3_journal_set_features(sbi->s_journal,
				compat, 0,
				JBD3_FEATURE_INCOMPAT_ASYNC_COMMIT |
				incompat);
	} else if (test_opt(sb, JOURNAL_CHECKSUM)) {
		ret = jbd3_journal_set_features(sbi->s_journal,
				compat, 0,
				incompat);
		jbd3_journal_clear_features(sbi->s_journal, 0, 0,
				JBD3_FEATURE_INCOMPAT_ASYNC_COMMIT);
	} else {
		jbd3_journal_clear_features(sbi->s_journal, 0, 0,
				JBD3_FEATURE_INCOMPAT_ASYNC_COMMIT);
	}

	return ret;
}

/*
 * Note: calculating the overhead so we can be compatible with
 * historical BSD practice is quite difficult in the face of
 * clusters/bigalloc.  This is because multiple metadata blocks from
 * different block group can end up in the same allocation cluster.
 * Calculating the exact overhead in the face of clustered allocation
 * requires either O(all block bitmaps) in memory or O(number of block
 * groups**2) in time.  We will still calculate the superblock for
 * older file systems --- and if we come across with a bigalloc file
 * system with zero in s_overhead_clusters the estimate will be close to
 * correct especially for very large cluster sizes --- but for newer
 * file systems, it's better to calculate this figure once at mkfs
 * time, and store it in the superblock.  If the superblock value is
 * present (even for non-bigalloc file systems), we will use it.
 */
static int count_overhead(struct super_block *sb, pxt4_group_t grp,
			  char *buf)
{
	struct pxt4_sb_info	*sbi = PXT4_SB(sb);
	struct pxt4_group_desc	*gdp;
	pxt4_fsblk_t		first_block, last_block, b;
	pxt4_group_t		i, ngroups = pxt4_get_groups_count(sb);
	int			s, j, count = 0;

	if (!pxt4_has_feature_bigalloc(sb))
		return (pxt4_bg_has_super(sb, grp) + pxt4_bg_num_gdb(sb, grp) +
			sbi->s_itb_per_group + 2);

	first_block = le32_to_cpu(sbi->s_es->s_first_data_block) +
		(grp * PXT4_BLOCKS_PER_GROUP(sb));
	last_block = first_block + PXT4_BLOCKS_PER_GROUP(sb) - 1;
	for (i = 0; i < ngroups; i++) {
		gdp = pxt4_get_group_desc(sb, i, NULL);
		b = pxt4_block_bitmap(sb, gdp);
		if (b >= first_block && b <= last_block) {
			pxt4_set_bit(PXT4_B2C(sbi, b - first_block), buf);
			count++;
		}
		b = pxt4_inode_bitmap(sb, gdp);
		if (b >= first_block && b <= last_block) {
			pxt4_set_bit(PXT4_B2C(sbi, b - first_block), buf);
			count++;
		}
		b = pxt4_inode_table(sb, gdp);
		if (b >= first_block && b + sbi->s_itb_per_group <= last_block)
			for (j = 0; j < sbi->s_itb_per_group; j++, b++) {
				int c = PXT4_B2C(sbi, b - first_block);
				pxt4_set_bit(c, buf);
				count++;
			}
		if (i != grp)
			continue;
		s = 0;
		if (pxt4_bg_has_super(sb, grp)) {
			pxt4_set_bit(s++, buf);
			count++;
		}
		j = pxt4_bg_num_gdb(sb, grp);
		if (s + j > PXT4_BLOCKS_PER_GROUP(sb)) {
			pxt4_error(sb, "Invalid number of block group "
				   "descriptor blocks: %d", j);
			j = PXT4_BLOCKS_PER_GROUP(sb) - s;
		}
		count += j;
		for (; j > 0; j--)
			pxt4_set_bit(PXT4_B2C(sbi, s++), buf);
	}
	if (!count)
		return 0;
	return PXT4_CLUSTERS_PER_GROUP(sb) -
		pxt4_count_free(buf, PXT4_CLUSTERS_PER_GROUP(sb) / 8);
}

/*
 * Compute the overhead and stash it in sbi->s_overhead
 */
int pxt4_calculate_overhead(struct super_block *sb)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_super_block *es = sbi->s_es;
	struct inode *j_inode;
	unsigned int j_blocks, j_inum = le32_to_cpu(es->s_journal_inum);
	pxt4_group_t i, ngroups = pxt4_get_groups_count(sb);
	pxt4_fsblk_t overhead = 0;
	char *buf = (char *) get_zeroed_page(GFP_NOFS);

	if (!buf)
		return -ENOMEM;

	/*
	 * Compute the overhead (FS structures).  This is constant
	 * for a given filesystem unless the number of block groups
	 * changes so we cache the previous value until it does.
	 */

	/*
	 * All of the blocks before first_data_block are overhead
	 */
	overhead = PXT4_B2C(sbi, le32_to_cpu(es->s_first_data_block));

	/*
	 * Add the overhead found in each block group
	 */
	for (i = 0; i < ngroups; i++) {
		int blks;

		blks = count_overhead(sb, i, buf);
		overhead += blks;
		if (blks)
			memset(buf, 0, PAGE_SIZE);
		cond_resched();
	}

	/*
	 * Add the internal journal blocks whether the journal has been
	 * loaded or not
	 */
	if (sbi->s_journal && !sbi->journal_bdev)
		overhead += PXT4_NUM_B2C(sbi, sbi->s_journal->j_maxlen);
	else if (pxt4_has_feature_journal(sb) && !sbi->s_journal && j_inum) {
		/* j_inum for internal journal is non-zero */
		j_inode = pxt4_get_journal_inode(sb, j_inum);
		if (j_inode) {
			j_blocks = j_inode->i_size >> sb->s_blocksize_bits;
			overhead += PXT4_NUM_B2C(sbi, j_blocks);
			iput(j_inode);
		} else {
			pxt4_msg(sb, KERN_ERR, "can't get journal size");
		}
	}
	sbi->s_overhead = overhead;
	smp_wmb();
	free_page((unsigned long) buf);
	return 0;
}

static void pxt4_set_resv_clusters(struct super_block *sb)
{
	pxt4_fsblk_t resv_clusters;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);

	/*
	 * There's no need to reserve anything when we aren't using extents.
	 * The space estimates are exact, there are no unwritten extents,
	 * hole punching doesn't need new metadata... This is needed especially
	 * to keep pxt2/3 backward compatibility.
	 */
	if (!pxt4_has_feature_extents(sb))
		return;
	/*
	 * By default we reserve 2% or 4096 clusters, whichever is smaller.
	 * This should cover the situations where we can not afford to run
	 * out of space like for example punch hole, or converting
	 * unwritten extents in delalloc path. In most cases such
	 * allocation would require 1, or 2 blocks, higher numbers are
	 * very rare.
	 */
	resv_clusters = (pxt4_blocks_count(sbi->s_es) >>
			 sbi->s_cluster_bits);

	do_div(resv_clusters, 50);
	resv_clusters = min_t(pxt4_fsblk_t, resv_clusters, 4096);

	atomic64_set(&sbi->s_resv_clusters, resv_clusters);
}

static int pxt4_fill_super(struct super_block *sb, void *data, int silent)
{
	struct dax_device *dax_dev = fs_dax_get_by_bdev(sb->s_bdev);
	char *orig_data = kstrdup(data, GFP_KERNEL);
	struct buffer_head *bh, **group_desc;
	struct pxt4_super_block *es = NULL;
	struct pxt4_sb_info *sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	struct flex_groups **flex_groups;
	pxt4_fsblk_t block;
	pxt4_fsblk_t sb_block = get_sb_block(&data);
	pxt4_fsblk_t logical_sb_block;
	unsigned long offset = 0;
	unsigned long journal_devnum = 0;
	unsigned long def_mount_opts;
	struct inode *root;
	const char *descr;
	int ret = -ENOMEM;
	int blocksize, clustersize;
	unsigned int db_count;
	unsigned int i;
	int needs_recovery, has_huge_files, has_bigalloc;
	__u64 blocks_count;
	int err = 0;
	unsigned int journal_ioprio = DEFAULT_JOURNAL_IOPRIO;
	pxt4_group_t first_not_zeroed;

	if ((data && !orig_data) || !sbi)
		goto out_free_base;

	sbi->s_daxdev = dax_dev;
	sbi->s_blockgroup_lock =
		kzalloc(sizeof(struct blockgroup_lock), GFP_KERNEL);
	if (!sbi->s_blockgroup_lock)
		goto out_free_base;

	sb->s_fs_info = sbi;
	sbi->s_sb = sb;
	sbi->s_inode_readahead_blks = PXT4_DEF_INODE_READAHEAD_BLKS;
	sbi->s_sb_block = sb_block;
	if (sb->s_bdev->bd_part)
		sbi->s_sectors_written_start =
			part_stat_read(sb->s_bdev->bd_part, sectors[STAT_WRITE]);

	/* Cleanup superblock name */
	strreplace(sb->s_id, '/', '!');

	/* -EINVAL is default */
	ret = -EINVAL;
	blocksize = sb_min_blocksize(sb, PXT4_MIN_BLOCK_SIZE);
	if (!blocksize) {
		pxt4_msg(sb, KERN_ERR, "unable to set blocksize");
		goto out_fail;
	}

	/*
	 * The pxt4 superblock will not be buffer aligned for other than 1kB
	 * block sizes.  We need to calculate the offset from buffer start.
	 */
	if (blocksize != PXT4_MIN_BLOCK_SIZE) {
		logical_sb_block = sb_block * PXT4_MIN_BLOCK_SIZE;
		offset = do_div(logical_sb_block, blocksize);
	} else {
		logical_sb_block = sb_block;
	}

	if (!(bh = sb_bread_unmovable(sb, logical_sb_block))) {
		pxt4_msg(sb, KERN_ERR, "unable to read superblock");
		goto out_fail;
	}
	/*
	 * Note: s_es must be initialized as soon as possible because
	 *       some pxt4 macro-instructions depend on its value
	 */
	es = (struct pxt4_super_block *) (bh->b_data + offset);
	sbi->s_es = es;
	sb->s_magic = le16_to_cpu(es->s_magic);
	if (sb->s_magic != PXT4_SUPER_MAGIC)
		goto cantfind_pxt4;
	sbi->s_kbytes_written = le64_to_cpu(es->s_kbytes_written);

	/* Warn if metadata_csum and gdt_csum are both set. */
	if (pxt4_has_feature_metadata_csum(sb) &&
	    pxt4_has_feature_gdt_csum(sb))
		pxt4_warning(sb, "metadata_csum and uninit_bg are "
			     "redundant flags; please run fsck.");

	/* Check for a known checksum algorithm */
	if (!pxt4_verify_csum_type(sb, es)) {
		pxt4_msg(sb, KERN_ERR, "VFS: Found pxt4 filesystem with "
			 "unknown checksum algorithm.");
		silent = 1;
		goto cantfind_pxt4;
	}

	/* Load the checksum driver */
	sbi->s_chksum_driver = crypto_alloc_shash("crc32c", 0, 0);
	if (IS_ERR(sbi->s_chksum_driver)) {
		pxt4_msg(sb, KERN_ERR, "Cannot load crc32c driver.");
		ret = PTR_ERR(sbi->s_chksum_driver);
		sbi->s_chksum_driver = NULL;
		goto failed_mount;
	}

	/* Check superblock checksum */
	if (!pxt4_superblock_csum_verify(sb, es)) {
		pxt4_msg(sb, KERN_ERR, "VFS: Found pxt4 filesystem with "
			 "invalid superblock checksum.  Run e2fsck?");
		silent = 1;
		ret = -EFSBADCRC;
		goto cantfind_pxt4;
	}

	/* Precompute checksum seed for all metadata */
	if (pxt4_has_feature_csum_seed(sb))
		sbi->s_csum_seed = le32_to_cpu(es->s_checksum_seed);
	else if (pxt4_has_metadata_csum(sb) || pxt4_has_feature_ea_inode(sb))
		sbi->s_csum_seed = pxt4_chksum(sbi, ~0, es->s_uuid,
					       sizeof(es->s_uuid));

	/* Set defaults before we parse the mount options */
	def_mount_opts = le32_to_cpu(es->s_default_mount_opts);
	set_opt(sb, INIT_INODE_TABLE);
	if (def_mount_opts & PXT4_DEFM_DEBUG)
		set_opt(sb, DEBUG);
	if (def_mount_opts & PXT4_DEFM_BSDGROUPS)
		set_opt(sb, GRPID);
	if (def_mount_opts & PXT4_DEFM_UID16)
		set_opt(sb, NO_UID32);
	/* xattr user namespace & acls are now defaulted on */
	set_opt(sb, XATTR_USER);
#ifdef CONFIG_PXT4_FS_POSIX_ACL
	set_opt(sb, POSIX_ACL);
#endif
	/* don't forget to enable journal_csum when metadata_csum is enabled. */
	if (pxt4_has_metadata_csum(sb))
		set_opt(sb, JOURNAL_CHECKSUM);

	if ((def_mount_opts & PXT4_DEFM_JMODE) == PXT4_DEFM_JMODE_DATA)
		set_opt(sb, JOURNAL_DATA);
	else if ((def_mount_opts & PXT4_DEFM_JMODE) == PXT4_DEFM_JMODE_ORDERED)
		set_opt(sb, ORDERED_DATA);
	else if ((def_mount_opts & PXT4_DEFM_JMODE) == PXT4_DEFM_JMODE_WBACK)
		set_opt(sb, WRITEBACK_DATA);

	if (le16_to_cpu(sbi->s_es->s_errors) == PXT4_ERRORS_PANIC)
		set_opt(sb, ERRORS_PANIC);
	else if (le16_to_cpu(sbi->s_es->s_errors) == PXT4_ERRORS_CONTINUE)
		set_opt(sb, ERRORS_CONT);
	else
		set_opt(sb, ERRORS_RO);
	/* block_validity enabled by default; disable with noblock_validity */
	set_opt(sb, BLOCK_VALIDITY);
	if (def_mount_opts & PXT4_DEFM_DISCARD)
		set_opt(sb, DISCARD);

	sbi->s_resuid = make_kuid(&init_user_ns, le16_to_cpu(es->s_def_resuid));
	sbi->s_resgid = make_kgid(&init_user_ns, le16_to_cpu(es->s_def_resgid));
	sbi->s_commit_interval = JBD3_DEFAULT_MAX_COMMIT_AGE * HZ;
	sbi->s_min_batch_time = PXT4_DEF_MIN_BATCH_TIME;
	sbi->s_max_batch_time = PXT4_DEF_MAX_BATCH_TIME;

	if ((def_mount_opts & PXT4_DEFM_NOBARRIER) == 0)
		set_opt(sb, BARRIER);

	/*
	 * enable delayed allocation by default
	 * Use -o nodelalloc to turn it off
	 */
	if (!IS_EXT3_SB(sb) && !IS_PXT2_SB(sb) &&
	    ((def_mount_opts & PXT4_DEFM_NODELALLOC) == 0))
		set_opt(sb, DELALLOC);

	/*
	 * set default s_li_wait_mult for lazyinit, for the case there is
	 * no mount option specified.
	 */
	sbi->s_li_wait_mult = PXT4_DEF_LI_WAIT_MULT;

	blocksize = BLOCK_SIZE << le32_to_cpu(es->s_log_block_size);
	if (blocksize < PXT4_MIN_BLOCK_SIZE ||
	    blocksize > PXT4_MAX_BLOCK_SIZE) {
		pxt4_msg(sb, KERN_ERR,
		       "Unsupported filesystem blocksize %d (%d log_block_size)",
			 blocksize, le32_to_cpu(es->s_log_block_size));
		goto failed_mount;
	}

	if (le32_to_cpu(es->s_rev_level) == PXT4_GOOD_OLD_REV) {
		sbi->s_inode_size = PXT4_GOOD_OLD_INODE_SIZE;
		sbi->s_first_ino = PXT4_GOOD_OLD_FIRST_INO;
	} else {
		sbi->s_inode_size = le16_to_cpu(es->s_inode_size);
		sbi->s_first_ino = le32_to_cpu(es->s_first_ino);
		if (sbi->s_first_ino < PXT4_GOOD_OLD_FIRST_INO) {
			pxt4_msg(sb, KERN_ERR, "invalid first ino: %u",
				 sbi->s_first_ino);
			goto failed_mount;
		}
		if ((sbi->s_inode_size < PXT4_GOOD_OLD_INODE_SIZE) ||
		    (!is_power_of_2(sbi->s_inode_size)) ||
		    (sbi->s_inode_size > blocksize)) {
			pxt4_msg(sb, KERN_ERR,
			       "unsupported inode size: %d",
			       sbi->s_inode_size);
			pxt4_msg(sb, KERN_ERR, "blocksize: %d", blocksize);
			goto failed_mount;
		}
		/*
		 * i_atime_extra is the last extra field available for
		 * [acm]times in struct pxt4_inode. Checking for that
		 * field should suffice to ensure we have extra space
		 * for all three.
		 */
		if (sbi->s_inode_size >= offsetof(struct pxt4_inode, i_atime_extra) +
			sizeof(((struct pxt4_inode *)0)->i_atime_extra)) {
			sb->s_time_gran = 1;
			sb->s_time_max = PXT4_EXTRA_TIMESTAMP_MAX;
		} else {
			sb->s_time_gran = NSEC_PER_SEC;
			sb->s_time_max = PXT4_NON_EXTRA_TIMESTAMP_MAX;
		}
		sb->s_time_min = PXT4_TIMESTAMP_MIN;
	}
	if (sbi->s_inode_size > PXT4_GOOD_OLD_INODE_SIZE) {
		sbi->s_want_extra_isize = sizeof(struct pxt4_inode) -
			PXT4_GOOD_OLD_INODE_SIZE;
		if (pxt4_has_feature_extra_isize(sb)) {
			unsigned v, max = (sbi->s_inode_size -
					   PXT4_GOOD_OLD_INODE_SIZE);

			v = le16_to_cpu(es->s_want_extra_isize);
			if (v > max) {
				pxt4_msg(sb, KERN_ERR,
					 "bad s_want_extra_isize: %d", v);
				goto failed_mount;
			}
			if (sbi->s_want_extra_isize < v)
				sbi->s_want_extra_isize = v;

			v = le16_to_cpu(es->s_min_extra_isize);
			if (v > max) {
				pxt4_msg(sb, KERN_ERR,
					 "bad s_min_extra_isize: %d", v);
				goto failed_mount;
			}
			if (sbi->s_want_extra_isize < v)
				sbi->s_want_extra_isize = v;
		}
	}

	if (sbi->s_es->s_mount_opts[0]) {
		char *s_mount_opts = kstrndup(sbi->s_es->s_mount_opts,
					      sizeof(sbi->s_es->s_mount_opts),
					      GFP_KERNEL);
		if (!s_mount_opts)
			goto failed_mount;
		if (!parse_options(s_mount_opts, sb, &journal_devnum,
				   &journal_ioprio, 0)) {
			pxt4_msg(sb, KERN_WARNING,
				 "failed to parse options in superblock: %s",
				 s_mount_opts);
		}
		kfree(s_mount_opts);
	}
	sbi->s_def_mount_opt = sbi->s_mount_opt;
	if (!parse_options((char *) data, sb, &journal_devnum,
			   &journal_ioprio, 0))
		goto failed_mount;

#ifdef CONFIG_UNICODE
	if (pxt4_has_feature_casefold(sb) && !sbi->s_encoding) {
		const struct pxt4_sb_encodings *encoding_info;
		struct unicode_map *encoding;
		__u16 encoding_flags;

		if (pxt4_has_feature_encrypt(sb)) {
			pxt4_msg(sb, KERN_ERR,
				 "Can't mount with encoding and encryption");
			goto failed_mount;
		}

		if (pxt4_sb_read_encoding(es, &encoding_info,
					  &encoding_flags)) {
			pxt4_msg(sb, KERN_ERR,
				 "Encoding requested by superblock is unknown");
			goto failed_mount;
		}

		encoding = utf8_load(encoding_info->version);
		if (IS_ERR(encoding)) {
			pxt4_msg(sb, KERN_ERR,
				 "can't mount with superblock charset: %s-%s "
				 "not supported by the kernel. flags: 0x%x.",
				 encoding_info->name, encoding_info->version,
				 encoding_flags);
			goto failed_mount;
		}
		pxt4_msg(sb, KERN_INFO,"Using encoding defined by superblock: "
			 "%s-%s with flags 0x%hx", encoding_info->name,
			 encoding_info->version?:"\b", encoding_flags);

		sbi->s_encoding = encoding;
		sbi->s_encoding_flags = encoding_flags;
	}
#endif

	if (test_opt(sb, DATA_FLAGS) == PXT4_MOUNT_JOURNAL_DATA) {
		printk_once(KERN_WARNING "PXT4-fs: Warning: mounting "
			    "with data=journal disables delayed "
			    "allocation and O_DIRECT support!\n");
		if (test_opt2(sb, EXPLICIT_DELALLOC)) {
			pxt4_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and delalloc");
			goto failed_mount;
		}
		if (test_opt(sb, DIOREAD_NOLOCK)) {
			pxt4_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and dioread_nolock");
			goto failed_mount;
		}
		if (test_opt(sb, DAX)) {
			pxt4_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and dax");
			goto failed_mount;
		}
		if (pxt4_has_feature_encrypt(sb)) {
			pxt4_msg(sb, KERN_WARNING,
				 "encrypted files will use data=ordered "
				 "instead of data journaling mode");
		}
		if (test_opt(sb, DELALLOC))
			clear_opt(sb, DELALLOC);
	} else {
		sb->s_iflags |= SB_I_CGROUPWB;
	}

	sb->s_flags = (sb->s_flags & ~SB_POSIXACL) |
		(test_opt(sb, POSIX_ACL) ? SB_POSIXACL : 0);

	if (le32_to_cpu(es->s_rev_level) == PXT4_GOOD_OLD_REV &&
	    (pxt4_has_compat_features(sb) ||
	     pxt4_has_ro_compat_features(sb) ||
	     pxt4_has_incompat_features(sb)))
		pxt4_msg(sb, KERN_WARNING,
		       "feature flags set on rev 0 fs, "
		       "running e2fsck is recommended");

	if (es->s_creator_os == cpu_to_le32(PXT4_OS_HURD)) {
		set_opt2(sb, HURD_COMPAT);
		if (pxt4_has_feature_64bit(sb)) {
			pxt4_msg(sb, KERN_ERR,
				 "The Hurd can't support 64-bit file systems");
			goto failed_mount;
		}

		/*
		 * ea_inode feature uses l_i_version field which is not
		 * available in HURD_COMPAT mode.
		 */
		if (pxt4_has_feature_ea_inode(sb)) {
			pxt4_msg(sb, KERN_ERR,
				 "ea_inode feature is not supported for Hurd");
			goto failed_mount;
		}
	}

	if (IS_PXT2_SB(sb)) {
		if (pxt2_feature_set_ok(sb))
			pxt4_msg(sb, KERN_INFO, "mounting pxt2 file system "
				 "using the pxt4 subsystem");
		else {
			/*
			 * If we're probing be silent, if this looks like
			 * it's actually an ext[34] filesystem.
			 */
			if (silent && pxt4_feature_set_ok(sb, sb_rdonly(sb)))
				goto failed_mount;
			pxt4_msg(sb, KERN_ERR, "couldn't mount as pxt2 due "
				 "to feature incompatibilities");
			goto failed_mount;
		}
	}

	if (IS_EXT3_SB(sb)) {
		if (ext3_feature_set_ok(sb))
			pxt4_msg(sb, KERN_INFO, "mounting ext3 file system "
				 "using the pxt4 subsystem");
		else {
			/*
			 * If we're probing be silent, if this looks like
			 * it's actually an pxt4 filesystem.
			 */
			if (silent && pxt4_feature_set_ok(sb, sb_rdonly(sb)))
				goto failed_mount;
			pxt4_msg(sb, KERN_ERR, "couldn't mount as ext3 due "
				 "to feature incompatibilities");
			goto failed_mount;
		}
	}

	/*
	 * Check feature flags regardless of the revision level, since we
	 * previously didn't change the revision level when setting the flags,
	 * so there is a chance incompat flags are set on a rev 0 filesystem.
	 */
	if (!pxt4_feature_set_ok(sb, (sb_rdonly(sb))))
		goto failed_mount;

	if (le32_to_cpu(es->s_log_block_size) >
	    (PXT4_MAX_BLOCK_LOG_SIZE - PXT4_MIN_BLOCK_LOG_SIZE)) {
		pxt4_msg(sb, KERN_ERR,
			 "Invalid log block size: %u",
			 le32_to_cpu(es->s_log_block_size));
		goto failed_mount;
	}
	if (le32_to_cpu(es->s_log_cluster_size) >
	    (PXT4_MAX_CLUSTER_LOG_SIZE - PXT4_MIN_BLOCK_LOG_SIZE)) {
		pxt4_msg(sb, KERN_ERR,
			 "Invalid log cluster size: %u",
			 le32_to_cpu(es->s_log_cluster_size));
		goto failed_mount;
	}

	if (le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks) > (blocksize / 4)) {
		pxt4_msg(sb, KERN_ERR,
			 "Number of reserved GDT blocks insanely large: %d",
			 le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks));
		goto failed_mount;
	}

	if (sbi->s_mount_opt & PXT4_MOUNT_DAX) {
		if (pxt4_has_feature_inline_data(sb)) {
			pxt4_msg(sb, KERN_ERR, "Cannot use DAX on a filesystem"
					" that may contain inline data");
			goto failed_mount;
		}
		if (!bdev_dax_supported(sb->s_bdev, blocksize)) {
			pxt4_msg(sb, KERN_ERR,
				"DAX unsupported by block device.");
			goto failed_mount;
		}
	}

	if (pxt4_has_feature_encrypt(sb) && es->s_encryption_level) {
		pxt4_msg(sb, KERN_ERR, "Unsupported encryption level %d",
			 es->s_encryption_level);
		goto failed_mount;
	}

	if (sb->s_blocksize != blocksize) {
		/* Validate the filesystem blocksize */
		if (!sb_set_blocksize(sb, blocksize)) {
			pxt4_msg(sb, KERN_ERR, "bad block size %d",
					blocksize);
			goto failed_mount;
		}

		brelse(bh);
		logical_sb_block = sb_block * PXT4_MIN_BLOCK_SIZE;
		offset = do_div(logical_sb_block, blocksize);
		bh = sb_bread_unmovable(sb, logical_sb_block);
		if (!bh) {
			pxt4_msg(sb, KERN_ERR,
			       "Can't read superblock on 2nd try");
			goto failed_mount;
		}
		es = (struct pxt4_super_block *)(bh->b_data + offset);
		sbi->s_es = es;
		if (es->s_magic != cpu_to_le16(PXT4_SUPER_MAGIC)) {
			pxt4_msg(sb, KERN_ERR,
			       "Magic mismatch, very weird!");
			goto failed_mount;
		}
	}

	has_huge_files = pxt4_has_feature_huge_file(sb);
	sbi->s_bitmap_maxbytes = pxt4_max_bitmap_size(sb->s_blocksize_bits,
						      has_huge_files);
	sb->s_maxbytes = pxt4_max_size(sb->s_blocksize_bits, has_huge_files);

	sbi->s_desc_size = le16_to_cpu(es->s_desc_size);
	if (pxt4_has_feature_64bit(sb)) {
		if (sbi->s_desc_size < PXT4_MIN_DESC_SIZE_64BIT ||
		    sbi->s_desc_size > PXT4_MAX_DESC_SIZE ||
		    !is_power_of_2(sbi->s_desc_size)) {
			pxt4_msg(sb, KERN_ERR,
			       "unsupported descriptor size %lu",
			       sbi->s_desc_size);
			goto failed_mount;
		}
	} else
		sbi->s_desc_size = PXT4_MIN_DESC_SIZE;

	sbi->s_blocks_per_group = le32_to_cpu(es->s_blocks_per_group);
	sbi->s_inodes_per_group = le32_to_cpu(es->s_inodes_per_group);

	sbi->s_inodes_per_block = blocksize / PXT4_INODE_SIZE(sb);
	if (sbi->s_inodes_per_block == 0)
		goto cantfind_pxt4;
	if (sbi->s_inodes_per_group < sbi->s_inodes_per_block ||
	    sbi->s_inodes_per_group > blocksize * 8) {
		pxt4_msg(sb, KERN_ERR, "invalid inodes per group: %lu\n",
			 sbi->s_inodes_per_group);
		goto failed_mount;
	}
	sbi->s_itb_per_group = sbi->s_inodes_per_group /
					sbi->s_inodes_per_block;
	sbi->s_desc_per_block = blocksize / PXT4_DESC_SIZE(sb);
	sbi->s_sbh = bh;
	sbi->s_mount_state = le16_to_cpu(es->s_state);
	sbi->s_addr_per_block_bits = ilog2(PXT4_ADDR_PER_BLOCK(sb));
	sbi->s_desc_per_block_bits = ilog2(PXT4_DESC_PER_BLOCK(sb));

	for (i = 0; i < 4; i++)
		sbi->s_hash_seed[i] = le32_to_cpu(es->s_hash_seed[i]);
	sbi->s_def_hash_version = es->s_def_hash_version;
	if (pxt4_has_feature_dir_index(sb)) {
		i = le32_to_cpu(es->s_flags);
		if (i & PXT2_FLAGS_UNSIGNED_HASH)
			sbi->s_hash_unsigned = 3;
		else if ((i & PXT2_FLAGS_SIGNED_HASH) == 0) {
#ifdef __CHAR_UNSIGNED__
			if (!sb_rdonly(sb))
				es->s_flags |=
					cpu_to_le32(PXT2_FLAGS_UNSIGNED_HASH);
			sbi->s_hash_unsigned = 3;
#else
			if (!sb_rdonly(sb))
				es->s_flags |=
					cpu_to_le32(PXT2_FLAGS_SIGNED_HASH);
#endif
		}
	}

	/* Handle clustersize */
	clustersize = BLOCK_SIZE << le32_to_cpu(es->s_log_cluster_size);
	has_bigalloc = pxt4_has_feature_bigalloc(sb);
	if (has_bigalloc) {
		if (clustersize < blocksize) {
			pxt4_msg(sb, KERN_ERR,
				 "cluster size (%d) smaller than "
				 "block size (%d)", clustersize, blocksize);
			goto failed_mount;
		}
		sbi->s_cluster_bits = le32_to_cpu(es->s_log_cluster_size) -
			le32_to_cpu(es->s_log_block_size);
		sbi->s_clusters_per_group =
			le32_to_cpu(es->s_clusters_per_group);
		if (sbi->s_clusters_per_group > blocksize * 8) {
			pxt4_msg(sb, KERN_ERR,
				 "#clusters per group too big: %lu",
				 sbi->s_clusters_per_group);
			goto failed_mount;
		}
		if (sbi->s_blocks_per_group !=
		    (sbi->s_clusters_per_group * (clustersize / blocksize))) {
			pxt4_msg(sb, KERN_ERR, "blocks per group (%lu) and "
				 "clusters per group (%lu) inconsistent",
				 sbi->s_blocks_per_group,
				 sbi->s_clusters_per_group);
			goto failed_mount;
		}
	} else {
		if (clustersize != blocksize) {
			pxt4_msg(sb, KERN_ERR,
				 "fragment/cluster size (%d) != "
				 "block size (%d)", clustersize, blocksize);
			goto failed_mount;
		}
		if (sbi->s_blocks_per_group > blocksize * 8) {
			pxt4_msg(sb, KERN_ERR,
				 "#blocks per group too big: %lu",
				 sbi->s_blocks_per_group);
			goto failed_mount;
		}
		sbi->s_clusters_per_group = sbi->s_blocks_per_group;
		sbi->s_cluster_bits = 0;
	}
	sbi->s_cluster_ratio = clustersize / blocksize;

	/* Do we have standard group size of clustersize * 8 blocks ? */
	if (sbi->s_blocks_per_group == clustersize << 3)
		set_opt2(sb, STD_GROUP_SIZE);

	/*
	 * Test whether we have more sectors than will fit in sector_t,
	 * and whether the max offset is addressable by the page cache.
	 */
	err = generic_check_addressable(sb->s_blocksize_bits,
					pxt4_blocks_count(es));
	if (err) {
		pxt4_msg(sb, KERN_ERR, "filesystem"
			 " too large to mount safely on this system");
		goto failed_mount;
	}

	if (PXT4_BLOCKS_PER_GROUP(sb) == 0)
		goto cantfind_pxt4;

	/* check blocks count against device size */
	blocks_count = sb->s_bdev->bd_inode->i_size >> sb->s_blocksize_bits;
	if (blocks_count && pxt4_blocks_count(es) > blocks_count) {
		pxt4_msg(sb, KERN_WARNING, "bad geometry: block count %llu "
		       "exceeds size of device (%llu blocks)",
		       pxt4_blocks_count(es), blocks_count);
		goto failed_mount;
	}

	/*
	 * It makes no sense for the first data block to be beyond the end
	 * of the filesystem.
	 */
	if (le32_to_cpu(es->s_first_data_block) >= pxt4_blocks_count(es)) {
		pxt4_msg(sb, KERN_WARNING, "bad geometry: first data "
			 "block %u is beyond end of filesystem (%llu)",
			 le32_to_cpu(es->s_first_data_block),
			 pxt4_blocks_count(es));
		goto failed_mount;
	}
	if ((es->s_first_data_block == 0) && (es->s_log_block_size == 0) &&
	    (sbi->s_cluster_ratio == 1)) {
		pxt4_msg(sb, KERN_WARNING, "bad geometry: first data "
			 "block is 0 with a 1k block and cluster size");
		goto failed_mount;
	}

	blocks_count = (pxt4_blocks_count(es) -
			le32_to_cpu(es->s_first_data_block) +
			PXT4_BLOCKS_PER_GROUP(sb) - 1);
	do_div(blocks_count, PXT4_BLOCKS_PER_GROUP(sb));
	if (blocks_count > ((uint64_t)1<<32) - PXT4_DESC_PER_BLOCK(sb)) {
		pxt4_msg(sb, KERN_WARNING, "groups count too large: %llu "
		       "(block count %llu, first data block %u, "
		       "blocks per group %lu)", blocks_count,
		       pxt4_blocks_count(es),
		       le32_to_cpu(es->s_first_data_block),
		       PXT4_BLOCKS_PER_GROUP(sb));
		goto failed_mount;
	}
	sbi->s_groups_count = blocks_count;
	sbi->s_blockfile_groups = min_t(pxt4_group_t, sbi->s_groups_count,
			(PXT4_MAX_BLOCK_FILE_PHYS / PXT4_BLOCKS_PER_GROUP(sb)));
	if (((u64)sbi->s_groups_count * sbi->s_inodes_per_group) !=
	    le32_to_cpu(es->s_inodes_count)) {
		pxt4_msg(sb, KERN_ERR, "inodes count not valid: %u vs %llu",
			 le32_to_cpu(es->s_inodes_count),
			 ((u64)sbi->s_groups_count * sbi->s_inodes_per_group));
		ret = -EINVAL;
		goto failed_mount;
	}
	db_count = (sbi->s_groups_count + PXT4_DESC_PER_BLOCK(sb) - 1) /
		   PXT4_DESC_PER_BLOCK(sb);
	if (pxt4_has_feature_meta_bg(sb)) {
		if (le32_to_cpu(es->s_first_meta_bg) > db_count) {
			pxt4_msg(sb, KERN_WARNING,
				 "first meta block group too large: %u "
				 "(group descriptor block count %u)",
				 le32_to_cpu(es->s_first_meta_bg), db_count);
			goto failed_mount;
		}
	}
	rcu_assign_pointer(sbi->s_group_desc,
			   kvmalloc_array(db_count,
					  sizeof(struct buffer_head *),
					  GFP_KERNEL));
	if (sbi->s_group_desc == NULL) {
		pxt4_msg(sb, KERN_ERR, "not enough memory");
		ret = -ENOMEM;
		goto failed_mount;
	}

	bgl_lock_init(sbi->s_blockgroup_lock);

	/* Pre-read the descriptors into the buffer cache */
	for (i = 0; i < db_count; i++) {
		block = descriptor_loc(sb, logical_sb_block, i);
		sb_breadahead_unmovable(sb, block);
	}

	for (i = 0; i < db_count; i++) {
		struct buffer_head *bh;

		block = descriptor_loc(sb, logical_sb_block, i);
		bh = sb_bread_unmovable(sb, block);
		if (!bh) {
			pxt4_msg(sb, KERN_ERR,
			       "can't read group descriptor %d", i);
			db_count = i;
			goto failed_mount2;
		}
		rcu_read_lock();
		rcu_dereference(sbi->s_group_desc)[i] = bh;
		rcu_read_unlock();
	}
	sbi->s_gdb_count = db_count;
	if (!pxt4_check_descriptors(sb, logical_sb_block, &first_not_zeroed)) {
		pxt4_msg(sb, KERN_ERR, "group descriptors corrupted!");
		ret = -EFSCORRUPTED;
		goto failed_mount2;
	}

	timer_setup(&sbi->s_err_report, print_daily_error_info, 0);

	/* Register extent status tree shrinker */
	if (pxt4_es_register_shrinker(sbi))
		goto failed_mount3;

	sbi->s_stripe = pxt4_get_stripe_size(sbi);
	sbi->s_extent_max_zeroout_kb = 32;

	/*
	 * set up enough so that it can read an inode
	 */
	sb->s_op = &pxt4_sops;
	sb->s_export_op = &pxt4_export_ops;
	sb->s_xattr = pxt4_xattr_handlers;
#ifdef CONFIG_FS_ENCRYPTION
	sb->s_cop = &pxt4_cryptops;
#endif
#ifdef CONFIG_FS_VERITY
	sb->s_vop = &pxt4_verityops;
#endif
#ifdef CONFIG_QUOTA
	sb->dq_op = &pxt4_quota_operations;
	if (pxt4_has_feature_quota(sb))
		sb->s_qcop = &dquot_quotactl_sysfile_ops;
	else
		sb->s_qcop = &pxt4_qctl_operations;
	sb->s_quota_types = QTYPE_MASK_USR | QTYPE_MASK_GRP | QTYPE_MASK_PRJ;
#endif
	memcpy(&sb->s_uuid, es->s_uuid, sizeof(es->s_uuid));

	INIT_LIST_HEAD(&sbi->s_orphan); /* unlinked but open files */
	mutex_init(&sbi->s_orphan_lock);

	sb->s_root = NULL;

	needs_recovery = (es->s_last_orphan != 0 ||
			  pxt4_has_feature_journal_needs_recovery(sb));

	if (pxt4_has_feature_mmp(sb) && !sb_rdonly(sb))
		if (pxt4_multi_mount_protect(sb, le64_to_cpu(es->s_mmp_block)))
			goto failed_mount3a;

	/*
	 * The first inode we look at is the journal inode.  Don't try
	 * root first: it may be modified in the journal!
	 */
	if (!test_opt(sb, NOLOAD) && pxt4_has_feature_journal(sb)) {
		err = pxt4_load_journal(sb, es, journal_devnum);
		if (err)
			goto failed_mount3a;
	} else if (test_opt(sb, NOLOAD) && !sb_rdonly(sb) &&
		   pxt4_has_feature_journal_needs_recovery(sb)) {
		pxt4_msg(sb, KERN_ERR, "required journal recovery "
		       "suppressed and not mounted read-only");
		goto failed_mount_wq;
	} else {
		/* Nojournal mode, all journal mount options are illegal */
		if (test_opt2(sb, EXPLICIT_JOURNAL_CHECKSUM)) {
			pxt4_msg(sb, KERN_ERR, "can't mount with "
				 "journal_checksum, fs mounted w/o journal");
			goto failed_mount_wq;
		}
		if (test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
			pxt4_msg(sb, KERN_ERR, "can't mount with "
				 "journal_async_commit, fs mounted w/o journal");
			goto failed_mount_wq;
		}
		if (sbi->s_commit_interval != JBD3_DEFAULT_MAX_COMMIT_AGE*HZ) {
			pxt4_msg(sb, KERN_ERR, "can't mount with "
				 "commit=%lu, fs mounted w/o journal",
				 sbi->s_commit_interval / HZ);
			goto failed_mount_wq;
		}
		if (PXT4_MOUNT_DATA_FLAGS &
		    (sbi->s_mount_opt ^ sbi->s_def_mount_opt)) {
			pxt4_msg(sb, KERN_ERR, "can't mount with "
				 "data=, fs mounted w/o journal");
			goto failed_mount_wq;
		}
		sbi->s_def_mount_opt &= ~PXT4_MOUNT_JOURNAL_CHECKSUM;
		clear_opt(sb, JOURNAL_CHECKSUM);
		clear_opt(sb, DATA_FLAGS);
		sbi->s_journal = NULL;
		needs_recovery = 0;
		goto no_journal;
	}

	if (pxt4_has_feature_64bit(sb) &&
	    !jbd3_journal_set_features(PXT4_SB(sb)->s_journal, 0, 0,
				       JBD3_FEATURE_INCOMPAT_64BIT)) {
		pxt4_msg(sb, KERN_ERR, "Failed to set 64-bit journal feature");
		goto failed_mount_wq;
	}

	if (!set_journal_csum_feature_set(sb)) {
		pxt4_msg(sb, KERN_ERR, "Failed to set journal checksum "
			 "feature set");
		goto failed_mount_wq;
	}

	/* We have now updated the journal if required, so we can
	 * validate the data journaling mode. */
	switch (test_opt(sb, DATA_FLAGS)) {
	case 0:
		/* No mode set, assume a default based on the journal
		 * capabilities: ORDERED_DATA if the journal can
		 * cope, else JOURNAL_DATA
		 */
		if (jbd3_journal_check_available_features
		    (sbi->s_journal, 0, 0, JBD3_FEATURE_INCOMPAT_REVOKE)) {
			set_opt(sb, ORDERED_DATA);
			sbi->s_def_mount_opt |= PXT4_MOUNT_ORDERED_DATA;
		} else {
			set_opt(sb, JOURNAL_DATA);
			sbi->s_def_mount_opt |= PXT4_MOUNT_JOURNAL_DATA;
		}
		break;

	case PXT4_MOUNT_ORDERED_DATA:
	case PXT4_MOUNT_WRITEBACK_DATA:
		if (!jbd3_journal_check_available_features
		    (sbi->s_journal, 0, 0, JBD3_FEATURE_INCOMPAT_REVOKE)) {
			pxt4_msg(sb, KERN_ERR, "Journal does not support "
			       "requested data journaling mode");
			goto failed_mount_wq;
		}
	default:
		break;
	}

	if (test_opt(sb, DATA_FLAGS) == PXT4_MOUNT_ORDERED_DATA &&
	    test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
		pxt4_msg(sb, KERN_ERR, "can't mount with "
			"journal_async_commit in data=ordered mode");
		goto failed_mount_wq;
	}

	set_task_ioprio(sbi->s_journal->j_task, journal_ioprio);

	sbi->s_journal->j_commit_callback = pxt4_journal_commit_callback;

no_journal:
	if (!test_opt(sb, NO_MBCACHE)) {
		sbi->s_ea_block_cache = pxt4_xattr_create_cache();
		if (!sbi->s_ea_block_cache) {
			pxt4_msg(sb, KERN_ERR,
				 "Failed to create ea_block_cache");
			goto failed_mount_wq;
		}

		if (pxt4_has_feature_ea_inode(sb)) {
			sbi->s_ea_inode_cache = pxt4_xattr_create_cache();
			if (!sbi->s_ea_inode_cache) {
				pxt4_msg(sb, KERN_ERR,
					 "Failed to create ea_inode_cache");
				goto failed_mount_wq;
			}
		}
	}

	if ((DUMMY_ENCRYPTION_ENABLED(sbi) || pxt4_has_feature_encrypt(sb)) &&
	    (blocksize != PAGE_SIZE)) {
		pxt4_msg(sb, KERN_ERR,
			 "Unsupported blocksize for fs encryption");
		goto failed_mount_wq;
	}

	if (pxt4_has_feature_verity(sb) && blocksize != PAGE_SIZE) {
		pxt4_msg(sb, KERN_ERR, "Unsupported blocksize for fs-verity");
		goto failed_mount_wq;
	}

	if (DUMMY_ENCRYPTION_ENABLED(sbi) && !sb_rdonly(sb) &&
	    !pxt4_has_feature_encrypt(sb)) {
		pxt4_set_feature_encrypt(sb);
		pxt4_commit_super(sb, 1);
	}

	/*
	 * Get the # of file system overhead blocks from the
	 * superblock if present.
	 */
	if (es->s_overhead_clusters)
		sbi->s_overhead = le32_to_cpu(es->s_overhead_clusters);
	else {
		err = pxt4_calculate_overhead(sb);
		if (err)
			goto failed_mount_wq;
	}

	/*
	 * The maximum number of concurrent works can be high and
	 * concurrency isn't really necessary.  Limit it to 1.
	 */
	PXT4_SB(sb)->rsv_conversion_wq =
		alloc_workqueue("pxt4-rsv-conversion", WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
	if (!PXT4_SB(sb)->rsv_conversion_wq) {
		printk(KERN_ERR "PXT4-fs: failed to create workqueue\n");
		ret = -ENOMEM;
		goto failed_mount4;
	}

	/*
	 * The jbd3_journal_load will have done any necessary log recovery,
	 * so we can safely mount the rest of the filesystem now.
	 */

	root = pxt4_iget(sb, PXT4_ROOT_INO, PXT4_IGET_SPECIAL);
	if (IS_ERR(root)) {
		pxt4_msg(sb, KERN_ERR, "get root inode failed");
		ret = PTR_ERR(root);
		root = NULL;
		goto failed_mount4;
	}
	if (!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		pxt4_msg(sb, KERN_ERR, "corrupt root inode, run e2fsck");
		iput(root);
		goto failed_mount4;
	}

#ifdef CONFIG_UNICODE
	if (sbi->s_encoding)
		sb->s_d_op = &pxt4_dentry_ops;
#endif

	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		pxt4_msg(sb, KERN_ERR, "get root dentry failed");
		ret = -ENOMEM;
		goto failed_mount4;
	}

	ret = pxt4_setup_super(sb, es, sb_rdonly(sb));
	if (ret == -EROFS) {
		sb->s_flags |= SB_RDONLY;
		ret = 0;
	} else if (ret)
		goto failed_mount4a;

	pxt4_set_resv_clusters(sb);

	if (test_opt(sb, BLOCK_VALIDITY)) {
		err = pxt4_setup_system_zone(sb);
		if (err) {
			pxt4_msg(sb, KERN_ERR, "failed to initialize system "
				 "zone (%d)", err);
			goto failed_mount4a;
		}
	}

	pxt4_ext_init(sb);
	err = pxt4_mb_init(sb);
	if (err) {
		pxt4_msg(sb, KERN_ERR, "failed to initialize mballoc (%d)",
			 err);
		goto failed_mount5;
	}

	block = pxt4_count_free_clusters(sb);
	pxt4_free_blocks_count_set(sbi->s_es, 
				   PXT4_C2B(sbi, block));
	pxt4_superblock_csum_set(sb);
	err = percpu_counter_init(&sbi->s_freeclusters_counter, block,
				  GFP_KERNEL);
	if (!err) {
		unsigned long freei = pxt4_count_free_inodes(sb);
		sbi->s_es->s_free_inodes_count = cpu_to_le32(freei);
		pxt4_superblock_csum_set(sb);
		err = percpu_counter_init(&sbi->s_freeinodes_counter, freei,
					  GFP_KERNEL);
	}
	if (!err)
		err = percpu_counter_init(&sbi->s_dirs_counter,
					  pxt4_count_dirs(sb), GFP_KERNEL);
	if (!err)
		err = percpu_counter_init(&sbi->s_dirtyclusters_counter, 0,
					  GFP_KERNEL);
	if (!err)
		err = percpu_init_rwsem(&sbi->s_writepages_rwsem);

	if (err) {
		pxt4_msg(sb, KERN_ERR, "insufficient memory");
		goto failed_mount6;
	}

	if (pxt4_has_feature_flex_bg(sb))
		if (!pxt4_fill_flex_info(sb)) {
			pxt4_msg(sb, KERN_ERR,
			       "unable to initialize "
			       "flex_bg meta info!");
			goto failed_mount6;
		}

	err = pxt4_register_li_request(sb, first_not_zeroed);
	if (err)
		goto failed_mount6;

	err = pxt4_register_sysfs(sb);
	if (err)
		goto failed_mount7;

#ifdef CONFIG_QUOTA
	/* Enable quota usage during mount. */
	if (pxt4_has_feature_quota(sb) && !sb_rdonly(sb)) {
		err = pxt4_enable_quotas(sb);
		if (err)
			goto failed_mount8;
	}
#endif  /* CONFIG_QUOTA */

	PXT4_SB(sb)->s_mount_state |= PXT4_ORPHAN_FS;
	pxt4_orphan_cleanup(sb, es);
	PXT4_SB(sb)->s_mount_state &= ~PXT4_ORPHAN_FS;
	if (needs_recovery) {
		pxt4_msg(sb, KERN_INFO, "recovery complete");
		err = pxt4_mark_recovery_complete(sb, es);
		if (err)
			goto failed_mount8;
	}
	if (PXT4_SB(sb)->s_journal) {
		if (test_opt(sb, DATA_FLAGS) == PXT4_MOUNT_JOURNAL_DATA)
			descr = " journalled data mode";
		else if (test_opt(sb, DATA_FLAGS) == PXT4_MOUNT_ORDERED_DATA)
			descr = " ordered data mode";
		else
			descr = " writeback data mode";
	} else
		descr = "out journal";

	if (test_opt(sb, DISCARD)) {
		struct request_queue *q = bdev_get_queue(sb->s_bdev);
		if (!blk_queue_discard(q))
			pxt4_msg(sb, KERN_WARNING,
				 "mounting with \"discard\" option, but "
				 "the device does not support discard");
	}

	if (___ratelimit(&pxt4_mount_msg_ratelimit, "PXT4-fs mount"))
		pxt4_msg(sb, KERN_INFO, "mounted filesystem with%s. "
			 "Opts: %.*s%s%s", descr,
			 (int) sizeof(sbi->s_es->s_mount_opts),
			 sbi->s_es->s_mount_opts,
			 *sbi->s_es->s_mount_opts ? "; " : "", orig_data);

	if (es->s_error_count)
		mod_timer(&sbi->s_err_report, jiffies + 300*HZ); /* 5 minutes */

	/* Enable message ratelimiting. Default is 10 messages per 5 secs. */
	ratelimit_state_init(&sbi->s_err_ratelimit_state, 5 * HZ, 10);
	ratelimit_state_init(&sbi->s_warning_ratelimit_state, 5 * HZ, 10);
	ratelimit_state_init(&sbi->s_msg_ratelimit_state, 5 * HZ, 10);

	kfree(orig_data);
	return 0;

cantfind_pxt4:
	if (!silent)
		pxt4_msg(sb, KERN_ERR, "VFS: Can't find pxt4 filesystem");
	goto failed_mount;

failed_mount8:
	pxt4_unregister_sysfs(sb);
failed_mount7:
	pxt4_unregister_li_request(sb);
failed_mount6:
	pxt4_mb_release(sb);
	rcu_read_lock();
	flex_groups = rcu_dereference(sbi->s_flex_groups);
	if (flex_groups) {
		for (i = 0; i < sbi->s_flex_groups_allocated; i++)
			kvfree(flex_groups[i]);
		kvfree(flex_groups);
	}
	rcu_read_unlock();
	percpu_counter_destroy(&sbi->s_freeclusters_counter);
	percpu_counter_destroy(&sbi->s_freeinodes_counter);
	percpu_counter_destroy(&sbi->s_dirs_counter);
	percpu_counter_destroy(&sbi->s_dirtyclusters_counter);
	percpu_free_rwsem(&sbi->s_writepages_rwsem);
failed_mount5:
	pxt4_ext_release(sb);
	pxt4_release_system_zone(sb);
failed_mount4a:
	dput(sb->s_root);
	sb->s_root = NULL;
failed_mount4:
	pxt4_msg(sb, KERN_ERR, "mount failed");
	if (PXT4_SB(sb)->rsv_conversion_wq)
		destroy_workqueue(PXT4_SB(sb)->rsv_conversion_wq);
failed_mount_wq:
	pxt4_xattr_destroy_cache(sbi->s_ea_inode_cache);
	sbi->s_ea_inode_cache = NULL;

	pxt4_xattr_destroy_cache(sbi->s_ea_block_cache);
	sbi->s_ea_block_cache = NULL;

	if (sbi->s_journal) {
		jbd3_journal_destroy(sbi->s_journal);
		sbi->s_journal = NULL;
	}
failed_mount3a:
	pxt4_es_unregister_shrinker(sbi);
failed_mount3:
	del_timer_sync(&sbi->s_err_report);
	if (sbi->s_mmp_tsk)
		kthread_stop(sbi->s_mmp_tsk);
failed_mount2:
	rcu_read_lock();
	group_desc = rcu_dereference(sbi->s_group_desc);
	for (i = 0; i < db_count; i++)
		brelse(group_desc[i]);
	kvfree(group_desc);
	rcu_read_unlock();
failed_mount:
	if (sbi->s_chksum_driver)
		crypto_free_shash(sbi->s_chksum_driver);

#ifdef CONFIG_UNICODE
	utf8_unload(sbi->s_encoding);
#endif

#ifdef CONFIG_QUOTA
	for (i = 0; i < PXT4_MAXQUOTAS; i++)
		kfree(get_qf_name(sb, sbi, i));
#endif
	pxt4_blkdev_remove(sbi);
	brelse(bh);
out_fail:
	sb->s_fs_info = NULL;
	kfree(sbi->s_blockgroup_lock);
out_free_base:
	kfree(sbi);
	kfree(orig_data);
	fs_put_dax(dax_dev);
	return err ? err : ret;
}

/*
 * Setup any per-fs journal parameters now.  We'll do this both on
 * initial mount, once the journal has been initialised but before we've
 * done any recovery; and again on any subsequent remount.
 */
static void pxt4_init_journal_params(struct super_block *sb, journal_t *journal)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);

	journal->j_commit_interval = sbi->s_commit_interval;
	journal->j_min_batch_time = sbi->s_min_batch_time;
	journal->j_max_batch_time = sbi->s_max_batch_time;

	write_lock(&journal->j_state_lock);
	if (test_opt(sb, BARRIER))
		journal->j_flags |= JBD3_BARRIER;
	else
		journal->j_flags &= ~JBD3_BARRIER;
	if (test_opt(sb, DATA_ERR_ABORT))
		journal->j_flags |= JBD3_ABORT_ON_SYNCDATA_ERR;
	else
		journal->j_flags &= ~JBD3_ABORT_ON_SYNCDATA_ERR;
	write_unlock(&journal->j_state_lock);
}

static struct inode *pxt4_get_journal_inode(struct super_block *sb,
					     unsigned int journal_inum)
{
	struct inode *journal_inode;

	/*
	 * Test for the existence of a valid inode on disk.  Bad things
	 * happen if we iget() an unused inode, as the subsequent iput()
	 * will try to delete it.
	 */
	journal_inode = pxt4_iget(sb, journal_inum, PXT4_IGET_SPECIAL);
	if (IS_ERR(journal_inode)) {
		pxt4_msg(sb, KERN_ERR, "no journal found");
		return NULL;
	}
	if (!journal_inode->i_nlink) {
		make_bad_inode(journal_inode);
		iput(journal_inode);
		pxt4_msg(sb, KERN_ERR, "journal inode is deleted");
		return NULL;
	}

	jbd_debug(2, "Journal inode found at %p: %lld bytes\n",
		  journal_inode, journal_inode->i_size);
	if (!S_ISREG(journal_inode->i_mode)) {
		pxt4_msg(sb, KERN_ERR, "invalid journal inode");
		iput(journal_inode);
		return NULL;
	}
	return journal_inode;
}

static journal_t *pxt4_get_journal(struct super_block *sb,
				   unsigned int journal_inum)
{
	struct inode *journal_inode;
	journal_t *journal;

	if (WARN_ON_ONCE(!pxt4_has_feature_journal(sb)))
		return NULL;

	journal_inode = pxt4_get_journal_inode(sb, journal_inum);
	if (!journal_inode)
		return NULL;

	journal = jbd3_journal_init_inode(journal_inode);
	if (!journal) {
		pxt4_msg(sb, KERN_ERR, "Could not load journal inode");
		iput(journal_inode);
		return NULL;
	}
	journal->j_private = sb;
	pxt4_init_journal_params(sb, journal);
	return journal;
}

static journal_t *pxt4_get_dev_journal(struct super_block *sb,
				       dev_t j_dev)
{
	struct buffer_head *bh;
	journal_t *journal;
	pxt4_fsblk_t start;
	pxt4_fsblk_t len;
	int hblock, blocksize;
	pxt4_fsblk_t sb_block;
	unsigned long offset;
	struct pxt4_super_block *es;
	struct block_device *bdev;

	if (WARN_ON_ONCE(!pxt4_has_feature_journal(sb)))
		return NULL;

	bdev = pxt4_blkdev_get(j_dev, sb);
	if (bdev == NULL)
		return NULL;

	blocksize = sb->s_blocksize;
	hblock = bdev_logical_block_size(bdev);
	if (blocksize < hblock) {
		pxt4_msg(sb, KERN_ERR,
			"blocksize too small for journal device");
		goto out_bdev;
	}

	sb_block = PXT4_MIN_BLOCK_SIZE / blocksize;
	offset = PXT4_MIN_BLOCK_SIZE % blocksize;
	set_blocksize(bdev, blocksize);
	if (!(bh = __bread(bdev, sb_block, blocksize))) {
		pxt4_msg(sb, KERN_ERR, "couldn't read superblock of "
		       "external journal");
		goto out_bdev;
	}

	es = (struct pxt4_super_block *) (bh->b_data + offset);
	if ((le16_to_cpu(es->s_magic) != PXT4_SUPER_MAGIC) ||
	    !(le32_to_cpu(es->s_feature_incompat) &
	      PXT4_FEATURE_INCOMPAT_JOURNAL_DEV)) {
		pxt4_msg(sb, KERN_ERR, "external journal has "
					"bad superblock");
		brelse(bh);
		goto out_bdev;
	}

	if ((le32_to_cpu(es->s_feature_ro_compat) &
	     PXT4_FEATURE_RO_COMPAT_METADATA_CSUM) &&
	    es->s_checksum != pxt4_superblock_csum(sb, es)) {
		pxt4_msg(sb, KERN_ERR, "external journal has "
				       "corrupt superblock");
		brelse(bh);
		goto out_bdev;
	}

	if (memcmp(PXT4_SB(sb)->s_es->s_journal_uuid, es->s_uuid, 16)) {
		pxt4_msg(sb, KERN_ERR, "journal UUID does not match");
		brelse(bh);
		goto out_bdev;
	}

	len = pxt4_blocks_count(es);
	start = sb_block + 1;
	brelse(bh);	/* we're done with the superblock */

	journal = jbd3_journal_init_dev(bdev, sb->s_bdev,
					start, len, blocksize);
	if (!journal) {
		pxt4_msg(sb, KERN_ERR, "failed to create device journal");
		goto out_bdev;
	}
	journal->j_private = sb;
	ll_rw_block(REQ_OP_READ, REQ_META | REQ_PRIO, 1, &journal->j_sb_buffer);
	wait_on_buffer(journal->j_sb_buffer);
	if (!buffer_uptodate(journal->j_sb_buffer)) {
		pxt4_msg(sb, KERN_ERR, "I/O error on journal device");
		goto out_journal;
	}
	if (be32_to_cpu(journal->j_superblock->s_nr_users) != 1) {
		pxt4_msg(sb, KERN_ERR, "External journal has more than one "
					"user (unsupported) - %d",
			be32_to_cpu(journal->j_superblock->s_nr_users));
		goto out_journal;
	}
	PXT4_SB(sb)->journal_bdev = bdev;
	pxt4_init_journal_params(sb, journal);
	return journal;

out_journal:
	jbd3_journal_destroy(journal);
out_bdev:
	pxt4_blkdev_put(bdev);
	return NULL;
}

static int pxt4_load_journal(struct super_block *sb,
			     struct pxt4_super_block *es,
			     unsigned long journal_devnum)
{
	journal_t *journal;
	unsigned int journal_inum = le32_to_cpu(es->s_journal_inum);
	dev_t journal_dev;
	int err = 0;
	int really_read_only;
	int journal_dev_ro;

	if (WARN_ON_ONCE(!pxt4_has_feature_journal(sb)))
		return -EFSCORRUPTED;

	if (journal_devnum &&
	    journal_devnum != le32_to_cpu(es->s_journal_dev)) {
		pxt4_msg(sb, KERN_INFO, "external journal device major/minor "
			"numbers have changed");
		journal_dev = new_decode_dev(journal_devnum);
	} else
		journal_dev = new_decode_dev(le32_to_cpu(es->s_journal_dev));

	if (journal_inum && journal_dev) {
		pxt4_msg(sb, KERN_ERR,
			 "filesystem has both journal inode and journal device!");
		return -EINVAL;
	}

	if (journal_inum) {
		journal = pxt4_get_journal(sb, journal_inum);
		if (!journal)
			return -EINVAL;
	} else {
		journal = pxt4_get_dev_journal(sb, journal_dev);
		if (!journal)
			return -EINVAL;
	}

	journal_dev_ro = bdev_read_only(journal->j_dev);
	really_read_only = bdev_read_only(sb->s_bdev) | journal_dev_ro;

	if (journal_dev_ro && !sb_rdonly(sb)) {
		pxt4_msg(sb, KERN_ERR,
			 "journal device read-only, try mounting with '-o ro'");
		err = -EROFS;
		goto err_out;
	}

	/*
	 * Are we loading a blank journal or performing recovery after a
	 * crash?  For recovery, we need to check in advance whether we
	 * can get read-write access to the device.
	 */
	if (pxt4_has_feature_journal_needs_recovery(sb)) {
		if (sb_rdonly(sb)) {
			pxt4_msg(sb, KERN_INFO, "INFO: recovery "
					"required on readonly filesystem");
			if (really_read_only) {
				pxt4_msg(sb, KERN_ERR, "write access "
					"unavailable, cannot proceed "
					"(try mounting with noload)");
				err = -EROFS;
				goto err_out;
			}
			pxt4_msg(sb, KERN_INFO, "write access will "
			       "be enabled during recovery");
		}
	}

	if (!(journal->j_flags & JBD3_BARRIER))
		pxt4_msg(sb, KERN_INFO, "barriers disabled");

	if (!pxt4_has_feature_journal_needs_recovery(sb))
		err = jbd3_journal_wipe(journal, !really_read_only);
	if (!err) {
		char *save = kmalloc(PXT4_S_ERR_LEN, GFP_KERNEL);
		if (save)
			memcpy(save, ((char *) es) +
			       PXT4_S_ERR_START, PXT4_S_ERR_LEN);
		err = jbd3_journal_load(journal);
		if (save)
			memcpy(((char *) es) + PXT4_S_ERR_START,
			       save, PXT4_S_ERR_LEN);
		kfree(save);
	}

	if (err) {
		pxt4_msg(sb, KERN_ERR, "error loading journal");
		goto err_out;
	}

	PXT4_SB(sb)->s_journal = journal;
	err = pxt4_clear_journal_err(sb, es);
	if (err) {
		PXT4_SB(sb)->s_journal = NULL;
		jbd3_journal_destroy(journal);
		return err;
	}

	if (!really_read_only && journal_devnum &&
	    journal_devnum != le32_to_cpu(es->s_journal_dev)) {
		es->s_journal_dev = cpu_to_le32(journal_devnum);

		/* Make sure we flush the recovery flag to disk. */
		pxt4_commit_super(sb, 1);
	}

	return 0;

err_out:
	jbd3_journal_destroy(journal);
	return err;
}

static int pxt4_commit_super(struct super_block *sb, int sync)
{
	struct pxt4_super_block *es = PXT4_SB(sb)->s_es;
	struct buffer_head *sbh = PXT4_SB(sb)->s_sbh;
	int error = 0;

	if (!sbh || block_device_ejected(sb))
		return error;

	/*
	 * If the file system is mounted read-only, don't update the
	 * superblock write time.  This avoids updating the superblock
	 * write time when we are mounting the root file system
	 * read/only but we need to replay the journal; at that point,
	 * for people who are east of GMT and who make their clock
	 * tick in localtime for Windows bug-for-bug compatibility,
	 * the clock is set in the future, and this will cause e2fsck
	 * to complain and force a full file system check.
	 */
	if (!(sb->s_flags & SB_RDONLY))
		pxt4_update_tstamp(es, s_wtime);
	if (sb->s_bdev->bd_part)
		es->s_kbytes_written =
			cpu_to_le64(PXT4_SB(sb)->s_kbytes_written +
			    ((part_stat_read(sb->s_bdev->bd_part,
					     sectors[STAT_WRITE]) -
			      PXT4_SB(sb)->s_sectors_written_start) >> 1));
	else
		es->s_kbytes_written =
			cpu_to_le64(PXT4_SB(sb)->s_kbytes_written);
	if (percpu_counter_initialized(&PXT4_SB(sb)->s_freeclusters_counter))
		pxt4_free_blocks_count_set(es,
			PXT4_C2B(PXT4_SB(sb), percpu_counter_sum_positive(
				&PXT4_SB(sb)->s_freeclusters_counter)));
	if (percpu_counter_initialized(&PXT4_SB(sb)->s_freeinodes_counter))
		es->s_free_inodes_count =
			cpu_to_le32(percpu_counter_sum_positive(
				&PXT4_SB(sb)->s_freeinodes_counter));
	BUFFER_TRACE(sbh, "marking dirty");
	pxt4_superblock_csum_set(sb);
	if (sync)
		lock_buffer(sbh);
	if (buffer_write_io_error(sbh) || !buffer_uptodate(sbh)) {
		/*
		 * Oh, dear.  A previous attempt to write the
		 * superblock failed.  This could happen because the
		 * USB device was yanked out.  Or it could happen to
		 * be a transient write error and maybe the block will
		 * be remapped.  Nothing we can do but to retry the
		 * write and hope for the best.
		 */
		pxt4_msg(sb, KERN_ERR, "previous I/O error to "
		       "superblock detected");
		clear_buffer_write_io_error(sbh);
		set_buffer_uptodate(sbh);
	}
	mark_buffer_dirty(sbh);
	if (sync) {
		unlock_buffer(sbh);
		error = __sync_dirty_buffer(sbh,
			REQ_SYNC | (test_opt(sb, BARRIER) ? REQ_FUA : 0));
		if (buffer_write_io_error(sbh)) {
			pxt4_msg(sb, KERN_ERR, "I/O error while writing "
			       "superblock");
			clear_buffer_write_io_error(sbh);
			set_buffer_uptodate(sbh);
		}
	}
	return error;
}

/*
 * Have we just finished recovery?  If so, and if we are mounting (or
 * remounting) the filesystem readonly, then we will end up with a
 * consistent fs on disk.  Record that fact.
 */
static int pxt4_mark_recovery_complete(struct super_block *sb,
				       struct pxt4_super_block *es)
{
	int err;
	journal_t *journal = PXT4_SB(sb)->s_journal;

	if (!pxt4_has_feature_journal(sb)) {
		if (journal != NULL) {
			pxt4_error(sb, "Journal got removed while the fs was "
				   "mounted!");
			return -EFSCORRUPTED;
		}
		return 0;
	}
	jbd3_journal_lock_updates(journal);
	err = jbd3_journal_flush(journal);
	if (err < 0)
		goto out;

	if (pxt4_has_feature_journal_needs_recovery(sb) && sb_rdonly(sb)) {
		pxt4_clear_feature_journal_needs_recovery(sb);
		pxt4_commit_super(sb, 1);
	}
out:
	jbd3_journal_unlock_updates(journal);
	return err;
}

/*
 * If we are mounting (or read-write remounting) a filesystem whose journal
 * has recorded an error from a previous lifetime, move that error to the
 * main filesystem now.
 */
static int pxt4_clear_journal_err(struct super_block *sb,
				   struct pxt4_super_block *es)
{
	journal_t *journal;
	int j_errno;
	const char *errstr;

	if (!pxt4_has_feature_journal(sb)) {
		pxt4_error(sb, "Journal got removed while the fs was mounted!");
		return -EFSCORRUPTED;
	}

	journal = PXT4_SB(sb)->s_journal;

	/*
	 * Now check for any error status which may have been recorded in the
	 * journal by a prior pxt4_error() or pxt4_abort()
	 */

	j_errno = jbd3_journal_errno(journal);
	if (j_errno) {
		char nbuf[16];

		errstr = pxt4_decode_error(sb, j_errno, nbuf);
		pxt4_warning(sb, "Filesystem error recorded "
			     "from previous mount: %s", errstr);
		pxt4_warning(sb, "Marking fs in need of filesystem check.");

		PXT4_SB(sb)->s_mount_state |= PXT4_ERROR_FS;
		es->s_state |= cpu_to_le16(PXT4_ERROR_FS);
		pxt4_commit_super(sb, 1);

		jbd3_journal_clear_err(journal);
		jbd3_journal_update_sb_errno(journal);
	}
	return 0;
}

/*
 * Force the running and committing transactions to commit,
 * and wait on the commit.
 */
int pxt4_force_commit(struct super_block *sb)
{
	journal_t *journal;

	if (sb_rdonly(sb))
		return 0;

	journal = PXT4_SB(sb)->s_journal;
	return pxt4_journal_force_commit(journal);
}

static int pxt4_sync_fs(struct super_block *sb, int wait)
{
	int ret = 0;
	tid_t target;
	bool needs_barrier = false;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);

	if (unlikely(pxt4_forced_shutdown(sbi)))
		return 0;

	trace_pxt4_sync_fs(sb, wait);
	flush_workqueue(sbi->rsv_conversion_wq);
	/*
	 * Writeback quota in non-journalled quota case - journalled quota has
	 * no dirty dquots
	 */
	dquot_writeback_dquots(sb, -1);
	/*
	 * Data writeback is possible w/o journal transaction, so barrier must
	 * being sent at the end of the function. But we can skip it if
	 * transaction_commit will do it for us.
	 */
	if (sbi->s_journal) {
		target = jbd3_get_latest_transaction(sbi->s_journal);
		if (wait && sbi->s_journal->j_flags & JBD3_BARRIER &&
		    !jbd3_trans_will_send_data_barrier(sbi->s_journal, target))
			needs_barrier = true;

		if (jbd3_journal_start_commit(sbi->s_journal, &target)) {
			if (wait)
				ret = jbd3_log_wait_commit(sbi->s_journal,
							   target);
		}
	} else if (wait && test_opt(sb, BARRIER))
		needs_barrier = true;
	if (needs_barrier) {
		int err;
		err = blkdev_issue_flush(sb->s_bdev, GFP_KERNEL, NULL);
		if (!ret)
			ret = err;
	}

	return ret;
}

/*
 * LVM calls this function before a (read-only) snapshot is created.  This
 * gives us a chance to flush the journal completely and mark the fs clean.
 *
 * Note that only this function cannot bring a filesystem to be in a clean
 * state independently. It relies on upper layer to stop all data & metadata
 * modifications.
 */
static int pxt4_freeze(struct super_block *sb)
{
	int error = 0;
	journal_t *journal;

	if (sb_rdonly(sb))
		return 0;

	journal = PXT4_SB(sb)->s_journal;

	if (journal) {
		/* Now we set up the journal barrier. */
		jbd3_journal_lock_updates(journal);

		/*
		 * Don't clear the needs_recovery flag if we failed to
		 * flush the journal.
		 */
		error = jbd3_journal_flush(journal);
		if (error < 0)
			goto out;

		/* Journal blocked and flushed, clear needs_recovery flag. */
		pxt4_clear_feature_journal_needs_recovery(sb);
	}

	error = pxt4_commit_super(sb, 1);
out:
	if (journal)
		/* we rely on upper layer to stop further updates */
		jbd3_journal_unlock_updates(journal);
	return error;
}

/*
 * Called by LVM after the snapshot is done.  We need to reset the RECOVER
 * flag here, even though the filesystem is not technically dirty yet.
 */
static int pxt4_unfreeze(struct super_block *sb)
{
	if (sb_rdonly(sb) || pxt4_forced_shutdown(PXT4_SB(sb)))
		return 0;

	if (PXT4_SB(sb)->s_journal) {
		/* Reset the needs_recovery flag before the fs is unlocked. */
		pxt4_set_feature_journal_needs_recovery(sb);
	}

	pxt4_commit_super(sb, 1);
	return 0;
}

/*
 * Structure to save mount options for pxt4_remount's benefit
 */
struct pxt4_mount_options {
	unsigned long s_mount_opt;
	unsigned long s_mount_opt2;
	kuid_t s_resuid;
	kgid_t s_resgid;
	unsigned long s_commit_interval;
	u32 s_min_batch_time, s_max_batch_time;
#ifdef CONFIG_QUOTA
	int s_jquota_fmt;
	char *s_qf_names[PXT4_MAXQUOTAS];
#endif
};

static int pxt4_remount(struct super_block *sb, int *flags, char *data)
{
	struct pxt4_super_block *es;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	unsigned long old_sb_flags, vfs_flags;
	struct pxt4_mount_options old_opts;
	int enable_quota = 0;
	pxt4_group_t g;
	unsigned int journal_ioprio = DEFAULT_JOURNAL_IOPRIO;
	int err = 0;
#ifdef CONFIG_QUOTA
	int i, j;
	char *to_free[PXT4_MAXQUOTAS];
#endif
	char *orig_data = kstrdup(data, GFP_KERNEL);

	if (data && !orig_data)
		return -ENOMEM;

	/* Store the original options */
	old_sb_flags = sb->s_flags;
	old_opts.s_mount_opt = sbi->s_mount_opt;
	old_opts.s_mount_opt2 = sbi->s_mount_opt2;
	old_opts.s_resuid = sbi->s_resuid;
	old_opts.s_resgid = sbi->s_resgid;
	old_opts.s_commit_interval = sbi->s_commit_interval;
	old_opts.s_min_batch_time = sbi->s_min_batch_time;
	old_opts.s_max_batch_time = sbi->s_max_batch_time;
#ifdef CONFIG_QUOTA
	old_opts.s_jquota_fmt = sbi->s_jquota_fmt;
	for (i = 0; i < PXT4_MAXQUOTAS; i++)
		if (sbi->s_qf_names[i]) {
			char *qf_name = get_qf_name(sb, sbi, i);

			old_opts.s_qf_names[i] = kstrdup(qf_name, GFP_KERNEL);
			if (!old_opts.s_qf_names[i]) {
				for (j = 0; j < i; j++)
					kfree(old_opts.s_qf_names[j]);
				kfree(orig_data);
				return -ENOMEM;
			}
		} else
			old_opts.s_qf_names[i] = NULL;
#endif
	if (sbi->s_journal && sbi->s_journal->j_task->io_context)
		journal_ioprio = sbi->s_journal->j_task->io_context->ioprio;

	/*
	 * Some options can be enabled by pxt4 and/or by VFS mount flag
	 * either way we need to make sure it matches in both *flags and
	 * s_flags. Copy those selected flags from *flags to s_flags
	 */
	vfs_flags = SB_LAZYTIME | SB_I_VERSION;
	sb->s_flags = (sb->s_flags & ~vfs_flags) | (*flags & vfs_flags);

	if (!parse_options(data, sb, NULL, &journal_ioprio, 1)) {
		err = -EINVAL;
		goto restore_opts;
	}

	if ((old_opts.s_mount_opt & PXT4_MOUNT_JOURNAL_CHECKSUM) ^
	    test_opt(sb, JOURNAL_CHECKSUM)) {
		pxt4_msg(sb, KERN_ERR, "changing journal_checksum "
			 "during remount not supported; ignoring");
		sbi->s_mount_opt ^= PXT4_MOUNT_JOURNAL_CHECKSUM;
	}

	if (test_opt(sb, DATA_FLAGS) == PXT4_MOUNT_JOURNAL_DATA) {
		if (test_opt2(sb, EXPLICIT_DELALLOC)) {
			pxt4_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and delalloc");
			err = -EINVAL;
			goto restore_opts;
		}
		if (test_opt(sb, DIOREAD_NOLOCK)) {
			pxt4_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and dioread_nolock");
			err = -EINVAL;
			goto restore_opts;
		}
	} else if (test_opt(sb, DATA_FLAGS) == PXT4_MOUNT_ORDERED_DATA) {
		if (test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
			pxt4_msg(sb, KERN_ERR, "can't mount with "
				"journal_async_commit in data=ordered mode");
			err = -EINVAL;
			goto restore_opts;
		}
	}

	if ((sbi->s_mount_opt ^ old_opts.s_mount_opt) & PXT4_MOUNT_NO_MBCACHE) {
		pxt4_msg(sb, KERN_ERR, "can't enable nombcache during remount");
		err = -EINVAL;
		goto restore_opts;
	}

	if (sbi->s_mount_flags & PXT4_MF_FS_ABORTED)
		pxt4_abort(sb, "Abort forced by user");

	sb->s_flags = (sb->s_flags & ~SB_POSIXACL) |
		(test_opt(sb, POSIX_ACL) ? SB_POSIXACL : 0);

	es = sbi->s_es;

	if (sbi->s_journal) {
		pxt4_init_journal_params(sb, sbi->s_journal);
		set_task_ioprio(sbi->s_journal->j_task, journal_ioprio);
	}

	if ((bool)(*flags & SB_RDONLY) != sb_rdonly(sb)) {
		if (sbi->s_mount_flags & PXT4_MF_FS_ABORTED) {
			err = -EROFS;
			goto restore_opts;
		}

		if (*flags & SB_RDONLY) {
			err = sync_filesystem(sb);
			if (err < 0)
				goto restore_opts;
			err = dquot_suspend(sb, -1);
			if (err < 0)
				goto restore_opts;

			/*
			 * First of all, the unconditional stuff we have to do
			 * to disable replay of the journal when we next remount
			 */
			sb->s_flags |= SB_RDONLY;

			/*
			 * OK, test if we are remounting a valid rw partition
			 * readonly, and if so set the rdonly flag and then
			 * mark the partition as valid again.
			 */
			if (!(es->s_state & cpu_to_le16(PXT4_VALID_FS)) &&
			    (sbi->s_mount_state & PXT4_VALID_FS))
				es->s_state = cpu_to_le16(sbi->s_mount_state);

			if (sbi->s_journal) {
				/*
				 * We let remount-ro finish even if marking fs
				 * as clean failed...
				 */
				pxt4_mark_recovery_complete(sb, es);
			}
			if (sbi->s_mmp_tsk)
				kthread_stop(sbi->s_mmp_tsk);
		} else {
			/* Make sure we can mount this feature set readwrite */
			if (pxt4_has_feature_readonly(sb) ||
			    !pxt4_feature_set_ok(sb, 0)) {
				err = -EROFS;
				goto restore_opts;
			}
			/*
			 * Make sure the group descriptor checksums
			 * are sane.  If they aren't, refuse to remount r/w.
			 */
			for (g = 0; g < sbi->s_groups_count; g++) {
				struct pxt4_group_desc *gdp =
					pxt4_get_group_desc(sb, g, NULL);

				if (!pxt4_group_desc_csum_verify(sb, g, gdp)) {
					pxt4_msg(sb, KERN_ERR,
	       "pxt4_remount: Checksum for group %u failed (%u!=%u)",
		g, le16_to_cpu(pxt4_group_desc_csum(sb, g, gdp)),
					       le16_to_cpu(gdp->bg_checksum));
					err = -EFSBADCRC;
					goto restore_opts;
				}
			}

			/*
			 * If we have an unprocessed orphan list hanging
			 * around from a previously readonly bdev mount,
			 * require a full umount/remount for now.
			 */
			if (es->s_last_orphan) {
				pxt4_msg(sb, KERN_WARNING, "Couldn't "
				       "remount RDWR because of unprocessed "
				       "orphan inode list.  Please "
				       "umount/remount instead");
				err = -EINVAL;
				goto restore_opts;
			}

			/*
			 * Mounting a RDONLY partition read-write, so reread
			 * and store the current valid flag.  (It may have
			 * been changed by e2fsck since we originally mounted
			 * the partition.)
			 */
			if (sbi->s_journal) {
				err = pxt4_clear_journal_err(sb, es);
				if (err)
					goto restore_opts;
			}
			sbi->s_mount_state = le16_to_cpu(es->s_state);

			err = pxt4_setup_super(sb, es, 0);
			if (err)
				goto restore_opts;

			sb->s_flags &= ~SB_RDONLY;
			if (pxt4_has_feature_mmp(sb))
				if (pxt4_multi_mount_protect(sb,
						le64_to_cpu(es->s_mmp_block))) {
					err = -EROFS;
					goto restore_opts;
				}
			enable_quota = 1;
		}
	}

	/*
	 * Reinitialize lazy itable initialization thread based on
	 * current settings
	 */
	if (sb_rdonly(sb) || !test_opt(sb, INIT_INODE_TABLE))
		pxt4_unregister_li_request(sb);
	else {
		pxt4_group_t first_not_zeroed;
		first_not_zeroed = pxt4_has_uninit_itable(sb);
		pxt4_register_li_request(sb, first_not_zeroed);
	}

	/*
	 * Handle creation of system zone data early because it can fail.
	 * Releasing of existing data is done when we are sure remount will
	 * succeed.
	 */
	if (test_opt(sb, BLOCK_VALIDITY) && !sbi->system_blks) {
		err = pxt4_setup_system_zone(sb);
		if (err)
			goto restore_opts;
	}

	if (sbi->s_journal == NULL && !(old_sb_flags & SB_RDONLY)) {
		err = pxt4_commit_super(sb, 1);
		if (err)
			goto restore_opts;
	}

#ifdef CONFIG_QUOTA
	/* Release old quota file names */
	for (i = 0; i < PXT4_MAXQUOTAS; i++)
		kfree(old_opts.s_qf_names[i]);
	if (enable_quota) {
		if (sb_any_quota_suspended(sb))
			dquot_resume(sb, -1);
		else if (pxt4_has_feature_quota(sb)) {
			err = pxt4_enable_quotas(sb);
			if (err)
				goto restore_opts;
		}
	}
#endif
	if (!test_opt(sb, BLOCK_VALIDITY) && sbi->system_blks)
		pxt4_release_system_zone(sb);

	/*
	 * Some options can be enabled by pxt4 and/or by VFS mount flag
	 * either way we need to make sure it matches in both *flags and
	 * s_flags. Copy those selected flags from s_flags to *flags
	 */
	*flags = (*flags & ~vfs_flags) | (sb->s_flags & vfs_flags);

	pxt4_msg(sb, KERN_INFO, "re-mounted. Opts: %s", orig_data);
	kfree(orig_data);
	return 0;

restore_opts:
	sb->s_flags = old_sb_flags;
	sbi->s_mount_opt = old_opts.s_mount_opt;
	sbi->s_mount_opt2 = old_opts.s_mount_opt2;
	sbi->s_resuid = old_opts.s_resuid;
	sbi->s_resgid = old_opts.s_resgid;
	sbi->s_commit_interval = old_opts.s_commit_interval;
	sbi->s_min_batch_time = old_opts.s_min_batch_time;
	sbi->s_max_batch_time = old_opts.s_max_batch_time;
	if (!test_opt(sb, BLOCK_VALIDITY) && sbi->system_blks)
		pxt4_release_system_zone(sb);
#ifdef CONFIG_QUOTA
	sbi->s_jquota_fmt = old_opts.s_jquota_fmt;
	for (i = 0; i < PXT4_MAXQUOTAS; i++) {
		to_free[i] = get_qf_name(sb, sbi, i);
		rcu_assign_pointer(sbi->s_qf_names[i], old_opts.s_qf_names[i]);
	}
	synchronize_rcu();
	for (i = 0; i < PXT4_MAXQUOTAS; i++)
		kfree(to_free[i]);
#endif
	kfree(orig_data);
	return err;
}

#ifdef CONFIG_QUOTA
static int pxt4_statfs_project(struct super_block *sb,
			       kprojid_t projid, struct kstatfs *buf)
{
	struct kqid qid;
	struct dquot *dquot;
	u64 limit;
	u64 curblock;

	qid = make_kqid_projid(projid);
	dquot = dqget(sb, qid);
	if (IS_ERR(dquot))
		return PTR_ERR(dquot);
	spin_lock(&dquot->dq_dqb_lock);

	limit = 0;
	if (dquot->dq_dqb.dqb_bsoftlimit &&
	    (!limit || dquot->dq_dqb.dqb_bsoftlimit < limit))
		limit = dquot->dq_dqb.dqb_bsoftlimit;
	if (dquot->dq_dqb.dqb_bhardlimit &&
	    (!limit || dquot->dq_dqb.dqb_bhardlimit < limit))
		limit = dquot->dq_dqb.dqb_bhardlimit;
	limit >>= sb->s_blocksize_bits;

	if (limit && buf->f_blocks > limit) {
		curblock = (dquot->dq_dqb.dqb_curspace +
			    dquot->dq_dqb.dqb_rsvspace) >> sb->s_blocksize_bits;
		buf->f_blocks = limit;
		buf->f_bfree = buf->f_bavail =
			(buf->f_blocks > curblock) ?
			 (buf->f_blocks - curblock) : 0;
	}

	limit = 0;
	if (dquot->dq_dqb.dqb_isoftlimit &&
	    (!limit || dquot->dq_dqb.dqb_isoftlimit < limit))
		limit = dquot->dq_dqb.dqb_isoftlimit;
	if (dquot->dq_dqb.dqb_ihardlimit &&
	    (!limit || dquot->dq_dqb.dqb_ihardlimit < limit))
		limit = dquot->dq_dqb.dqb_ihardlimit;

	if (limit && buf->f_files > limit) {
		buf->f_files = limit;
		buf->f_ffree =
			(buf->f_files > dquot->dq_dqb.dqb_curinodes) ?
			 (buf->f_files - dquot->dq_dqb.dqb_curinodes) : 0;
	}

	spin_unlock(&dquot->dq_dqb_lock);
	dqput(dquot);
	return 0;
}
#endif

static int pxt4_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_super_block *es = sbi->s_es;
	pxt4_fsblk_t overhead = 0, resv_blocks;
	u64 fsid;
	s64 bfree;
	resv_blocks = PXT4_C2B(sbi, atomic64_read(&sbi->s_resv_clusters));

	if (!test_opt(sb, MINIX_DF))
		overhead = sbi->s_overhead;

	buf->f_type = PXT4_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = pxt4_blocks_count(es) - PXT4_C2B(sbi, overhead);
	bfree = percpu_counter_sum_positive(&sbi->s_freeclusters_counter) -
		percpu_counter_sum_positive(&sbi->s_dirtyclusters_counter);
	/* prevent underflow in case that few free space is available */
	buf->f_bfree = PXT4_C2B(sbi, max_t(s64, bfree, 0));
	buf->f_bavail = buf->f_bfree -
			(pxt4_r_blocks_count(es) + resv_blocks);
	if (buf->f_bfree < (pxt4_r_blocks_count(es) + resv_blocks))
		buf->f_bavail = 0;
	buf->f_files = le32_to_cpu(es->s_inodes_count);
	buf->f_ffree = percpu_counter_sum_positive(&sbi->s_freeinodes_counter);
	buf->f_namelen = PXT4_NAME_LEN;
	fsid = le64_to_cpup((void *)es->s_uuid) ^
	       le64_to_cpup((void *)es->s_uuid + sizeof(u64));
	buf->f_fsid.val[0] = fsid & 0xFFFFFFFFUL;
	buf->f_fsid.val[1] = (fsid >> 32) & 0xFFFFFFFFUL;

#ifdef CONFIG_QUOTA
	if (pxt4_test_inode_flag(dentry->d_inode, PXT4_INODE_PROJINHERIT) &&
	    sb_has_quota_limits_enabled(sb, PRJQUOTA))
		pxt4_statfs_project(sb, PXT4_I(dentry->d_inode)->i_projid, buf);
#endif
	return 0;
}


#ifdef CONFIG_QUOTA

/*
 * Helper functions so that transaction is started before we acquire dqio_sem
 * to keep correct lock ordering of transaction > dqio_sem
 */
static inline struct inode *dquot_to_inode(struct dquot *dquot)
{
	return sb_dqopt(dquot->dq_sb)->files[dquot->dq_id.type];
}

static int pxt4_write_dquot(struct dquot *dquot)
{
	int ret, err;
	handle_t *handle;
	struct inode *inode;

	inode = dquot_to_inode(dquot);
	handle = pxt4_journal_start(inode, PXT4_HT_QUOTA,
				    PXT4_QUOTA_TRANS_BLOCKS(dquot->dq_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = dquot_commit(dquot);
	err = pxt4_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

static int pxt4_acquire_dquot(struct dquot *dquot)
{
	int ret, err;
	handle_t *handle;

	handle = pxt4_journal_start(dquot_to_inode(dquot), PXT4_HT_QUOTA,
				    PXT4_QUOTA_INIT_BLOCKS(dquot->dq_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = dquot_acquire(dquot);
	err = pxt4_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

static int pxt4_release_dquot(struct dquot *dquot)
{
	int ret, err;
	handle_t *handle;

	handle = pxt4_journal_start(dquot_to_inode(dquot), PXT4_HT_QUOTA,
				    PXT4_QUOTA_DEL_BLOCKS(dquot->dq_sb));
	if (IS_ERR(handle)) {
		/* Release dquot anyway to avoid endless cycle in dqput() */
		dquot_release(dquot);
		return PTR_ERR(handle);
	}
	ret = dquot_release(dquot);
	err = pxt4_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

static int pxt4_mark_dquot_dirty(struct dquot *dquot)
{
	struct super_block *sb = dquot->dq_sb;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);

	/* Are we journaling quotas? */
	if (pxt4_has_feature_quota(sb) ||
	    sbi->s_qf_names[USRQUOTA] || sbi->s_qf_names[GRPQUOTA]) {
		dquot_mark_dquot_dirty(dquot);
		return pxt4_write_dquot(dquot);
	} else {
		return dquot_mark_dquot_dirty(dquot);
	}
}

static int pxt4_write_info(struct super_block *sb, int type)
{
	int ret, err;
	handle_t *handle;

	/* Data block + inode block */
	handle = pxt4_journal_start(d_inode(sb->s_root), PXT4_HT_QUOTA, 2);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = dquot_commit_info(sb, type);
	err = pxt4_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

/*
 * Turn on quotas during mount time - we need to find
 * the quota file and such...
 */
static int pxt4_quota_on_mount(struct super_block *sb, int type)
{
	return dquot_quota_on_mount(sb, get_qf_name(sb, PXT4_SB(sb), type),
					PXT4_SB(sb)->s_jquota_fmt, type);
}

static void lockdep_set_quota_inode(struct inode *inode, int subclass)
{
	struct pxt4_inode_info *ei = PXT4_I(inode);

	/* The first argument of lockdep_set_subclass has to be
	 * *exactly* the same as the argument to init_rwsem() --- in
	 * this case, in init_once() --- or lockdep gets unhappy
	 * because the name of the lock is set using the
	 * stringification of the argument to init_rwsem().
	 */
	(void) ei;	/* shut up clang warning if !CONFIG_LOCKDEP */
	lockdep_set_subclass(&ei->i_data_sem, subclass);
}

/*
 * Standard function to be called on quota_on
 */
static int pxt4_quota_on(struct super_block *sb, int type, int format_id,
			 const struct path *path)
{
	int err;

	if (!test_opt(sb, QUOTA))
		return -EINVAL;

	/* Quotafile not on the same filesystem? */
	if (path->dentry->d_sb != sb)
		return -EXDEV;
	/* Journaling quota? */
	if (PXT4_SB(sb)->s_qf_names[type]) {
		/* Quotafile not in fs root? */
		if (path->dentry->d_parent != sb->s_root)
			pxt4_msg(sb, KERN_WARNING,
				"Quota file not on filesystem root. "
				"Journaled quota will not work");
		sb_dqopt(sb)->flags |= DQUOT_NOLIST_DIRTY;
	} else {
		/*
		 * Clear the flag just in case mount options changed since
		 * last time.
		 */
		sb_dqopt(sb)->flags &= ~DQUOT_NOLIST_DIRTY;
	}

	/*
	 * When we journal data on quota file, we have to flush journal to see
	 * all updates to the file when we bypass pagecache...
	 */
	if (PXT4_SB(sb)->s_journal &&
	    pxt4_should_journal_data(d_inode(path->dentry))) {
		/*
		 * We don't need to lock updates but journal_flush() could
		 * otherwise be livelocked...
		 */
		jbd3_journal_lock_updates(PXT4_SB(sb)->s_journal);
		err = jbd3_journal_flush(PXT4_SB(sb)->s_journal);
		jbd3_journal_unlock_updates(PXT4_SB(sb)->s_journal);
		if (err)
			return err;
	}

	lockdep_set_quota_inode(path->dentry->d_inode, I_DATA_SEM_QUOTA);
	err = dquot_quota_on(sb, type, format_id, path);
	if (err) {
		lockdep_set_quota_inode(path->dentry->d_inode,
					     I_DATA_SEM_NORMAL);
	} else {
		struct inode *inode = d_inode(path->dentry);
		handle_t *handle;

		/*
		 * Set inode flags to prevent userspace from messing with quota
		 * files. If this fails, we return success anyway since quotas
		 * are already enabled and this is not a hard failure.
		 */
		inode_lock(inode);
		handle = pxt4_journal_start(inode, PXT4_HT_QUOTA, 1);
		if (IS_ERR(handle))
			goto unlock_inode;
		PXT4_I(inode)->i_flags |= PXT4_NOATIME_FL | PXT4_IMMUTABLE_FL;
		inode_set_flags(inode, S_NOATIME | S_IMMUTABLE,
				S_NOATIME | S_IMMUTABLE);
		pxt4_mark_inode_dirty(handle, inode);
		pxt4_journal_stop(handle);
	unlock_inode:
		inode_unlock(inode);
	}
	return err;
}

static int pxt4_quota_enable(struct super_block *sb, int type, int format_id,
			     unsigned int flags)
{
	int err;
	struct inode *qf_inode;
	unsigned long qf_inums[PXT4_MAXQUOTAS] = {
		le32_to_cpu(PXT4_SB(sb)->s_es->s_usr_quota_inum),
		le32_to_cpu(PXT4_SB(sb)->s_es->s_grp_quota_inum),
		le32_to_cpu(PXT4_SB(sb)->s_es->s_prj_quota_inum)
	};

	BUG_ON(!pxt4_has_feature_quota(sb));

	if (!qf_inums[type])
		return -EPERM;

	qf_inode = pxt4_iget(sb, qf_inums[type], PXT4_IGET_SPECIAL);
	if (IS_ERR(qf_inode)) {
		pxt4_error(sb, "Bad quota inode # %lu", qf_inums[type]);
		return PTR_ERR(qf_inode);
	}

	/* Don't account quota for quota files to avoid recursion */
	qf_inode->i_flags |= S_NOQUOTA;
	lockdep_set_quota_inode(qf_inode, I_DATA_SEM_QUOTA);
	err = dquot_enable(qf_inode, type, format_id, flags);
	if (err)
		lockdep_set_quota_inode(qf_inode, I_DATA_SEM_NORMAL);
	iput(qf_inode);

	return err;
}

/* Enable usage tracking for all quota types. */
static int pxt4_enable_quotas(struct super_block *sb)
{
	int type, err = 0;
	unsigned long qf_inums[PXT4_MAXQUOTAS] = {
		le32_to_cpu(PXT4_SB(sb)->s_es->s_usr_quota_inum),
		le32_to_cpu(PXT4_SB(sb)->s_es->s_grp_quota_inum),
		le32_to_cpu(PXT4_SB(sb)->s_es->s_prj_quota_inum)
	};
	bool quota_mopt[PXT4_MAXQUOTAS] = {
		test_opt(sb, USRQUOTA),
		test_opt(sb, GRPQUOTA),
		test_opt(sb, PRJQUOTA),
	};

	sb_dqopt(sb)->flags |= DQUOT_QUOTA_SYS_FILE | DQUOT_NOLIST_DIRTY;
	for (type = 0; type < PXT4_MAXQUOTAS; type++) {
		if (qf_inums[type]) {
			err = pxt4_quota_enable(sb, type, QFMT_VFS_V1,
				DQUOT_USAGE_ENABLED |
				(quota_mopt[type] ? DQUOT_LIMITS_ENABLED : 0));
			if (err) {
				pxt4_warning(sb,
					"Failed to enable quota tracking "
					"(type=%d, err=%d). Please run "
					"e2fsck to fix.", type, err);
				for (type--; type >= 0; type--)
					dquot_quota_off(sb, type);

				return err;
			}
		}
	}
	return 0;
}

static int pxt4_quota_off(struct super_block *sb, int type)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	handle_t *handle;
	int err;

	/* Force all delayed allocation blocks to be allocated.
	 * Caller already holds s_umount sem */
	if (test_opt(sb, DELALLOC))
		sync_filesystem(sb);

	if (!inode || !igrab(inode))
		goto out;

	err = dquot_quota_off(sb, type);
	if (err || pxt4_has_feature_quota(sb))
		goto out_put;

	inode_lock(inode);
	/*
	 * Update modification times of quota files when userspace can
	 * start looking at them. If we fail, we return success anyway since
	 * this is not a hard failure and quotas are already disabled.
	 */
	handle = pxt4_journal_start(inode, PXT4_HT_QUOTA, 1);
	if (IS_ERR(handle))
		goto out_unlock;
	PXT4_I(inode)->i_flags &= ~(PXT4_NOATIME_FL | PXT4_IMMUTABLE_FL);
	inode_set_flags(inode, 0, S_NOATIME | S_IMMUTABLE);
	inode->i_mtime = inode->i_ctime = current_time(inode);
	pxt4_mark_inode_dirty(handle, inode);
	pxt4_journal_stop(handle);
out_unlock:
	inode_unlock(inode);
out_put:
	lockdep_set_quota_inode(inode, I_DATA_SEM_NORMAL);
	iput(inode);
	return err;
out:
	return dquot_quota_off(sb, type);
}

/* Read data from quotafile - avoid pagecache and such because we cannot afford
 * acquiring the locks... As quota files are never truncated and quota code
 * itself serializes the operations (and no one else should touch the files)
 * we don't have to be afraid of races */
static ssize_t pxt4_quota_read(struct super_block *sb, int type, char *data,
			       size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	pxt4_lblk_t blk = off >> PXT4_BLOCK_SIZE_BITS(sb);
	int offset = off & (sb->s_blocksize - 1);
	int tocopy;
	size_t toread;
	struct buffer_head *bh;
	loff_t i_size = i_size_read(inode);

	if (off > i_size)
		return 0;
	if (off+len > i_size)
		len = i_size-off;
	toread = len;
	while (toread > 0) {
		tocopy = sb->s_blocksize - offset < toread ?
				sb->s_blocksize - offset : toread;
		bh = pxt4_bread(NULL, inode, blk, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		if (!bh)	/* A hole? */
			memset(data, 0, tocopy);
		else
			memcpy(data, bh->b_data+offset, tocopy);
		brelse(bh);
		offset = 0;
		toread -= tocopy;
		data += tocopy;
		blk++;
	}
	return len;
}

/* Write to quotafile (we know the transaction is already started and has
 * enough credits) */
static ssize_t pxt4_quota_write(struct super_block *sb, int type,
				const char *data, size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	pxt4_lblk_t blk = off >> PXT4_BLOCK_SIZE_BITS(sb);
	int err, offset = off & (sb->s_blocksize - 1);
	int retries = 0;
	struct buffer_head *bh;
	handle_t *handle = journal_current_handle();

	if (PXT4_SB(sb)->s_journal && !handle) {
		pxt4_msg(sb, KERN_WARNING, "Quota write (off=%llu, len=%llu)"
			" cancelled because transaction is not started",
			(unsigned long long)off, (unsigned long long)len);
		return -EIO;
	}
	/*
	 * Since we account only one data block in transaction credits,
	 * then it is impossible to cross a block boundary.
	 */
	if (sb->s_blocksize - offset < len) {
		pxt4_msg(sb, KERN_WARNING, "Quota write (off=%llu, len=%llu)"
			" cancelled because not block aligned",
			(unsigned long long)off, (unsigned long long)len);
		return -EIO;
	}

	do {
		bh = pxt4_bread(handle, inode, blk,
				PXT4_GET_BLOCKS_CREATE |
				PXT4_GET_BLOCKS_METADATA_NOFAIL);
	} while (IS_ERR(bh) && (PTR_ERR(bh) == -ENOSPC) &&
		 pxt4_should_retry_alloc(inode->i_sb, &retries));
	if (IS_ERR(bh))
		return PTR_ERR(bh);
	if (!bh)
		goto out;
	BUFFER_TRACE(bh, "get write access");
	err = pxt4_journal_get_write_access(handle, bh);
	if (err) {
		brelse(bh);
		return err;
	}
	lock_buffer(bh);
	memcpy(bh->b_data+offset, data, len);
	flush_dcache_page(bh->b_page);
	unlock_buffer(bh);
	err = pxt4_handle_dirty_metadata(handle, NULL, bh);
	brelse(bh);
out:
	if (inode->i_size < off + len) {
		i_size_write(inode, off + len);
		PXT4_I(inode)->i_disksize = inode->i_size;
		pxt4_mark_inode_dirty(handle, inode);
	}
	return len;
}

static int pxt4_get_next_id(struct super_block *sb, struct kqid *qid)
{
	const struct quota_format_ops	*ops;

	if (!sb_has_quota_loaded(sb, qid->type))
		return -ESRCH;
	ops = sb_dqopt(sb)->ops[qid->type];
	if (!ops || !ops->get_next_id)
		return -ENOSYS;
	return dquot_get_next_id(sb, qid);
}
#endif

static struct dentry *pxt4_mount(struct file_system_type *fs_type, int flags,
		       const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, pxt4_fill_super);
}

#if !defined(CONFIG_PXT2_FS) && !defined(CONFIG_PXT2_FS_MODULE) && defined(CONFIG_PXT4_USE_FOR_PXT2)
static inline void register_as_pxt2(void)
{
	int err = register_filesystem(&pxt2_fs_type);
	if (err)
		printk(KERN_WARNING
		       "PXT4-fs: Unable to register as pxt2 (%d)\n", err);
}

static inline void unregister_as_pxt2(void)
{
	unregister_filesystem(&pxt2_fs_type);
}

static inline int pxt2_feature_set_ok(struct super_block *sb)
{
	if (pxt4_has_unknown_pxt2_incompat_features(sb))
		return 0;
	if (sb_rdonly(sb))
		return 1;
	if (pxt4_has_unknown_pxt2_ro_compat_features(sb))
		return 0;
	return 1;
}
#else
static inline void register_as_pxt2(void) { }
static inline void unregister_as_pxt2(void) { }
static inline int pxt2_feature_set_ok(struct super_block *sb) { return 0; }
#endif

static inline void register_as_ext3(void)
{
	int err = register_filesystem(&ext3_fs_type);
	if (err)
		printk(KERN_WARNING
		       "PXT4-fs: Unable to register as ext3 (%d)\n", err);
}

static inline void unregister_as_ext3(void)
{
	unregister_filesystem(&ext3_fs_type);
}

static inline int ext3_feature_set_ok(struct super_block *sb)
{
	if (pxt4_has_unknown_ext3_incompat_features(sb))
		return 0;
	if (!pxt4_has_feature_journal(sb))
		return 0;
	if (sb_rdonly(sb))
		return 1;
	if (pxt4_has_unknown_ext3_ro_compat_features(sb))
		return 0;
	return 1;
}

static struct file_system_type pxt4_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "pxt4",
	.mount		= pxt4_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("pxt4");

/* Shared across all pxt4 file systems */
wait_queue_head_t pxt4__ioend_wq[PXT4_WQ_HASH_SZ];

static int __init pxt4_init_fs(void)
{
	int i, err;

	ratelimit_state_init(&pxt4_mount_msg_ratelimit, 30 * HZ, 64);
	pxt4_li_info = NULL;
	mutex_init(&pxt4_li_mtx);

	/* Build-time check for flags consistency */
	pxt4_check_flag_values();

	for (i = 0; i < PXT4_WQ_HASH_SZ; i++)
		init_waitqueue_head(&pxt4__ioend_wq[i]);

	err = pxt4_init_es();
	if (err)
		return err;

	err = pxt4_init_pending();
	if (err)
		goto out7;

	err = pxt4_init_post_read_processing();
	if (err)
		goto out6;

	err = pxt4_init_pageio();
	if (err)
		goto out5;

	err = pxt4_init_system_zone();
	if (err)
		goto out4;

	err = pxt4_init_sysfs();
	if (err)
		goto out3;

	err = pxt4_init_mballoc();
	if (err)
		goto out2;
	err = init_inodecache();
	if (err)
		goto out1;
	register_as_ext3();
	register_as_pxt2();
	err = register_filesystem(&pxt4_fs_type);
	if (err)
		goto out;

	return 0;
out:
	unregister_as_pxt2();
	unregister_as_ext3();
	destroy_inodecache();
out1:
	pxt4_exit_mballoc();
out2:
	pxt4_exit_sysfs();
out3:
	pxt4_exit_system_zone();
out4:
	pxt4_exit_pageio();
out5:
	pxt4_exit_post_read_processing();
out6:
	pxt4_exit_pending();
out7:
	pxt4_exit_es();

	return err;
}

static void __exit pxt4_exit_fs(void)
{
	pxt4_destroy_lazyinit_thread();
	unregister_as_pxt2();
	unregister_as_ext3();
	unregister_filesystem(&pxt4_fs_type);
	destroy_inodecache();
	pxt4_exit_mballoc();
	pxt4_exit_sysfs();
	pxt4_exit_system_zone();
	pxt4_exit_pageio();
	pxt4_exit_post_read_processing();
	pxt4_exit_es();
	pxt4_exit_pending();
}

MODULE_AUTHOR("Remy Card, Stephen Tweedie, Andrew Morton, Andreas Dilger, Theodore Ts'o and others");
MODULE_DESCRIPTION("Fourth Extended Filesystem");
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: crc32c");
module_init(pxt4_init_fs)
module_exit(pxt4_exit_fs)
