// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/pxt4/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  pxt4 fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *	(jj@sunsite.ms.mff.cuni.cz)
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/dax.h>
#include <linux/quotaops.h>
#include <linux/pagevec.h>
#include <linux/uio.h>
#include <linux/mman.h>
#include "pxt4.h"
#include "pxt4_jbd3.h"
#include "xattr.h"
#include "acl.h"

#ifdef CONFIG_FS_DAX
static ssize_t pxt4_dax_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock_shared(inode))
			return -EAGAIN;
	} else {
		inode_lock_shared(inode);
	}
	/*
	 * Recheck under inode lock - at this point we are sure it cannot
	 * change anymore
	 */
	if (!IS_DAX(inode)) {
		inode_unlock_shared(inode);
		/* Fallback to buffered IO in case we cannot support DAX */
		return generic_file_read_iter(iocb, to);
	}
	ret = dax_iomap_rw(iocb, to, &pxt4_iomap_ops);
	inode_unlock_shared(inode);

	file_accessed(iocb->ki_filp);
	return ret;
}
#endif

static ssize_t pxt4_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	if (unlikely(pxt4_forced_shutdown(PXT4_SB(file_inode(iocb->ki_filp)->i_sb))))
		return -EIO;

	if (!iov_iter_count(to))
		return 0; /* skip atime */

#ifdef CONFIG_FS_DAX
	if (IS_DAX(file_inode(iocb->ki_filp)))
		return pxt4_dax_read_iter(iocb, to);
#endif
	return generic_file_read_iter(iocb, to);
}

/*
 * Called when an inode is released. Note that this is different
 * from pxt4_file_open: open gets called at every open, but release
 * gets called only when /all/ the files are closed.
 */
static int pxt4_release_file(struct inode *inode, struct file *filp)
{
	if (pxt4_test_inode_state(inode, PXT4_STATE_DA_ALLOC_CLOSE)) {
		pxt4_alloc_da_blocks(inode);
		pxt4_clear_inode_state(inode, PXT4_STATE_DA_ALLOC_CLOSE);
	}
	/* if we are the last writer on the inode, drop the block reservation */
	if ((filp->f_mode & FMODE_WRITE) &&
			(atomic_read(&inode->i_writecount) == 1) &&
		        !PXT4_I(inode)->i_reserved_data_blocks)
	{
		down_write(&PXT4_I(inode)->i_data_sem);
		pxt4_discard_preallocations(inode);
		up_write(&PXT4_I(inode)->i_data_sem);
	}
	if (is_dx(inode) && filp->private_data)
		pxt4_htree_free_dir_info(filp->private_data);

	return 0;
}

static void pxt4_unwritten_wait(struct inode *inode)
{
	wait_queue_head_t *wq = pxt4_ioend_wq(inode);

	wait_event(*wq, (atomic_read(&PXT4_I(inode)->i_unwritten) == 0));
}

/*
 * This tests whether the IO in question is block-aligned or not.
 * Ext4 utilizes unwritten extents when hole-filling during direct IO, and they
 * are converted to written only after the IO is complete.  Until they are
 * mapped, these blocks appear as holes, so dio_zero_block() will assume that
 * it needs to zero out portions of the start and/or end block.  If 2 AIO
 * threads are at work on the same unwritten block, they must be synchronized
 * or one thread will zero the other's data, causing corruption.
 */
static int
pxt4_unaligned_aio(struct inode *inode, struct iov_iter *from, loff_t pos)
{
	struct super_block *sb = inode->i_sb;
	int blockmask = sb->s_blocksize - 1;

	if (pos >= ALIGN(i_size_read(inode), sb->s_blocksize))
		return 0;

	if ((pos | iov_iter_alignment(from)) & blockmask)
		return 1;

	return 0;
}

/* Is IO overwriting allocated and initialized blocks? */
static bool pxt4_overwrite_io(struct inode *inode, loff_t pos, loff_t len)
{
	struct pxt4_map_blocks map;
	unsigned int blkbits = inode->i_blkbits;
	int err, blklen;

	if (pos + len > i_size_read(inode))
		return false;

	map.m_lblk = pos >> blkbits;
	map.m_len = PXT4_MAX_BLOCKS(len, pos, blkbits);
	blklen = map.m_len;

	err = pxt4_map_blocks(NULL, inode, &map, 0);
	/*
	 * 'err==len' means that all of the blocks have been preallocated,
	 * regardless of whether they have been initialized or not. To exclude
	 * unwritten extents, we need to check m_flags.
	 */
	return err == blklen && (map.m_flags & PXT4_MAP_MAPPED);
}

static ssize_t pxt4_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		return ret;

	if (unlikely(IS_IMMUTABLE(inode)))
		return -EPERM;

	/*
	 * If we have encountered a bitmap-format file, the size limit
	 * is smaller than s_maxbytes, which is for extent-mapped files.
	 */
	if (!(pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS))) {
		struct pxt4_sb_info *sbi = PXT4_SB(inode->i_sb);

		if (iocb->ki_pos >= sbi->s_bitmap_maxbytes)
			return -EFBIG;
		iov_iter_truncate(from, sbi->s_bitmap_maxbytes - iocb->ki_pos);
	}
	return iov_iter_count(from);
}

#ifdef CONFIG_FS_DAX
static ssize_t
pxt4_dax_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock(inode))
			return -EAGAIN;
	} else {
		inode_lock(inode);
	}
	ret = pxt4_write_checks(iocb, from);
	if (ret <= 0)
		goto out;
	ret = file_remove_privs(iocb->ki_filp);
	if (ret)
		goto out;
	ret = file_update_time(iocb->ki_filp);
	if (ret)
		goto out;

	ret = dax_iomap_rw(iocb, from, &pxt4_iomap_ops);
out:
	inode_unlock(inode);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
}
#endif

static ssize_t
pxt4_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	int o_direct = iocb->ki_flags & IOCB_DIRECT;
	int unaligned_aio = 0;
	int overwrite = 0;
	ssize_t ret;

	if (unlikely(pxt4_forced_shutdown(PXT4_SB(inode->i_sb))))
		return -EIO;

#ifdef CONFIG_FS_DAX
	if (IS_DAX(inode))
		return pxt4_dax_write_iter(iocb, from);
#endif

	if (!inode_trylock(inode)) {
		if (iocb->ki_flags & IOCB_NOWAIT)
			return -EAGAIN;
		inode_lock(inode);
	}

	ret = pxt4_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	/*
	 * Unaligned direct AIO must be serialized among each other as zeroing
	 * of partial blocks of two competing unaligned AIOs can result in data
	 * corruption.
	 */
	if (o_direct && pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS) &&
	    !is_sync_kiocb(iocb) &&
	    pxt4_unaligned_aio(inode, from, iocb->ki_pos)) {
		unaligned_aio = 1;
		pxt4_unwritten_wait(inode);
	}

	iocb->private = &overwrite;
	/* Check whether we do a DIO overwrite or not */
	if (o_direct && !unaligned_aio) {
		if (pxt4_overwrite_io(inode, iocb->ki_pos, iov_iter_count(from))) {
			if (pxt4_should_dioread_nolock(inode))
				overwrite = 1;
		} else if (iocb->ki_flags & IOCB_NOWAIT) {
			ret = -EAGAIN;
			goto out;
		}
	}

	ret = __generic_file_write_iter(iocb, from);
	/*
	 * Unaligned direct AIO must be the only IO in flight. Otherwise
	 * overlapping aligned IO after unaligned might result in data
	 * corruption.
	 */
	if (ret == -EIOCBQUEUED && unaligned_aio)
		pxt4_unwritten_wait(inode);
	inode_unlock(inode);

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);

	return ret;

out:
	inode_unlock(inode);
	return ret;
}

#ifdef CONFIG_FS_DAX
static vm_fault_t pxt4_dax_huge_fault(struct vm_fault *vmf,
		enum page_entry_size pe_size)
{
	int error = 0;
	vm_fault_t result;
	int retries = 0;
	handle_t *handle = NULL;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct super_block *sb = inode->i_sb;

	/*
	 * We have to distinguish real writes from writes which will result in a
	 * COW page; COW writes should *not* poke the journal (the file will not
	 * be changed). Doing so would cause unintended failures when mounted
	 * read-only.
	 *
	 * We check for VM_SHARED rather than vmf->cow_page since the latter is
	 * unset for pe_size != PE_SIZE_PTE (i.e. only in do_cow_fault); for
	 * other sizes, dax_iomap_fault will handle splitting / fallback so that
	 * we eventually come back with a COW page.
	 */
	bool write = (vmf->flags & FAULT_FLAG_WRITE) &&
		(vmf->vma->vm_flags & VM_SHARED);
	pfn_t pfn;

	if (write) {
		sb_start_pagefault(sb);
		file_update_time(vmf->vma->vm_file);
		down_read(&PXT4_I(inode)->i_mmap_sem);
retry:
		handle = pxt4_journal_start_sb(sb, PXT4_HT_WRITE_PAGE,
					       PXT4_DATA_TRANS_BLOCKS(sb));
		if (IS_ERR(handle)) {
			up_read(&PXT4_I(inode)->i_mmap_sem);
			sb_end_pagefault(sb);
			return VM_FAULT_SIGBUS;
		}
	} else {
		down_read(&PXT4_I(inode)->i_mmap_sem);
	}
	result = dax_iomap_fault(vmf, pe_size, &pfn, &error, &pxt4_iomap_ops);
	if (write) {
		pxt4_journal_stop(handle);

		if ((result & VM_FAULT_ERROR) && error == -ENOSPC &&
		    pxt4_should_retry_alloc(sb, &retries))
			goto retry;
		/* Handling synchronous page fault? */
		if (result & VM_FAULT_NEEDDSYNC)
			result = dax_finish_sync_fault(vmf, pe_size, pfn);
		up_read(&PXT4_I(inode)->i_mmap_sem);
		sb_end_pagefault(sb);
	} else {
		up_read(&PXT4_I(inode)->i_mmap_sem);
	}

	return result;
}

static vm_fault_t pxt4_dax_fault(struct vm_fault *vmf)
{
	return pxt4_dax_huge_fault(vmf, PE_SIZE_PTE);
}

static const struct vm_operations_struct pxt4_dax_vm_ops = {
	.fault		= pxt4_dax_fault,
	.huge_fault	= pxt4_dax_huge_fault,
	.page_mkwrite	= pxt4_dax_fault,
	.pfn_mkwrite	= pxt4_dax_fault,
};
#else
#define pxt4_dax_vm_ops	pxt4_file_vm_ops
#endif

static const struct vm_operations_struct pxt4_file_vm_ops = {
	.fault		= pxt4_filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite   = pxt4_page_mkwrite,
};

static int pxt4_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file->f_mapping->host;
	struct pxt4_sb_info *sbi = PXT4_SB(inode->i_sb);
	struct dax_device *dax_dev = sbi->s_daxdev;

	if (unlikely(pxt4_forced_shutdown(sbi)))
		return -EIO;

	/*
	 * We don't support synchronous mappings for non-DAX files and
	 * for DAX files if underneath dax_device is not synchronous.
	 */
	if (!daxdev_mapping_supported(vma, dax_dev))
		return -EOPNOTSUPP;

	file_accessed(file);
	if (IS_DAX(file_inode(file))) {
		vma->vm_ops = &pxt4_dax_vm_ops;
		vma->vm_flags |= VM_HUGEPAGE;
	} else {
		vma->vm_ops = &pxt4_file_vm_ops;
	}
	return 0;
}

static int pxt4_sample_last_mounted(struct super_block *sb,
				    struct vfsmount *mnt)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct path path;
	char buf[64], *cp;
	handle_t *handle;
	int err;

	if (likely(sbi->s_mount_flags & PXT4_MF_MNTDIR_SAMPLED))
		return 0;

	if (sb_rdonly(sb) || !sb_start_intwrite_trylock(sb))
		return 0;

	sbi->s_mount_flags |= PXT4_MF_MNTDIR_SAMPLED;
	/*
	 * Sample where the filesystem has been mounted and
	 * store it in the superblock for sysadmin convenience
	 * when trying to sort through large numbers of block
	 * devices or filesystem images.
	 */
	memset(buf, 0, sizeof(buf));
	path.mnt = mnt;
	path.dentry = mnt->mnt_root;
	cp = d_path(&path, buf, sizeof(buf));
	err = 0;
	if (IS_ERR(cp))
		goto out;

	handle = pxt4_journal_start_sb(sb, PXT4_HT_MISC, 1);
	err = PTR_ERR(handle);
	if (IS_ERR(handle))
		goto out;
	BUFFER_TRACE(sbi->s_sbh, "get_write_access");
	err = pxt4_journal_get_write_access(handle, sbi->s_sbh);
	if (err)
		goto out_journal;
	strlcpy(sbi->s_es->s_last_mounted, cp,
		sizeof(sbi->s_es->s_last_mounted));
	pxt4_handle_dirty_super(handle, sb);
out_journal:
	pxt4_journal_stop(handle);
out:
	sb_end_intwrite(sb);
	return err;
}

static int pxt4_file_open(struct inode * inode, struct file * filp)
{
	int ret;

	if (unlikely(pxt4_forced_shutdown(PXT4_SB(inode->i_sb))))
		return -EIO;

	ret = pxt4_sample_last_mounted(inode->i_sb, filp->f_path.mnt);
	if (ret)
		return ret;

	ret = fscrypt_file_open(inode, filp);
	if (ret)
		return ret;

	ret = fsverity_file_open(inode, filp);
	if (ret)
		return ret;

	/*
	 * Set up the jbd3_inode if we are opening the inode for
	 * writing and the journal is present
	 */
	if (filp->f_mode & FMODE_WRITE) {
		ret = pxt4_inode_attach_jinode(inode);
		if (ret < 0)
			return ret;
	}

	filp->f_mode |= FMODE_NOWAIT;
	return dquot_file_open(inode, filp);
}

/*
 * pxt4_llseek() handles both block-mapped and extent-mapped maxbytes values
 * by calling generic_file_llseek_size() with the appropriate maxbytes
 * value for each.
 */
loff_t pxt4_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	loff_t maxbytes;

	if (!(pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS)))
		maxbytes = PXT4_SB(inode->i_sb)->s_bitmap_maxbytes;
	else
		maxbytes = inode->i_sb->s_maxbytes;

	switch (whence) {
	default:
		return generic_file_llseek_size(file, offset, whence,
						maxbytes, i_size_read(inode));
	case SEEK_HOLE:
		inode_lock_shared(inode);
		offset = iomap_seek_hole(inode, offset, &pxt4_iomap_ops);
		inode_unlock_shared(inode);
		break;
	case SEEK_DATA:
		inode_lock_shared(inode);
		offset = iomap_seek_data(inode, offset, &pxt4_iomap_ops);
		inode_unlock_shared(inode);
		break;
	}

	if (offset < 0)
		return offset;
	return vfs_setpos(file, offset, maxbytes);
}

const struct file_operations pxt4_file_operations = {
	.llseek		= pxt4_llseek,
	.read_iter	= pxt4_file_read_iter,
	.write_iter	= pxt4_file_write_iter,
	.unlocked_ioctl = pxt4_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= pxt4_compat_ioctl,
#endif
	.mmap		= pxt4_file_mmap,
	.mmap_supported_flags = MAP_SYNC,
	.open		= pxt4_file_open,
	.release	= pxt4_release_file,
	.fsync		= pxt4_sync_file,
	.get_unmapped_area = thp_get_unmapped_area,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.fallocate	= pxt4_fallocate,
};

const struct inode_operations pxt4_file_inode_operations = {
	.setattr	= pxt4_setattr,
	.getattr	= pxt4_file_getattr,
	.listxattr	= pxt4_listxattr,
	.get_acl	= pxt4_get_acl,
	.set_acl	= pxt4_set_acl,
	.fiemap		= pxt4_fiemap,
};

