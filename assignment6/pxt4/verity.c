// SPDX-License-Identifier: GPL-2.0
/*
 * fs/pxt4/verity.c: fs-verity support for pxt4
 *
 * Copyright 2019 Google LLC
 */

/*
 * Implementation of fsverity_operations for pxt4.
 *
 * pxt4 stores the verity metadata (Merkle tree and fsverity_descriptor) past
 * the end of the file, starting at the first 64K boundary beyond i_size.  This
 * approach works because (a) verity files are readonly, and (b) pages fully
 * beyond i_size aren't visible to userspace but can be read/written internally
 * by pxt4 with only some relatively small changes to pxt4.  This approach
 * avoids having to depend on the EA_INODE feature and on rearchitecturing
 * pxt4's xattr support to support paging multi-gigabyte xattrs into memory, and
 * to support encrypting xattrs.  Note that the verity metadata *must* be
 * encrypted when the file is, since it contains hashes of the plaintext data.
 *
 * Using a 64K boundary rather than a 4K one keeps things ready for
 * architectures with 64K pages, and it doesn't necessarily waste space on-disk
 * since there can be a hole between i_size and the start of the Merkle tree.
 */

#include <linux/quotaops.h>

#include "pxt4.h"
#include "pxt4_extents.h"
#include "pxt4_jbd3.h"

static inline loff_t pxt4_verity_metadata_pos(const struct inode *inode)
{
	return round_up(inode->i_size, 65536);
}

/*
 * Read some verity metadata from the inode.  __vfs_read() can't be used because
 * we need to read beyond i_size.
 */
static int pagecache_read(struct inode *inode, void *buf, size_t count,
			  loff_t pos)
{
	while (count) {
		size_t n = min_t(size_t, count,
				 PAGE_SIZE - offset_in_page(pos));
		struct page *page;
		void *addr;

		page = read_mapping_page(inode->i_mapping, pos >> PAGE_SHIFT,
					 NULL);
		if (IS_ERR(page))
			return PTR_ERR(page);

		addr = kmap_atomic(page);
		memcpy(buf, addr + offset_in_page(pos), n);
		kunmap_atomic(addr);

		put_page(page);

		buf += n;
		pos += n;
		count -= n;
	}
	return 0;
}

/*
 * Write some verity metadata to the inode for FS_IOC_ENABLE_VERITY.
 * kernel_write() can't be used because the file descriptor is readonly.
 */
static int pagecache_write(struct inode *inode, const void *buf, size_t count,
			   loff_t pos)
{
	if (pos + count > inode->i_sb->s_maxbytes)
		return -EFBIG;

	while (count) {
		size_t n = min_t(size_t, count,
				 PAGE_SIZE - offset_in_page(pos));
		struct page *page;
		void *fsdata;
		void *addr;
		int res;

		res = pagecache_write_begin(NULL, inode->i_mapping, pos, n, 0,
					    &page, &fsdata);
		if (res)
			return res;

		addr = kmap_atomic(page);
		memcpy(addr + offset_in_page(pos), buf, n);
		kunmap_atomic(addr);

		res = pagecache_write_end(NULL, inode->i_mapping, pos, n, n,
					  page, fsdata);
		if (res < 0)
			return res;
		if (res != n)
			return -EIO;

		buf += n;
		pos += n;
		count -= n;
	}
	return 0;
}

static int pxt4_begin_enable_verity(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	const int credits = 2; /* superblock and inode for pxt4_orphan_add() */
	handle_t *handle;
	int err;

	if (pxt4_verity_in_progress(inode))
		return -EBUSY;

	/*
	 * Since the file was opened readonly, we have to initialize the jbd
	 * inode and quotas here and not rely on ->open() doing it.  This must
	 * be done before evicting the inline data.
	 */

	err = pxt4_inode_attach_jinode(inode);
	if (err)
		return err;

	err = dquot_initialize(inode);
	if (err)
		return err;

	err = pxt4_convert_inline_data(inode);
	if (err)
		return err;

	if (!pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS)) {
		pxt4_warning_inode(inode,
				   "verity is only allowed on extent-based files");
		return -EOPNOTSUPP;
	}

	/*
	 * pxt4 uses the last allocated block to find the verity descriptor, so
	 * we must remove any other blocks past EOF which might confuse things.
	 */
	err = pxt4_truncate(inode);
	if (err)
		return err;

	handle = pxt4_journal_start(inode, PXT4_HT_INODE, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	err = pxt4_orphan_add(handle, inode);
	if (err == 0)
		pxt4_set_inode_state(inode, PXT4_STATE_VERITY_IN_PROGRESS);

	pxt4_journal_stop(handle);
	return err;
}

/*
 * pxt4 stores the verity descriptor beginning on the next filesystem block
 * boundary after the Merkle tree.  Then, the descriptor size is stored in the
 * last 4 bytes of the last allocated filesystem block --- which is either the
 * block in which the descriptor ends, or the next block after that if there
 * weren't at least 4 bytes remaining.
 *
 * We can't simply store the descriptor in an xattr because it *must* be
 * encrypted when pxt4 encryption is used, but pxt4 encryption doesn't encrypt
 * xattrs.  Also, if the descriptor includes a large signature blob it may be
 * too large to store in an xattr without the EA_INODE feature.
 */
static int pxt4_write_verity_descriptor(struct inode *inode, const void *desc,
					size_t desc_size, u64 merkle_tree_size)
{
	const u64 desc_pos = round_up(pxt4_verity_metadata_pos(inode) +
				      merkle_tree_size, i_blocksize(inode));
	const u64 desc_end = desc_pos + desc_size;
	const __le32 desc_size_disk = cpu_to_le32(desc_size);
	const u64 desc_size_pos = round_up(desc_end + sizeof(desc_size_disk),
					   i_blocksize(inode)) -
				  sizeof(desc_size_disk);
	int err;

	err = pagecache_write(inode, desc, desc_size, desc_pos);
	if (err)
		return err;

	return pagecache_write(inode, &desc_size_disk, sizeof(desc_size_disk),
			       desc_size_pos);
}

static int pxt4_end_enable_verity(struct file *filp, const void *desc,
				  size_t desc_size, u64 merkle_tree_size)
{
	struct inode *inode = file_inode(filp);
	const int credits = 2; /* superblock and inode for pxt4_orphan_del() */
	handle_t *handle;
	int err = 0;
	int err2;

	if (desc != NULL) {
		/* Succeeded; write the verity descriptor. */
		err = pxt4_write_verity_descriptor(inode, desc, desc_size,
						   merkle_tree_size);

		/* Write all pages before clearing VERITY_IN_PROGRESS. */
		if (!err)
			err = filemap_write_and_wait(inode->i_mapping);
	}

	/* If we failed, truncate anything we wrote past i_size. */
	if (desc == NULL || err)
		pxt4_truncate(inode);

	/*
	 * We must always clean up by clearing PXT4_STATE_VERITY_IN_PROGRESS and
	 * deleting the inode from the orphan list, even if something failed.
	 * If everything succeeded, we'll also set the verity bit in the same
	 * transaction.
	 */

	pxt4_clear_inode_state(inode, PXT4_STATE_VERITY_IN_PROGRESS);

	handle = pxt4_journal_start(inode, PXT4_HT_INODE, credits);
	if (IS_ERR(handle)) {
		pxt4_orphan_del(NULL, inode);
		return PTR_ERR(handle);
	}

	err2 = pxt4_orphan_del(handle, inode);
	if (err2)
		goto out_stop;

	if (desc != NULL && !err) {
		struct pxt4_iloc iloc;

		err = pxt4_reserve_inode_write(handle, inode, &iloc);
		if (err)
			goto out_stop;
		pxt4_set_inode_flag(inode, PXT4_INODE_VERITY);
		pxt4_set_inode_flags(inode);
		err = pxt4_mark_iloc_dirty(handle, inode, &iloc);
	}
out_stop:
	pxt4_journal_stop(handle);
	return err ?: err2;
}

static int pxt4_get_verity_descriptor_location(struct inode *inode,
					       size_t *desc_size_ret,
					       u64 *desc_pos_ret)
{
	struct pxt4_ext_path *path;
	struct pxt4_extent *last_extent;
	u32 end_lblk;
	u64 desc_size_pos;
	__le32 desc_size_disk;
	u32 desc_size;
	u64 desc_pos;
	int err;

	/*
	 * Descriptor size is in last 4 bytes of last allocated block.
	 * See pxt4_write_verity_descriptor().
	 */

	if (!pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS)) {
		PXT4_ERROR_INODE(inode, "verity file doesn't use extents");
		return -EFSCORRUPTED;
	}

	path = pxt4_find_extent(inode, EXT_MAX_BLOCKS - 1, NULL, 0);
	if (IS_ERR(path))
		return PTR_ERR(path);

	last_extent = path[path->p_depth].p_ext;
	if (!last_extent) {
		PXT4_ERROR_INODE(inode, "verity file has no extents");
		pxt4_ext_drop_refs(path);
		kfree(path);
		return -EFSCORRUPTED;
	}

	end_lblk = le32_to_cpu(last_extent->ee_block) +
		   pxt4_ext_get_actual_len(last_extent);
	desc_size_pos = (u64)end_lblk << inode->i_blkbits;
	pxt4_ext_drop_refs(path);
	kfree(path);

	if (desc_size_pos < sizeof(desc_size_disk))
		goto bad;
	desc_size_pos -= sizeof(desc_size_disk);

	err = pagecache_read(inode, &desc_size_disk, sizeof(desc_size_disk),
			     desc_size_pos);
	if (err)
		return err;
	desc_size = le32_to_cpu(desc_size_disk);

	/*
	 * The descriptor is stored just before the desc_size_disk, but starting
	 * on a filesystem block boundary.
	 */

	if (desc_size > INT_MAX || desc_size > desc_size_pos)
		goto bad;

	desc_pos = round_down(desc_size_pos - desc_size, i_blocksize(inode));
	if (desc_pos < pxt4_verity_metadata_pos(inode))
		goto bad;

	*desc_size_ret = desc_size;
	*desc_pos_ret = desc_pos;
	return 0;

bad:
	PXT4_ERROR_INODE(inode, "verity file corrupted; can't find descriptor");
	return -EFSCORRUPTED;
}

static int pxt4_get_verity_descriptor(struct inode *inode, void *buf,
				      size_t buf_size)
{
	size_t desc_size = 0;
	u64 desc_pos = 0;
	int err;

	err = pxt4_get_verity_descriptor_location(inode, &desc_size, &desc_pos);
	if (err)
		return err;

	if (buf_size) {
		if (desc_size > buf_size)
			return -ERANGE;
		err = pagecache_read(inode, buf, desc_size, desc_pos);
		if (err)
			return err;
	}
	return desc_size;
}

static struct page *pxt4_read_merkle_tree_page(struct inode *inode,
					       pgoff_t index)
{
	index += pxt4_verity_metadata_pos(inode) >> PAGE_SHIFT;

	return read_mapping_page(inode->i_mapping, index, NULL);
}

static int pxt4_write_merkle_tree_block(struct inode *inode, const void *buf,
					u64 index, int log_blocksize)
{
	loff_t pos = pxt4_verity_metadata_pos(inode) + (index << log_blocksize);

	return pagecache_write(inode, buf, 1 << log_blocksize, pos);
}

const struct fsverity_operations pxt4_verityops = {
	.begin_enable_verity	= pxt4_begin_enable_verity,
	.end_enable_verity	= pxt4_end_enable_verity,
	.get_verity_descriptor	= pxt4_get_verity_descriptor,
	.read_merkle_tree_page	= pxt4_read_merkle_tree_page,
	.write_merkle_tree_block = pxt4_write_merkle_tree_block,
};
