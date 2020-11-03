// SPDX-License-Identifier: GPL-2.0
/*
 * Interface between pxt4 and JBD
 */

#include "pxt4_jbd3.h"

#include <trace/events/pxt4.h>

/* Just increment the non-pointer handle value */
static handle_t *pxt4_get_nojournal(void)
{
	handle_t *handle = current->journal_info;
	unsigned long ref_cnt = (unsigned long)handle;

	BUG_ON(ref_cnt >= PXT4_NOJOURNAL_MAX_REF_COUNT);

	ref_cnt++;
	handle = (handle_t *)ref_cnt;

	current->journal_info = handle;
	return handle;
}


/* Decrement the non-pointer handle value */
static void pxt4_put_nojournal(handle_t *handle)
{
	unsigned long ref_cnt = (unsigned long)handle;

	BUG_ON(ref_cnt == 0);

	ref_cnt--;
	handle = (handle_t *)ref_cnt;

	current->journal_info = handle;
}

/*
 * Wrappers for jbd3_journal_start/end.
 */
static int pxt4_journal_check_start(struct super_block *sb)
{
	journal_t *journal;

	might_sleep();

	if (unlikely(pxt4_forced_shutdown(PXT4_SB(sb))))
		return -EIO;

	if (sb_rdonly(sb))
		return -EROFS;
	WARN_ON(sb->s_writers.frozen == SB_FREEZE_COMPLETE);
	journal = PXT4_SB(sb)->s_journal;
	/*
	 * Special case here: if the journal has aborted behind our
	 * backs (eg. EIO in the commit thread), then we still need to
	 * take the FS itself readonly cleanly.
	 */
	if (journal && is_journal_aborted(journal)) {
		pxt4_abort(sb, "Detected aborted journal");
		return -EROFS;
	}
	return 0;
}

handle_t *__pxt4_journal_start_sb(struct super_block *sb, unsigned int line,
				  int type, int blocks, int rsv_blocks)
{
	journal_t *journal;
	int err;

	trace_pxt4_journal_start(sb, blocks, rsv_blocks, _RET_IP_);
	err = pxt4_journal_check_start(sb);
	if (err < 0)
		return ERR_PTR(err);

	journal = PXT4_SB(sb)->s_journal;
	if (!journal)
		return pxt4_get_nojournal();
	return jbd3__journal_start(journal, blocks, rsv_blocks, GFP_NOFS,
				   type, line);
}

int __pxt4_journal_stop(const char *where, unsigned int line, handle_t *handle)
{
	struct super_block *sb;
	int err;
	int rc;

	if (!pxt4_handle_valid(handle)) {
		pxt4_put_nojournal(handle);
		return 0;
	}

	err = handle->h_err;
	if (!handle->h_transaction) {
		rc = jbd3_journal_stop(handle);
		return err ? err : rc;
	}

	sb = handle->h_transaction->t_journal->j_private;
	rc = jbd3_journal_stop(handle);

	if (!err)
		err = rc;
	if (err)
		__pxt4_std_error(sb, where, line, err);
	return err;
}

handle_t *__pxt4_journal_start_reserved(handle_t *handle, unsigned int line,
					int type)
{
	struct super_block *sb;
	int err;

	if (!pxt4_handle_valid(handle))
		return pxt4_get_nojournal();

	sb = handle->h_journal->j_private;
	trace_pxt4_journal_start_reserved(sb, handle->h_buffer_credits,
					  _RET_IP_);
	err = pxt4_journal_check_start(sb);
	if (err < 0) {
		jbd3_journal_free_reserved(handle);
		return ERR_PTR(err);
	}

	err = jbd3_journal_start_reserved(handle, type, line);
	if (err < 0)
		return ERR_PTR(err);
	return handle;
}

static void pxt4_journal_abort_handle(const char *caller, unsigned int line,
				      const char *err_fn,
				      struct buffer_head *bh,
				      handle_t *handle, int err)
{
	char nbuf[16];
	const char *errstr = pxt4_decode_error(NULL, err, nbuf);

	BUG_ON(!pxt4_handle_valid(handle));

	if (bh)
		BUFFER_TRACE(bh, "abort");

	if (!handle->h_err)
		handle->h_err = err;

	if (is_handle_aborted(handle))
		return;

	printk(KERN_ERR "PXT4-fs: %s:%d: aborting transaction: %s in %s\n",
	       caller, line, errstr, err_fn);

	jbd3_journal_abort_handle(handle);
}

int __pxt4_journal_get_write_access(const char *where, unsigned int line,
				    handle_t *handle, struct buffer_head *bh)
{
	int err = 0;

	might_sleep();

	if (pxt4_handle_valid(handle)) {
		err = jbd3_journal_get_write_access(handle, bh);
		if (err)
			pxt4_journal_abort_handle(where, line, __func__, bh,
						  handle, err);
	}
	return err;
}

/*
 * The pxt4 forget function must perform a revoke if we are freeing data
 * which has been journaled.  Metadata (eg. indirect blocks) must be
 * revoked in all cases.
 *
 * "bh" may be NULL: a metadata block may have been freed from memory
 * but there may still be a record of it in the journal, and that record
 * still needs to be revoked.
 *
 * If the handle isn't valid we're not journaling, but we still need to
 * call into pxt4_journal_revoke() to put the buffer head.
 */
int __pxt4_forget(const char *where, unsigned int line, handle_t *handle,
		  int is_metadata, struct inode *inode,
		  struct buffer_head *bh, pxt4_fsblk_t blocknr)
{
	int err;

	might_sleep();

	trace_pxt4_forget(inode, is_metadata, blocknr);
	BUFFER_TRACE(bh, "enter");

	jbd_debug(4, "forgetting bh %p: is_metadata = %d, mode %o, "
		  "data mode %x\n",
		  bh, is_metadata, inode->i_mode,
		  test_opt(inode->i_sb, DATA_FLAGS));

	/* In the no journal case, we can just do a bforget and return */
	if (!pxt4_handle_valid(handle)) {
		bforget(bh);
		return 0;
	}

	/* Never use the revoke function if we are doing full data
	 * journaling: there is no need to, and a V1 superblock won't
	 * support it.  Otherwise, only skip the revoke on un-journaled
	 * data blocks. */

	if (test_opt(inode->i_sb, DATA_FLAGS) == PXT4_MOUNT_JOURNAL_DATA ||
	    (!is_metadata && !pxt4_should_journal_data(inode))) {
		if (bh) {
			BUFFER_TRACE(bh, "call jbd3_journal_forget");
			err = jbd3_journal_forget(handle, bh);
			if (err)
				pxt4_journal_abort_handle(where, line, __func__,
							  bh, handle, err);
			return err;
		}
		return 0;
	}

	/*
	 * data!=journal && (is_metadata || should_journal_data(inode))
	 */
	BUFFER_TRACE(bh, "call jbd3_journal_revoke");
	err = jbd3_journal_revoke(handle, blocknr, bh);
	if (err) {
		pxt4_journal_abort_handle(where, line, __func__,
					  bh, handle, err);
		__pxt4_abort(inode->i_sb, where, line,
			   "error %d when attempting revoke", err);
	}
	BUFFER_TRACE(bh, "exit");
	return err;
}

int __pxt4_journal_get_create_access(const char *where, unsigned int line,
				handle_t *handle, struct buffer_head *bh)
{
	int err = 0;

	if (pxt4_handle_valid(handle)) {
		err = jbd3_journal_get_create_access(handle, bh);
		if (err)
			pxt4_journal_abort_handle(where, line, __func__,
						  bh, handle, err);
	}
	return err;
}

int __pxt4_handle_dirty_metadata(const char *where, unsigned int line,
				 handle_t *handle, struct inode *inode,
				 struct buffer_head *bh)
{
	int err = 0;

	might_sleep();

	set_buffer_meta(bh);
	set_buffer_prio(bh);
	if (pxt4_handle_valid(handle)) {
		err = jbd3_journal_dirty_metadata(handle, bh);
		/* Errors can only happen due to aborted journal or a nasty bug */
		if (!is_handle_aborted(handle) && WARN_ON_ONCE(err)) {
			pxt4_journal_abort_handle(where, line, __func__, bh,
						  handle, err);
			if (inode == NULL) {
				pr_err("PXT4: jbd3_journal_dirty_metadata "
				       "failed: handle type %u started at "
				       "line %u, credits %u/%u, errcode %d",
				       handle->h_type,
				       handle->h_line_no,
				       handle->h_requested_credits,
				       handle->h_buffer_credits, err);
				return err;
			}
			pxt4_error_inode(inode, where, line,
					 bh->b_blocknr,
					 "journal_dirty_metadata failed: "
					 "handle type %u started at line %u, "
					 "credits %u/%u, errcode %d",
					 handle->h_type,
					 handle->h_line_no,
					 handle->h_requested_credits,
					 handle->h_buffer_credits, err);
		}
	} else {
		if (inode)
			mark_buffer_dirty_inode(bh, inode);
		else
			mark_buffer_dirty(bh);
		if (inode && inode_needs_sync(inode)) {
			sync_dirty_buffer(bh);
			if (buffer_req(bh) && !buffer_uptodate(bh)) {
				struct pxt4_super_block *es;

				es = PXT4_SB(inode->i_sb)->s_es;
				es->s_last_error_block =
					cpu_to_le64(bh->b_blocknr);
				pxt4_error_inode(inode, where, line,
						 bh->b_blocknr,
					"IO error syncing itable block");
				err = -EIO;
			}
		}
	}
	return err;
}

int __pxt4_handle_dirty_super(const char *where, unsigned int line,
			      handle_t *handle, struct super_block *sb)
{
	struct buffer_head *bh = PXT4_SB(sb)->s_sbh;
	int err = 0;

	pxt4_superblock_csum_set(sb);
	if (pxt4_handle_valid(handle)) {
		err = jbd3_journal_dirty_metadata(handle, bh);
		if (err)
			pxt4_journal_abort_handle(where, line, __func__,
						  bh, handle, err);
	} else
		mark_buffer_dirty(bh);
	return err;
}
