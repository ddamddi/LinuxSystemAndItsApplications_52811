// SPDX-License-Identifier: GPL-2.0
/*
  File: fs/pxt4/acl.h

  (C) 2001 Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/

#include <linux/posix_acl_xattr.h>

#define PXT4_ACL_VERSION	0x0001

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
	__le32		e_id;
} pxt4_acl_entry;

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
} pxt4_acl_entry_short;

typedef struct {
	__le32		a_version;
} pxt4_acl_header;

static inline size_t pxt4_acl_size(int count)
{
	if (count <= 4) {
		return sizeof(pxt4_acl_header) +
		       count * sizeof(pxt4_acl_entry_short);
	} else {
		return sizeof(pxt4_acl_header) +
		       4 * sizeof(pxt4_acl_entry_short) +
		       (count - 4) * sizeof(pxt4_acl_entry);
	}
}

static inline int pxt4_acl_count(size_t size)
{
	ssize_t s;
	size -= sizeof(pxt4_acl_header);
	s = size - 4 * sizeof(pxt4_acl_entry_short);
	if (s < 0) {
		if (size % sizeof(pxt4_acl_entry_short))
			return -1;
		return size / sizeof(pxt4_acl_entry_short);
	} else {
		if (s % sizeof(pxt4_acl_entry))
			return -1;
		return s / sizeof(pxt4_acl_entry) + 4;
	}
}

#ifdef CONFIG_EXT4_FS_POSIX_ACL

/* acl.c */
struct posix_acl *pxt4_get_acl(struct inode *inode, int type);
int pxt4_set_acl(struct inode *inode, struct posix_acl *acl, int type);
extern int pxt4_init_acl(handle_t *, struct inode *, struct inode *);

#else  /* CONFIG_PXT4_FS_POSIX_ACL */
#include <linux/sched.h>
#define pxt4_get_acl NULL
#define pxt4_set_acl NULL

static inline int
pxt4_init_acl(handle_t *handle, struct inode *inode, struct inode *dir)
{
	return 0;
}
#endif  /* CONFIG_PXT4_FS_POSIX_ACL */

