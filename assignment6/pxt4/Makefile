# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux ext4-filesystem routines.
#

obj-m += pxt4.o

pxt4-y := balloc.o bitmap.o dir.o file.o fsmap.o fsync.o ialloc.o inode.o page-io.o \
	ioctl.o namei.o super.o symlink.o hash.o resize.o extents.o \
	pxt4_jbd3.o migrate.o mballoc.o block_validity.o move_extent.o \
	mmp.o indirect.o extents_status.o xattr.o xattr_user.o \
	xattr_trusted.o inline.o readpage.o sysfs.o


pxt4-m += acl.o
pxt4-m += xattr_security.o
pxt4-m += verity.o


KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	rm *.mod.*
	rm *.ko
	rm *.o
