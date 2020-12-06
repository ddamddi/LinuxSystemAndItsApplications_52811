# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the linux journaling routines.
#

obj-m := list_test.o 


KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)


default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	rm *.mod.*
	rm *.ko
	rm *.o

