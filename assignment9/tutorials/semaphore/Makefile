obj-m		:= semaphore.o

KERNEL_DIR	:= /lib/modules/$(shell uname -r)/build
PWD		:= $(shell pwd)

default :
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
clean :
	rm *.mod.*
	rm *.ko
	rm *.o         
