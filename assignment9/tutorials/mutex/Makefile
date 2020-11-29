obj-m	:= mutex.o

KERNEL_DIR	:= /lib/modules/$(shell uname -r)/build
PWD		:= $(shell pwd)

defualt:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
clean:
	rm *.mod.*
	rm *.ko
	rm *.o
