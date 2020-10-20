#include <linux/kernel.h>

asmlinkage long sys_mycall(void){
	printk("20144320 Gyeong-hyeon Kim's System Call Example!!\n");

	return 0;
}
