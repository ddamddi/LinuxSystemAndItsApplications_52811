#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>

int counter;
struct mutex my_mutex;
struct task_struct *writer_thread1, *writer_thread2;

static int writer_function(void *data)
{
    while(!kthread_should_stop()){
        mutex_lock(&my_mutex);
        counter++;
        printk("%s, counter: %d, pid: %u\n", __func__, counter, current->pid);
        mutex_unlock(&my_mutex);
        msleep(500);
    }
    do_exit(0);
}

int __init my_module_init(void)
{
    printk(KERN_EMERG "Hello SpinLock Module\n");
    counter = 0;
    mutex_init(&my_mutex);
    writer_thread1 = kthread_run(writer_function, NULL, "writer_function");
    writer_thread2 = kthread_run(writer_function, NULL, "writer_function");
    return 0;
}


void __exit my_module_cleanup(void)
{
    kthread_stop(writer_thread1);
    kthread_stop(writer_thread2);
    printk("%s, Exiting module\n", __func__);
}


module_init(my_module_init);
module_exit(my_module_cleanup);

MODULE_LICENSE("GPL");
