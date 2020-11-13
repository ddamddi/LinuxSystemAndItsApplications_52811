#define BILLION 1000000000
#define INSERT 0
#define SEARCH 1
#define DELETE 2

#define NUM_OF_ENTRY 100000

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h> // for thread
#include <linux/slab.h> // for kmalloc
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/time.h>

void insert(void);
void search(void);
void delete(void);

unsigned long long calclock3(struct timespec64 *spclock, unsigned long long *total_time, unsigned long long *total_count){
    long temp, temp_n;
    unsigned long long timedelay = 0;
    if(spclock[1].tv_nsec >= spclock[0].tv_nsec)
    {
        temp = spclock[1].tv_sec - spclock[0].tv_sec;
	temp_n = spclock[1].tv_nsec - spclock[0].tv_nsec;
	timedelay = BILLION * temp + temp_n;
    }
    else
    {
        temp = spclock[1].tv_sec - spclock[0].tv_sec - 1;
	temp_n = BILLION + spclock[1].tv_nsec - spclock[0].tv_nsec;
	timedelay = BILLION * temp + temp_n;
    }
    
    __sync_fetch_and_add(total_time, timedelay);
    __sync_fetch_and_add(total_count, 1);
    return timedelay;
}

struct simple_list{
    struct list_head list;
    unsigned int data;
};

void struct_example(int op)
{

    if (op == INSERT)
    {
    	insert();
    }
    else if (op == SEARCH)
    {
    	search();
    }
    else if (op == DELETE)
    {
    	delete();
    }
    else
    {
    	printk("UNDEFINED OPERATION ERROR\n");
    }
}

void insert()
{
    int i;
    unsigned long long add_to_hp_list_time = 0;
    unsigned long long add_to_hp_list_count = 0;
    struct list_head simple_list_head;
    struct timespec64 spclock[2];
    
    /* init timespec */
    for(i=0; i<2; i++)
    {
    	spclock[i].tv_sec = 0;
    	spclock[i].tv_nsec = 0;
    }
    
    /* init list */
    INIT_LIST_HEAD(&simple_list_head);
    
    /* Insert list element */
    for(i=0; i<NUM_OF_ENTRY; i++)
    {
        struct simple_list *new = kmalloc(sizeof(struct simple_list), GFP_KERNEL);
        new->data = i;
        ktime_get_real_ts64(&spclock[0]);
        list_add(&new->list, &simple_list_head);
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &add_to_hp_list_time, &add_to_hp_list_count);
    }
    
    printk("INSERT %d Entries\n", NUM_OF_ENTRY);
    printk("add_to_hp_list_time: %llu, count: %llu\n", add_to_hp_list_time, add_to_hp_list_count);
}

void search()
{
    int i;
    unsigned long long add_to_hp_list_time = 0;
    unsigned long long add_to_hp_list_count = 0;
    struct list_head simple_list_head;
    struct timespec64 spclock[2];
    
    /* init timespec */
    for(i=0; i<2; i++)
    {
    	spclock[i].tv_sec = 0;
    	spclock[i].tv_nsec = 0;
    }
    
    /* init list */
    INIT_LIST_HEAD(&simple_list_head);

    /* Search list element */
    for(i=0; i<NUM_OF_ENTRY; i++)
    {
    	struct simple_list *new = kmalloc(sizeof(struct simple_list), GFP_KERNEL);
        new->data = i;
        list_add(&new->list, &simple_list_head);
    }
    
    for(i=0; i<NUM_OF_ENTRY; i++)
    {
    	struct simple_list *current_node;
	struct list_head *p;
	
	ktime_get_real_ts64(&spclock[0]);
	list_for_each(p, &simple_list_head)
	{
	    current_node = list_entry(p, struct simple_list, list);
	    if(current_node->data == i)
	    	break;
	}
    	ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &add_to_hp_list_time, &add_to_hp_list_count);
    }
    
    printk("SEARCH %d Entries\n", NUM_OF_ENTRY);
    printk("add_to_hp_list_time: %llu, count: %llu\n", add_to_hp_list_time, add_to_hp_list_count);
}

void delete()
{
    int i;
    unsigned long long add_to_hp_list_time = 0;
    unsigned long long add_to_hp_list_count = 0;
    struct list_head simple_list_head;
    struct timespec64 spclock[2];
    
    /* init timespec */
    for(i=0; i<2; i++)
    {
    	spclock[i].tv_sec = 0;
    	spclock[i].tv_nsec = 0;
    }
    
    /* init list */
    INIT_LIST_HEAD(&simple_list_head);
    
    /* Create list element */
    for(i=0; i<NUM_OF_ENTRY; i++)
    {
    	struct simple_list *new = kmalloc(sizeof(struct simple_list), GFP_KERNEL);
        new->data = i;
        list_add(&new->list, &simple_list_head);
    }
    
    /* Delete list element */
    for(i=0; i<NUM_OF_ENTRY; i++)
    {
    	struct simple_list *current_node, *tmp;	
        list_for_each_entry_safe(current_node, tmp, &simple_list_head, list)
        {
	    if(current_node->data == i)
	    {        
                ktime_get_real_ts64(&spclock[0]);
    	        list_del(&current_node->list);
    	        kfree(current_node);
    	        ktime_get_real_ts64(&spclock[1]);
                calclock3(spclock, &add_to_hp_list_time, &add_to_hp_list_count);
            }
    	}
    }
    
    printk("DELETE %d Entries\n", NUM_OF_ENTRY);
    printk("add_to_hp_list_time: %llu, count: %llu\n", add_to_hp_list_time, add_to_hp_list_count);
}


int __init simple_module_init(void)
{
    int op = SEARCH;
    struct_example(op);
    printk(KERN_EMERG "Hello Simple Module\n");
    return 0;
}

void __exit simple_module_cleanup(void)
{
    printk("Bye Simple Module\n");
}

module_init(simple_module_init);
module_exit(simple_module_cleanup);
