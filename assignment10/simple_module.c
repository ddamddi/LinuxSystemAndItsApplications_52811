#define BILLION 1000000000
#define NUM_OF_ENTRY 100000
#define NUM_OF_KTHREAD 4

#define INSERT 0
#define SEARCH 1
#define DELETE 2

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h> // for thread
#include <linux/slab.h> // for kmalloc
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/time.h>
#include <linux/sched.h>

unsigned long long add_to_hp_list_time = 0;
unsigned long long add_to_hp_list_count = 0;
struct timespec64 spclock[2];

int counter, op;
char* locking_alg;

spinlock_t counter_lock;
//struct mutex my_mutex;
//struct rw_semaphore counter_rwse;

struct task_struct *thread1, *thread2, *thread3, *thread4;
struct list_head simple_list_head;

struct simple_list{
    struct list_head list;
    unsigned int data;
};

void insert(void);
void delete(void);
void search(void);
void list_create(int);

void initialize_ts64(struct timespec64 *spclock)
{
    int i;
    for(i=0; i<2; i++)
    {
        spclock[i].tv_sec = 0;
    	spclock[i].tv_nsec = 0;
    }
}


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


static int insert_function(void *data)
{
    int i;

    /* Insert list element */
    for(i=1; i<=NUM_OF_ENTRY/NUM_OF_KTHREAD; i++)
    {
	spin_lock(&counter_lock);
	//mutex_lock(&my_mutex);
	//down_write(&counter_rwse);
	
	struct simple_list *new = kmalloc(sizeof(struct simple_list), GFP_KERNEL);
        new->data = counter;
        counter++;
        ktime_get_real_ts64(&spclock[0]);
        list_add(&new->list, &simple_list_head);
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &add_to_hp_list_time, &add_to_hp_list_count);
        // printk("%s, counter: %d, i: %d, pid: %u\n", __func__, counter, i, current->pid);
        
        spin_unlock(&counter_lock);
	//mutex_unlock(&my_mutex);
	//up_write(&counter_rwse);
    }
    do_exit(0);
}

static int search_function(void *data)
{
    int n = *((int*)data);
    int i;
    
    /* Search list element */
    for(i=NUM_OF_ENTRY/NUM_OF_KTHREAD * n; i<NUM_OF_ENTRY/NUM_OF_KTHREAD *(n+1); i++)
    {
        spin_lock(&counter_lock);
        //mutex_lock(&my_mutex);
        //down_read(&counter_rwse);

    	struct simple_list *current_node;
	struct list_head *p;
	
	ktime_get_real_ts64(&spclock[0]);
	list_for_each(p, &simple_list_head)
	{
	    current_node = list_entry(p, struct simple_list, list);
	    if(current_node->data == i){
		// counter++;
		__sync_fetch_and_add(&counter, 1);
	    	break;
	    }
	}
	// printk("%s, counter: %d, i: %d, pid: %u\n", __func__, counter, i, current->pid);
    	ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &add_to_hp_list_time, &add_to_hp_list_count);
        
        spin_unlock(&counter_lock);
        //mutex_unlock(&my_mutex);
        //up_read(&counter_rwse);
    }
    do_exit(0);
}

static int delete_function(void *data)
{
    int n = *((int*)data);
    int i;
    
    /* Delete list element */
    for(i=NUM_OF_ENTRY/NUM_OF_KTHREAD * n; i<NUM_OF_ENTRY/NUM_OF_KTHREAD *(n+1); i++)
    {
        spin_lock(&counter_lock);
        //mutex_lock(&my_mutex);
        //down_write(&counter_rwse);
        
    	struct simple_list *current_node, *tmp;
    	
    	ktime_get_real_ts64(&spclock[0]);
        list_for_each_entry_safe(current_node, tmp, &simple_list_head, list)
        {
	    if(current_node->data == i)
	    {
	        // printk("%d\n",current_node->data);
    	        list_del(&current_node->list);
    	        kfree(current_node);
            }
    	}
    	ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &add_to_hp_list_time, &add_to_hp_list_count);
    	
    	spin_unlock(&counter_lock);
    	//mutex_unlock(&my_mutex);
    	//up_write(&counter_rwse);
    }
}


void list_create(int n)
{
    int i;
    for(i=0; i<n; i++)
    {
    	struct simple_list *new = kmalloc(sizeof(struct simple_list), GFP_KERNEL);
        new->data = i;
        list_add(&new->list, &simple_list_head);
    }
}


void insert()
{
    int i;
    for(i=0; i<NUM_OF_KTHREAD; i++)
    	kthread_run(insert_function, NULL, "insert_function");
}

void search()
{
    int i;
    list_create(NUM_OF_ENTRY);
    for(i=0; i<NUM_OF_KTHREAD; i++)
    {
        int* arg = (int*)kmalloc(sizeof(int), GFP_KERNEL);
        *arg = i;
        kthread_run(search_function, (void*)arg, "search_function");
    }
}

void delete()
{
    int i;
    list_create(NUM_OF_ENTRY);
    for(i=0; i<NUM_OF_KTHREAD; i++)
    {
        int* arg = (int*)kmalloc(sizeof(int), GFP_KERNEL);
        *arg = i;
        kthread_run(delete_function, (void*)arg, "delete_function");
    }
}


int __init simple_module_init(void)
{
    /* init timespec */
    initialize_ts64(spclock);
    
    /* init list */
    INIT_LIST_HEAD(&simple_list_head);
    
    /* init spinlock */
    counter = 0;
    spin_lock_init(&counter_lock);
    // mutex_init(&my_mutex);
    // init_rwsem(&counter_rwse);
    
    // printk(KERN_EMERG "Hello Simple Module\n");
    
    op = DELETE;
    locking_alg = "Spinlock";
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
       
    return 0;
}


void __exit simple_module_cleanup(void)
{
    if (op == INSERT)
        printk("%s linked list insert time: %llu, count: %llu\n", locking_alg, add_to_hp_list_time, add_to_hp_list_count);
    else if (op == SEARCH)
        printk("%s linked list search time: %llu, count: %llu\n", locking_alg, add_to_hp_list_time, add_to_hp_list_count);
    else if (op == DELETE)
        printk("%s linked list delete time: %llu, count: %llu\n", locking_alg, add_to_hp_list_time, add_to_hp_list_count);
}


module_init(simple_module_init);
module_exit(simple_module_cleanup);

MODULE_LICENSE("GPL");
