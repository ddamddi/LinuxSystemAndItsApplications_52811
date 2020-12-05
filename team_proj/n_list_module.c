#define BILLION 1000000000
#define NUM_OF_ENTRY 100000

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

struct sub_head{
    struct list_head h_list;
    struct list_head v_list;
    int len;
};

struct node{
   struct list_head v_list;
   struct sub_head *_sub;
   int value;
};

struct rw_semaphore counter_rwse;

void initialize_ts64(struct timespec64 *spclock);
unsigned long long calclock3(struct timespec64 *spclock, unsigned long long *total_time, unsigned long long *total_count);
void new_sub_head(struct list_head *head);
void n_list_add(struct list_head *new, struct list_head *head);
void n_list_del(struct list_head *entry, struct list_head *head);
void n_list_traverse(struct list_head *head, int num_of_thread);
static int _n_list_traverse(void *current_sub_head);
struct list_head* n_list_get(int index, struct list_head* head);
void init_n_list(struct list_head *head);
void run(void);

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


void new_sub_head(struct list_head *head)
{
    //printk("new_sub_head() called\n");
    struct sub_head *new = kmalloc(sizeof(struct sub_head), GFP_KERNEL);
    //list_entry(new, struct sub_head, h_list)->len = 0;
    INIT_LIST_HEAD(&new->v_list);
    new->len = 0;
    //printk("0\n");
    list_add(&new->h_list, head);
}

void n_list_add(struct list_head *new, struct list_head *head)
{
    //printk("n_list_add() called\n");
    if(list_entry(head->next, struct sub_head, h_list)->len >= 1000) 
        new_sub_head(head);
        
    //printk("0\n");
    struct sub_head *tmp = list_entry(head->next, struct sub_head, h_list);
    //printk("%d\n", tmp->len);
    
    //printk("1\n");
    list_add(new, &tmp->v_list);
    
    //printk("2\n");
    list_entry(head->next, struct sub_head, h_list)->len++;
    
    // TODO : Sturct Node
    list_entry(new, struct node, v_list)->_sub = list_entry(head->next, struct sub_head, h_list); 
}

void n_list_del(struct list_head *entry, struct list_head *head)
{
    struct sub_head *_sub_head = list_entry(entry, struct node, v_list)->_sub;
    list_del(entry);
    
    _sub_head->len--;
    if(_sub_head->len == 0)
        list_del(&_sub_head->h_list);
}

void n_list_traverse(struct list_head* head, int num_of_thread)
{
    struct sub_head *current_sub_head;
    struct list_head *hp;
    list_for_each(hp, head)
    {
        //struct sub_head *data = list_entry(HEAD.next, struct sub_head, h_list);
        //struct sub_head *data2 = list_entry(data->h_list.next, struct sub_head, h_list);
        //kthread_run(_n_list_traverse, (void*)data,"TRAVERSE");
        //kthread_run(_n_list_traverse, (void*)data2,"TRAVERSE");
    
        current_sub_head = list_entry(hp, struct sub_head, h_list);
        struct sub_head* arg = kmalloc(sizeof(struct sub_head*), GFP_KERNEL);
        arg = current_sub_head;
        kthread_run(_n_list_traverse, (void*)arg, "TRAVERSE");
        
        //current_sub_head = list_entry(hp, struct sub_head, h_list);
        //_n_list_traverse(current_sub_head);
    }
}

static int _n_list_traverse(void *current_sub_head)
{
    struct sub_head *_current_sub_head = current_sub_head;
    struct node *current_node;
    struct list_head *p;
        
    list_for_each(p, &_current_sub_head->v_list)
    {
        down_write(&counter_rwse);
        current_node = list_entry(p, struct node, v_list);
        printk("%d\n", current_node->value);
        up_write(&counter_rwse);
    }
    // do_exit(0);
}

struct list_head* n_list_get(int index, struct list_head* head)
{
    struct list_head* current_sub = head->prev;
    struct sub_head* current_sub_entry = list_entry(current_sub, struct sub_head, h_list);
    
    int index_sum = 0, i;
    while(1)
    {
        if (current_sub_entry->len + index_sum >= index) break;
        index_sum += current_sub_entry->len;
        current_sub = current_sub->prev;
        current_sub_entry = list_entry(current_sub, struct sub_head, h_list);
    }
    
    struct list_head* current_list_head;
    current_list_head = &current_sub_entry->v_list;
    current_list_head = current_list_head->prev;
    
    for(i=0; i<index-index_sum; i++)
        current_list_head = current_list_head->prev;
    return current_list_head;
}

void init_n_list(struct list_head *head)
{
    // printk("init_n_list() called\n");
    INIT_LIST_HEAD(head);
    new_sub_head(head);
}

void run(void){
    struct list_head HEAD;
    int i;
    
    initialize_ts64(spclock);
    init_n_list(&HEAD);
    init_rwsem(&counter_rwse);
    // printk("INITIALIZE HEAD\n");
    
    struct node *del_entry;
    
    for(i=0; i<NUM_OF_ENTRY; i++)
    {
        struct node *new = kmalloc(sizeof(struct node), GFP_KERNEL);
        new->value = i;
        n_list_add(&new->v_list, &HEAD);
        // printk("ADD NEW NODE\n");
        if(i == 1498)
            del_entry = new;
    }
    
    //n_list_del(&del_entry->v_list, &HEAD);
    
    /*
    // printk("START TRAVERSE\n");
    struct sub_head *current_sub_head;
    struct list_head *hp;
    list_for_each(hp, &HEAD)
    {
        struct node *current_node;
        struct list_head *p;
        
        current_sub_head = list_entry(hp, struct sub_head, h_list);
        list_for_each(p, &current_sub_head->v_list)
        {
            current_node = list_entry(p, struct node, v_list);
            printk("%d\n", current_node->value);
        }
    }
    */
    
    
    
    /*
    struct node *current_node;
    struct list_head *p;
    struct sub_head *_sub_head = list_entry(HEAD.next, struct sub_head, h_list);
    list_for_each(p, &_sub_head->v_list)
    {
        current_node = list_entry(p, struct node, v_list);
        printk("%d\n", current_node->value);
    }
    */
    
    /*
    struct sub_head *data = list_entry(HEAD.next, struct sub_head, h_list);
    struct sub_head *data2 = list_entry(data->h_list.next, struct sub_head, h_list);
    kthread_run(_n_list_traverse, (void*)data,"TRAVERSE");
    kthread_run(_n_list_traverse, (void*)data2,"TRAVERSE");
    */
    
    
    ktime_get_real_ts64(&spclock[0]);
    // struct list_head* found_head = n_list_get(12500, &HEAD);
    n_list_traverse(&HEAD, 0);
    ktime_get_real_ts64(&spclock[1]);
    calclock3(spclock, &add_to_hp_list_time, &add_to_hp_list_count);
    
    //printk("found:%d\n", list_entry(found_head, struct node, v_list)->value);
}

int __init simple_module_init(void)
{
    printk(KERN_EMERG "Hello Simple Module\n");
    run();
    return 0;
}

void __exit simple_module_cleanup(void)
{
    printk("time: %llu, count: %llu\n", add_to_hp_list_time, add_to_hp_list_count);
    printk("Bye Simple Module\n");
}

module_init(simple_module_init);
module_exit(simple_module_cleanup);

