#define BILLION 1000000000
#define NUM_OF_ENTRY 100000

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>

unsigned long long add_to_hp_list_time = 0;
unsigned long long add_to_hp_list_count = 0;
struct timespec64 spclock[2];

struct node{
   struct list_head list;
   int value;
};


unsigned long long list_insert_time=0;
unsigned long long list_insert_count=0;
unsigned long long list_delete_time=0;
unsigned long long list_delete_count=0;
unsigned long long list_get_time=0;
unsigned long long list_get_count=0;
unsigned long long list_traverse_time=0;
unsigned long long list_traverse_count=0;

void initialize_ts64(struct timespec64 *spclock);
unsigned long long calclock3(struct timespec64 *spclock, unsigned long long *total_time, unsigned long long *total_count);
struct list_head* list_get(int index,struct list_head* head);
void list_test_insert(void);
void list_test_delete(void);
void list_test_get(void);
void list_test_traverse(void);

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


struct list_head* list_get(int index, struct list_head* head)
{
   struct list_head *current_list=head->prev;
   int i;
   for (i=0;i<index;i++)
   {
      current_list=current_list->prev;
   }
   
   return current_list;
}

void list_test_insert(void)
{   
    struct list_head HEAD;
    
    INIT_LIST_HEAD(&HEAD);
    
    int i;
    for (i=0;i<NUM_OF_ENTRY;i++)
    {
       struct node* new=kmalloc(sizeof(struct node),GFP_KERNEL);
       new->value=i;
       list_add(&new->list,&HEAD);
    }    

    
    //INSERT
    ktime_get_real_ts64(&spclock[0]);
    struct node* new=kmalloc(sizeof(struct node),GFP_KERNEL);
    new->value=NUM_OF_ENTRY;
    list_add(&new->list,&HEAD);
    ktime_get_real_ts64(&spclock[1]);
    calclock3(spclock, &list_insert_time, &list_insert_count);
}

void list_test_delete(void)
{
   struct list_head HEAD;
    
    INIT_LIST_HEAD(&HEAD);
    
    int i;
    for (i=0;i<NUM_OF_ENTRY;i++)
    {
       struct node* new=kmalloc(sizeof(struct node),GFP_KERNEL);
       new->value=i;
       list_add(&new->list,&HEAD);
    }    


    //DELETE
    ktime_get_real_ts64(&spclock[0]);
    list_del(HEAD.next);
    ktime_get_real_ts64(&spclock[1]);
    calclock3(spclock, &list_delete_time, &list_delete_count);
}

void list_test_get(void)
{
    struct list_head HEAD;
    
    INIT_LIST_HEAD(&HEAD);
    
    int i;
    for (i=0;i<NUM_OF_ENTRY;i++)
    {
       struct node* new=kmalloc(sizeof(struct node),GFP_KERNEL);
       new->value=i;
       list_add(&new->list,&HEAD);
    }    


    //TRAVERSE
    struct node *current_node;
    struct list_head *p;
    struct list_head* found_head;
    
    for (i=99999;i<NUM_OF_ENTRY;i++)
    {
    	ktime_get_real_ts64(&spclock[0]);
        found_head=list_get(i, &HEAD);
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &list_get_time, &list_get_count);
    }
}

void list_test_traverse(void)
{
    struct list_head HEAD;
    INIT_LIST_HEAD(&HEAD);
    
    int i;
    for (i=0;i<NUM_OF_ENTRY;i++)
    {
       struct node* new=kmalloc(sizeof(struct node),GFP_KERNEL);
       new->value=i;
       list_add(&new->list,&HEAD);
    }    


    //TRAVERSE
    struct node *current_node;
    int tmp;
    struct list_head *p;
    struct list_head *current_list = &HEAD;
    
    ktime_get_real_ts64(&spclock[0]);
    list_for_each(p, &HEAD)
    {
       current_node=list_entry(p,struct node,list);
    }
    
    for(i=0; i<NUM_OF_ENTRY; i++){
    	current_list = current_list->next;
    	tmp = list_entry(current_list, struct node, list)->value;
    }
    ktime_get_real_ts64(&spclock[1]);
    calclock3(spclock, &list_traverse_time, &list_traverse_count);
}


int __init simple_module_init(void)
{
    printk(KERN_EMERG "list testing Module\n");
    list_test_insert();
    list_test_delete();
    list_test_get();
    list_test_traverse();
    return 0;
}

void __exit simple_module_cleanup(void)
{
    printk("list testing Done\n");
    printk("list insert time : %llu, count: %llu\n", list_insert_time, list_insert_count);
    printk("list delete time : %llu, count: %llu\n", list_delete_time, list_delete_count);
    printk("list get time : %llu, count: %llu\n", list_get_time, list_get_count);
    printk("list traverse time : %llu, count: %llu\n", list_traverse_time, list_traverse_count);
}

module_init(simple_module_init);
module_exit(simple_module_cleanup);
