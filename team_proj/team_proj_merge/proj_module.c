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
#include "n_list.h"

unsigned long long list_insert_time=0;
unsigned long long list_insert_count=0;
unsigned long long list_delete_time=0;
unsigned long long list_delete_count=0;
unsigned long long list_get_time=0;
unsigned long long list_get_count=0;
unsigned long long list_search_time=0;
unsigned long long list_search_count=0;

unsigned long long n_list_insert_time = 0;
unsigned long long n_list_insert_count = 0;
unsigned long long n_list_delete_time = 0;
unsigned long long n_list_delete_count = 0;
unsigned long long n_list_delete_s_time = 0;
unsigned long long n_list_delete_s_count = 0;
unsigned long long n_list_get_time = 0;
unsigned long long n_list_get_count = 0;
unsigned long long n_list_get_s_time = 0;
unsigned long long n_list_get_s_count = 0;
unsigned long long n_list_search_time = 0;
unsigned long long n_list_search_count = 0;
struct timespec64 spclock[2];

//////////////////////////////////////////////////
struct list_head* list_get(int index, struct list_head* head);
void list_test_insert(void);
void list_test_delete(void);
void list_test_get(void);
void list_test_search(void);

void n_list_test_insert(void);
void n_list_test_delete(void);
void n_list_test_delete_stable(void);
void n_list_test_get(void);
void n_list_test_get_stable(void);
void n_list_test_search(void);
void initialize_ts64(struct timespec64* spclock);
unsigned long long calclock3(struct timespec64* spclock, unsigned long long* total_time, unsigned long long* total_count);

void initialize_ts64(struct timespec64* spclock)
{
    int i;
    for (i=0; i<2; i++)
    {
        spclock[i].tv_sec = 0;
        spclock[i].tv_nsec = 0;
    }
}
unsigned long long calclock3(struct timespec64* spclock, unsigned long long* total_time, unsigned long long* total_count)
{
    unsigned long long timedelay = 0, temp, temp_n;
    
    if (spclock[1].tv_nsec >= spclock[0].tv_nsec)
    {
        temp = spclock[1].tv_sec - spclock[0].tv_sec;
        temp_n = spclock[1].tv_nsec - spclock[0].tv_nsec;
        timedelay = BILLION * temp + temp_n;
    }
    else
    {
        temp = spclock[1].tv_sec - spclock[0].tv_sec -1;
        temp_n = BILLION + spclock[1].tv_nsec - spclock[0].tv_nsec;
        timedelay = BILLION * temp + temp_n;
    }
    __sync_fetch_and_add(total_time, timedelay);
    __sync_fetch_and_add(total_count, 1);
    return timedelay;
}

/////////////////////////original list testing function ////////////////////////////////

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
    int i;
    struct list_head HEAD;
    INIT_LIST_HEAD(&HEAD);
    
    for (i=0;i<NUM_OF_ENTRY;i++)
    {
        struct origin_node* new=kmalloc(sizeof(struct origin_node),GFP_KERNEL);
        new->value=i;
        ktime_get_real_ts64(&spclock[0]);
        list_add(&new->list,&HEAD);
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &list_insert_time, &list_insert_count);
    }    
}

void list_test_delete(void)
{
   struct list_head HEAD;
    
    INIT_LIST_HEAD(&HEAD);
    
    int i;
    for (i=0;i<NUM_OF_ENTRY;i++)
    {
       struct origin_node* new=kmalloc(sizeof(struct origin_node),GFP_KERNEL);
       new->value=i;
       list_add(&new->list,&HEAD);
    }    


    //DELETE
    for (i=0;i<NUM_OF_ENTRY;i++)
    {
        ktime_get_real_ts64(&spclock[0]);
        list_del(HEAD.next);
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &list_delete_time, &list_delete_count);
    }    
}

void list_test_get(void)
{
    int i;
    struct list_head HEAD;
    init_n_list(&HEAD);
    
    for (i=0; i<NUM_OF_ENTRY; i++)
    {
        struct node *new = kmalloc(sizeof(struct node), GFP_KERNEL);
        new->value = i;
        n_list_add(&new->v_list, &HEAD);
    }

    // GET
    //struct list_head* found_head;
    
    for (i=0;i<NUM_OF_ENTRY;i++)
    {
    	ktime_get_real_ts64(&spclock[0]);
        struct list_head* found_head = list_get(i, &HEAD);
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &list_get_time, &list_get_count);
    }
}

void list_test_search(void)
{
    struct list_head HEAD;
    INIT_LIST_HEAD(&HEAD);
    
    int i;
    for (i=0;i<NUM_OF_ENTRY;i++)
    {
       struct origin_node* new=kmalloc(sizeof(struct origin_node),GFP_KERNEL);
       new->value=i;
       list_add(&new->list,&HEAD);
    }    


    // SEARCH
    struct origin_node *current_node;
    struct list_head *p;
    /*
    for(i=0; i<NUM_OF_ENTRY; i+=99999){
        ktime_get_real_ts64(&spclock[0]);
        list_for_each(p, &HEAD)
        {
            current_node=list_entry(p, struct origin_node, list);
            if(current_node->value == i)
       	        break;
        }
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &list_search_time, &list_search_count);
    }*/
    ktime_get_real_ts64(&spclock[0]);
    list_for_each(p, &HEAD)
    {
        current_node=list_entry(p, struct origin_node, list);
        if(current_node->value == 49999)
            break;
    }
    ktime_get_real_ts64(&spclock[1]);
    calclock3(spclock, &list_search_time, &list_search_count);
}

///////////////////////// n_list testing function //////////////////////

void n_list_test_insert(void)
{
    int i;
    struct list_head HEAD;
    init_n_list(&HEAD);
    
    for (i=0;i<NUM_OF_ENTRY;i++)
    {
        struct node* new=kmalloc(sizeof(struct node),GFP_KERNEL);
        new->value=i;
        ktime_get_real_ts64(&spclock[0]);
        n_list_add(&new->v_list, &HEAD);
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &n_list_insert_time, &n_list_insert_count);
    }
}


void n_list_test_delete(void)
{
    int i;
    struct list_head HEAD;
    init_n_list(&HEAD);
    
    for (i=0; i<NUM_OF_ENTRY; i++)
    {
        struct node *new = kmalloc(sizeof(struct node), GFP_KERNEL);
        new->value = i;
        n_list_add(&new->v_list, &HEAD);
    }
    
    //DELETE
    for (i=0;i<NUM_OF_ENTRY;i++)
    {
        struct list_head *tmp = &list_entry(HEAD.next, struct sub_head, h_list)->v_list;
        ktime_get_real_ts64(&spclock[0]);
        n_list_del(tmp->prev, &HEAD);
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &n_list_delete_time, &n_list_delete_count);
    }
}
void n_list_test_delete_stable(void)
{
    int i;
    struct list_head HEAD;
    init_n_list(&HEAD);
    
    for (i=0; i<NUM_OF_ENTRY; i++)
    {
        struct node *new = kmalloc(sizeof(struct node), GFP_KERNEL);
        new->value = i;
        n_list_add(&new->v_list, &HEAD);
    }
    
    //DELETE STABLE
    for (i=0;i<NUM_OF_ENTRY;i++)
    {
        struct list_head *tmp = &list_entry(HEAD.next, struct sub_head, h_list)->v_list;
        ktime_get_real_ts64(&spclock[0]);
        n_list_del_stable(tmp->next, &HEAD);
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &n_list_delete_s_time, &n_list_delete_s_count);
    }
}

void n_list_test_get(void)
{
    initialize_ts64(spclock);
    struct list_head HEAD;
    init_n_list(&HEAD);
    int i;
    for (i=0; i<NUM_OF_ENTRY; i++)
    {
        struct node *new = kmalloc(sizeof(struct node), GFP_KERNEL);
        new->value = i;
        n_list_add(&new->v_list, &HEAD);
    }
    
    for (i=0; i<NUM_OF_ENTRY; i++)
    {
        ktime_get_real_ts64(&spclock[0]);
        struct list_head* found = n_list_get(i, &HEAD);
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &n_list_get_time, &n_list_get_count);
    }
}

void n_list_test_get_stable(void)
{
    initialize_ts64(spclock);
    struct list_head HEAD;
    init_n_list(&HEAD);
    int i;
    for (i=0; i<NUM_OF_ENTRY; i++)
    {
        struct node *new = kmalloc(sizeof(struct node), GFP_KERNEL);
        new->value = i;
        n_list_add(&new->v_list, &HEAD);
    }
    
    for (i=0; i<NUM_OF_ENTRY; i++)
    {
        ktime_get_real_ts64(&spclock[0]);
        struct list_head* found = n_list_get_stable(i, &HEAD);
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &n_list_get_s_time, &n_list_get_s_count);
    }
}

void n_list_test_search(void)
{
    int i;
    struct list_head HEAD;
    init_n_list(&HEAD);    
    
    for (i=0; i<NUM_OF_ENTRY; i++)
    {
        struct node *new = kmalloc(sizeof(struct node), GFP_KERNEL);
        new->value = i;
        n_list_add(&new->v_list, &HEAD);
    }
    
    n_list_traverse(&HEAD, 49999, spclock, &n_list_search_time, &n_list_search_count);
  
}

int __init proj_module_init(void)
{
    printk(KERN_EMERG "Linux list testing\n");
    list_test_insert();
    list_test_delete();
    //list_test_get();
    list_test_search();
    
    printk(KERN_EMERG "Multi-head list testing\n");
    n_list_test_insert();
    //n_list_test_delete();
    n_list_test_delete_stable();
    //n_list_test_get();
    //n_list_test_get_stable();
    n_list_test_search();
    
    return 0;
}

void __exit proj_module_cleanup(void)
{
    printk("====Linux list testing Done====\n");
    printk("Linux list INSERT time : %llu\n", list_insert_time/list_insert_count);
    printk("Linux list DELETE time : %llu\n", list_delete_time/list_delete_count);
    //printk("List GET time : %llu\n", list_get_time/list_get_count);
    printk("List SEARCH time : %llu\n", list_search_time/list_search_count);
    
    printk("====Multi-head list testing Done====\n");
    printk("Multi-head list INSERT time : %llu\n", n_list_insert_time/n_list_insert_count);
    //printk("Multi-head list DELETE time : %llu\n", n_list_delete_time/ n_list_delete_count);
    printk("Multi-head list DELETE_S time : %llu\n", n_list_delete_s_time/ n_list_delete_s_count);
    //printk("Multi-head list GET time : %llu\n", n_list_get_time/ n_list_get_count);
    //printk("Multi-head list GET_S time : %llu\n", n_list_get_s_time, n_list_get_s_count);
    printk("Multi-head list SEARCH time : %llu\n", n_list_search_time/ n_list_search_count);
    
}

module_init(proj_module_init);
module_exit(proj_module_cleanup);
