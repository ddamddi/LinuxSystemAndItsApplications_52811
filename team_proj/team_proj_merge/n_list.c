#define SUB_LENGTH 1000
#define NUM_OF_ENTRY 100000

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h> // for thread
#include <linux/slab.h> // for kmalloc
#include <linux/delay.h>
#include <linux/sched.h>
#include "n_list.h"

struct rw_semaphore counter_rwse;
struct mutex my_mutex;
unsigned long long count = 0;

void new_sub_head(struct list_head *head)
{
    struct sub_head *new = kmalloc(sizeof(struct sub_head), GFP_KERNEL);
    INIT_LIST_HEAD(&new->v_list);
    new->len = 0;
    list_add(&new->h_list, head);
}

void n_list_add(struct list_head *new, struct list_head *head)
{
    if(list_entry(head->next, struct sub_head, h_list)->len >= SUB_LENGTH) 
        new_sub_head(head);
        
    struct sub_head *tmp = list_entry(head->next, struct sub_head, h_list);
    //printk("%d\n", tmp->len);
    
    list_add(new, &tmp->v_list);
    
    list_entry(head->next, struct sub_head, h_list)->len++;
    
    // TODO : sturct node
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
        current_sub_head = list_entry(hp, struct sub_head, h_list);
        struct sub_head* arg = kmalloc(sizeof(struct sub_head*), GFP_KERNEL);
        arg = current_sub_head;
        kthread_run(_n_list_traverse, (void*)arg, "TRAVERSE");
    }
       
    while(1)
    {
    	if(count == NUM_OF_ENTRY)
    	    break;
    	//printk("count: %d  NUM_OF_ENTRY: 100000\n", count);
    	msleep(1);
    }
}

static int _n_list_traverse(void *current_sub_head)
{
    struct sub_head *_current_sub_head = current_sub_head;
    struct node *current_node;
    struct list_head *p;
        
    list_for_each(p, &_current_sub_head->v_list)
    {
        down_read(&counter_rwse);
        current_node = list_entry(p, struct node, v_list);
        // printk("%d\n", current_node->value);
        up_read(&counter_rwse);
    }
    mutex_lock(&my_mutex);
    count += _current_sub_head->len;
    mutex_unlock(&my_mutex);
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
