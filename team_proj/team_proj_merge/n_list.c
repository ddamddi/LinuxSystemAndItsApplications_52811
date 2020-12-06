#define SUB_LENGTH 10000
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
//struct mutex my_mutex;
unsigned long long count = 0;

struct list_head thread_list_head;

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

void n_list_traverse(struct list_head* head, int to_find)
{
    INIT_LIST_HEAD(&thread_list_head);
    struct sub_head *current_sub_head;
    struct list_head *hp;
    int thread_counter=0;
    
    list_for_each(hp, head)
    { 
        struct th_info *t_info = kmalloc(sizeof(struct th_info*), GFP_KERNEL);
        current_sub_head = list_entry(hp, struct sub_head, h_list);
        // struct sub_head* arg = kmalloc(sizeof(struct sub_head*), GFP_KERNEL);
        struct thread_arg *arg = kmalloc(sizeof(struct thread_arg*), GFP_KERNEL);
        arg->s = current_sub_head;
        arg->to_find = to_find;
        arg->thread_number = thread_counter;
        thread_counter++;
        
        t_info->g_th_id = kthread_run(_n_list_traverse, (void*)arg, "TRAVERSE");
        list_add(&t_info->list, &thread_list_head);
    }
}

static int _n_list_traverse(void *thread_arg)
{
    struct sub_head *_current_sub_head = ((struct thread_arg*)thread_arg)->s;
    int to_find = ((struct thread_arg*)thread_arg)->to_find;
    int thread_number = ((struct thread_arg*)thread_arg)->thread_number;
    struct node *current_node;
    struct list_head *p;
    int isFound = 0, i;
        
    list_for_each(p, &_current_sub_head->v_list)
    {
        down_read(&counter_rwse);
        current_node = list_entry(p, struct node, v_list);
        // printk("%d\n", current_node->value);
        
        if(current_node->value == to_find)
        {
            isFound = 1;
            up_read(&counter_rwse);
            break;
        }
        up_read(&counter_rwse);
    }
    
    if(isFound)
    {
        // All thread stop
        
        printk("FIND ; %d\n", to_find);
        struct list_head *p;
        struct list_head * new_head = &thread_list_head;
        
        for(i=0; i<thread_number; i++)
        {
            new_head = new_head->next;
        }
        new_head = new_head->next;
        
        list_for_each(p, new_head)
        {
            kthread_stop(list_entry(p, struct th_info, list)->g_th_id);
        }
    }
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
