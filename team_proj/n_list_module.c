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

void new_sub_head(struct list_head *head);
void n_list_add(struct list_head *new, struct list_head *head);
void n_list_del(struct list_head *entry, struct list_head *head);
void init_n_list(struct list_head *head);
void run(void);

void new_sub_head(struct list_head *head)
{
    printk("new_sub_head() called\n");
    struct sub_head *new = kmalloc(sizeof(struct sub_head), GFP_KERNEL);
    //list_entry(new, struct sub_head, h_list)->len = 0;
    new->len = 0;
    printk("0\n");
    list_add(&new->h_list, head);
}

void n_list_add(struct list_head *new, struct list_head *head)
{
    printk("n_list_add() called\n");
    if(list_entry(head->next, struct sub_head, h_list)->len >= 1000) 
        new_sub_head(head);
        
    printk("0\n");
    struct sub_head *tmp = list_entry(head->next, struct sub_head, h_list);
    printk("%d\n", tmp->len);
    
    printk("1\n");
    list_add(new, &tmp->v_list);
    
    printk("2\n");
    list_entry(head->next, struct sub_head, h_list)->len++;
    
    // TODO : Sturct Node
    printk("3\n");
    list_entry(new, struct node, v_list)->_sub = list_entry(head->next, struct sub_head, h_list); 
}


void init_n_list(struct list_head *head)
{
    printk("init_n_list() called\n");
    INIT_LIST_HEAD(head);
    new_sub_head(head);
}

void run(void){
    struct list_head HEAD;
    int i;
    
    init_n_list(&HEAD);
    printk("INITIALIZE HEAD\n");
    
    for(i=0; i<10; i++)
    {
        struct node *new = kmalloc(sizeof(struct node), GFP_KERNEL);
        new->value = i;
        n_list_add(&new->v_list, &HEAD);
        printk("ADD NEW NODE\n");
    }
    
    struct node *current_node;
    struct list_head *p;
    printk("START TRAVERSE\n");
    list_for_each(p, &HEAD)
    {
        current_node = list_entry(p, struct node, v_list);
        printk("%d\n", current_node->value);
    }
}

int __init simple_module_init(void)
{
    printk(KERN_EMERG "Hello Simple Module\n");
    run();
    return 0;
}

void __exit simple_module_cleanup(void)
{
    printk("Bye Simple Module\n");
}

module_init(simple_module_init);
module_exit(simple_module_cleanup);
