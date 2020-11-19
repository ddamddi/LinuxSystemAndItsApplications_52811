#define BILLION 1000000000
#define NUM_OF_ENTRY 100000

#define INSERT 0
#define SEARCH 1
#define DELETE 2

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h> // for thread
#include <linux/slab.h> // for kmalloc
#include <linux/delay.h>
#include <linux/rbtree.h> // for Red-Black tree
#include <linux/time.h>

void insert(void);
void search(void);
void delete(void);
void rb_init_node(struct rb_node *rb);
void rbtree_print(void);

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


void initialize_ts64(struct timespec64 *spclock)
{
    int i;
    for(i=0; i<2; i++)
    {
        spclock[i].tv_sec = 0;
    	spclock[i].tv_nsec = 0;
    }
}


struct my_node{
    struct rb_node node;
    unsigned int key;
    unsigned int value;
};

unsigned long long add_to_hp_list_time = 0;
unsigned long long add_to_hp_list_count = 0;
struct timespec64 spclock[2];
struct rb_root root_node = RB_ROOT;


void rb_init_node(struct rb_node *rb)
{
   rb->__rb_parent_color = 0;
   rb->rb_right = NULL;
   rb->rb_left = NULL;
   RB_CLEAR_NODE(rb);
}


void rbtree_print()
{
    struct rb_node *iter_node; 
    for(iter_node=rb_first(&root_node); iter_node; iter_node=rb_next(iter_node))
    {
    	printk("(K,V)=(%d, %d)\n", rb_entry(iter_node, struct my_node, node)->key, rb_entry(iter_node, struct my_node, node)->value);
    }
}


void insert()
{
    int i;

    /* init timespec */
    initialize_ts64(spclock);
        
    /* Create Red-Black Tree and Insert RB Node */
    for(i=0; i<NUM_OF_ENTRY; i++)
    {
        struct my_node *new_node = kmalloc(sizeof(struct my_node), GFP_KERNEL);
        if(!new_node)
        {
            printk("NULL POINTER ERROR\n");
            return;
        }
        rb_init_node(&new_node->node);

        new_node->value = i*10;
        new_node->key = i;
        
        struct rb_node **new = &(root_node.rb_node);
        struct rb_node *parent = NULL;
        
        ktime_get_real_ts64(&spclock[0]);
        while(*new)
        {
            struct my_node *connect = rb_entry(*new, struct my_node, node);
            
            parent = *new;
            if(new_node->key > connect->key)
                new = &((*new)->rb_left);
            else if (new_node->key < connect->key)
            	new = &((*new)->rb_right);
            else
            	printk("RB-TREE INSERT ERROR");
        }
        
	rb_link_node(&new_node->node, parent, new);	// link new node
	rb_insert_color(&new_node->node, &root_node);  // Rearrange red-black tree node color
	
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &add_to_hp_list_time, &add_to_hp_list_count);
        
    }
        
    // rbtree_print();
    
    /* Print Result */
    printk("INSERT %d Entries\n", NUM_OF_ENTRY);
    printk("add_to_hp_list_time: %llu, count: %llu\n", add_to_hp_list_time, add_to_hp_list_count);
}


void search(){
    int i;
    
    /* init timespec */
    initialize_ts64(spclock);
    
    /* Create Red-Black Tree and Insert RB Node */
    for(i=0; i<NUM_OF_ENTRY; i++)
    {
        struct my_node *new_node = kmalloc(sizeof(struct my_node), GFP_KERNEL);
        if(!new_node)
        {
            printk("NULL POINTER ERROR\n");
            return;
        }
        rb_init_node(&new_node->node);

        new_node->value = i*10;
        new_node->key = i;
        
        struct rb_node **new = &(root_node.rb_node);
        struct rb_node *parent = NULL;
        
        
        while(*new)
        {
            struct my_node *connect = rb_entry(*new, struct my_node, node);
            
            parent = *new;
            if (new_node->key > connect->key)
                new = &((*new)->rb_left);
            else if (new_node->key < connect->key)
            	new = &((*new)->rb_right);
            else
            	printk("RB-TREE INSERT ERROR");
        }

	rb_link_node(&new_node->node, parent, new);	// link new node
	rb_insert_color(&new_node->node, &root_node);  // Rearrange red-black tree node color         
    }
    
    /* Search */
    for(i=0; i<NUM_OF_ENTRY; i++)
    {
        struct rb_node *iter_node;
        
        ktime_get_real_ts64(&spclock[0]);

    	for(iter_node=rb_first(&root_node); iter_node; iter_node=rb_next(iter_node))
    	{
    	    if (i == rb_entry(iter_node, struct my_node, node)->key)
    	        break;
    	}
    
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &add_to_hp_list_time, &add_to_hp_list_count);
    }
    
    // rbtree_print();
    
    /* Print Result */
    printk("SEARCH %d Entries\n", NUM_OF_ENTRY);
    printk("add_to_hp_list_time: %llu, count: %llu\n", add_to_hp_list_time, add_to_hp_list_count);
}


void delete(){
    int i;
    
    /* init timespec */
    initialize_ts64(spclock);
    
    /* Create Red-Black Tree and Insert RB Node */
    for(i=0; i<NUM_OF_ENTRY; i++)
    {
        struct my_node *new_node = kmalloc(sizeof(struct my_node), GFP_KERNEL);
        if(!new_node)
        {
            printk("NULL POINTER ERROR\n");
            return;
        }
        rb_init_node(&new_node->node);

        new_node->value = i*10;
        new_node->key = i;
        
        struct rb_node **new = &(root_node.rb_node);
        struct rb_node *parent = NULL;
        
        
        while(*new)
        {
            struct my_node *connect = rb_entry(*new, struct my_node, node);
            
            parent = *new;
            if (new_node->key > connect->key)
                new = &((*new)->rb_left);
            else if (new_node->key < connect->key)
            	new = &((*new)->rb_right);
            else
            	printk("RB-TREE INSERT ERROR");
        }

	rb_link_node(&new_node->node, parent, new);	// link new node
	rb_insert_color(&new_node->node, &root_node);  // Rearrange red-black tree node color         
    }
    
    /* Delete Node */
    for(i=0; i<NUM_OF_ENTRY; i++)
    {
        struct rb_node *iter_node;
        
        ktime_get_real_ts64(&spclock[0]);

    	for(iter_node=rb_first(&root_node); iter_node; iter_node=rb_next(iter_node))
    	{
    	    if (i == rb_entry(iter_node, struct my_node, node)->key)
    	    {
    	        rb_erase(iter_node, &root_node);
    	        kfree(iter_node);
		break;
    	    }
    	}
    	
        ktime_get_real_ts64(&spclock[1]);
        calclock3(spclock, &add_to_hp_list_time, &add_to_hp_list_count);
    }
    
    // rbtree_print();
    
    /* Print Result */
    printk("DELETE %d Entries\n", NUM_OF_ENTRY);
    printk("add_to_hp_list_time: %llu, count: %llu\n", add_to_hp_list_time, add_to_hp_list_count);
}


void rbtree_example(int op)
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


int __init rbtree_module_init(void)
{
    printk(KERN_EMERG "Hello RB-Tree Module\n");
    int op = DELETE;
    rbtree_example(op);
    return 0;
}


void __exit rbtree_module_cleanup(void)
{
    printk("Bye RB-Tree Module\n");
}


module_init(rbtree_module_init);
module_exit(rbtree_module_cleanup);
