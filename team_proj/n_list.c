#include <linux/init.h>
#include <linux/slab.h> // for kmalloc
#include <linux/list.h>


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

void new_sub_head(struct list_head *head)
{
    struct sub_head *new = kmalloc(sizeof(struct sub_head), GFP_KERNEL);
    list_entry(new, struct sub_head, h_list)->len = 0;
    list_add(new->h_list, head);
}

void n_list_add(struct list_head *new, struct list_head *head)
{
    if(list_entry(head->next, struct sub_head, h_list)->length >= 1000) 
        new_sub_head(head);
        
    list_add(new, list_entry(head->next, struct sub_head, h_list)->v_list);
    list_entry(head->next, struct sub_head, h_list)->len++;
    // TODO : Sturct Node
    list_entry(new, struct node, v_list)->_sub = head->next; 
}


void init_n_list(struct list_head *head)
{
    INIT_LIST_HEAD(head);
    new_sub_head(head);
}

int main(void){
    struct list_head HEAD;
    int i;
    
    init_n_list(&HEAD);
    
    for(i=0; i<10; i++)
    {
        struct node *new = kmalloc(sizeof(struct node), GFP_KERNEL);
        new->value = i;
        n_list_add(new->v_list, &HEAD);
    }
    
    struct node *current_node;
    struct list_head *p;
    list_for_each(p, &HEAD)
    {
        current_node = list_entry(p, struct node, v_list);
        printf("%d", current_node->value);
    }
}


