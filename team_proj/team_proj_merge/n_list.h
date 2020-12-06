#ifndef __N_LIST_H
#define __N_LIST_H

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

struct thread_arg{
    struct sub_head* s;
    int to_find;
    int thread_number;
};

struct th_info{
    struct list_head list;
    struct task_struct *g_th_id;
};

void new_sub_head(struct list_head *head);
void n_list_add(struct list_head *new, struct list_head *head);
void n_list_del(struct list_head *entry, struct list_head *head);
void n_list_traverse(struct list_head *head, int to_find);
static int _n_list_traverse(void *current_sub_head);
struct list_head* n_list_get(int index, struct list_head* head);
void init_n_list(struct list_head *head);


#endif
