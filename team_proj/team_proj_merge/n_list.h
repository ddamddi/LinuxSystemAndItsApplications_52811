#ifndef __N_LIST_H
#define __N_LIST_H

#include <linux/list.h>
#include <linux/completion.h>
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

struct origin_node
{
    struct list_head list;
    int value;
};


struct task{
    struct list_head t_list;
    struct sub_head* todo;
};


struct thread_arg{
    struct list_head* tasks;
    int to_find;
    struct timespec64* spclock;
    unsigned long long* time;
    unsigned long long* count;
};


void new_sub_head(struct list_head *head);
void n_list_add(struct list_head *new, struct list_head *head);
void n_list_del(struct list_head *entry, struct list_head *head);
void n_list_del_stable(struct list_head *entry, struct list_head *head);
void n_list_traverse(struct list_head *head, int _to_find, struct timespec64* _spclock, unsigned long long* _time, unsigned long long* _count);
static int _n_list_traverse(void *current_sub_head);
struct list_head* n_list_get(int index, struct list_head* head);
struct list_head* n_list_get_stable(int index, struct list_head* head);
void init_n_list(struct list_head *head);


#endif
