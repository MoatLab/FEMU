#ifndef MENU_LIST_H
#define MENU_LIST_H

#ifndef bool_defined
#define bool_defined
typedef int bool;
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#ifndef NULL
#define NULL ((void *)0L)
#endif


/* List functions */
typedef struct node_s
{
    struct node_s *prev;
    struct node_s *next;
} node_t;

typedef struct list_s
{
    node_t *first;
    node_t *last;
} mylist_t;

//void list_init(mylist_t *list);
//void list_add(mylist_t *list, node_t *node);
//bool list_empty(mylist_t *list);

#endif //MENU_LIST_H
