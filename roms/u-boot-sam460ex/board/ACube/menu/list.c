//#include "menu.h"
#include "list.h"
void list_init(mylist_t *l)
{
    l->first = NULL;
    l->last  = NULL;
}

bool list_empty(mylist_t *l)
{
    if (l->first == NULL) 	return true;
    else 					return false;
}

void list_add(mylist_t *l, node_t *n)
{
    if (l->first == NULL)
    {
		l->first = n;
		l->last = n;
		n->prev = NULL;
		n->next = NULL;
    }
    else
    {
		node_t *b = l->last;
		l->last = n;

		n->prev = b;
		n->next = 0;

		b->next = n;
    }
}


    
