#ifndef LISTSUPPORT_H
#define LISTSUPPORT_H

struct mynode
{
  struct mynode * mln_Succ;
  struct mynode * mln_Pred;
};

struct fullNode
{
  struct mynode * ln_Succ;
  struct mynode * ln_Pred;
  BYTE ln_Pri;
  UBYTE ln_padding[3];
};

#define Node mynode

struct MinList {
   struct  mynode *mlh_Head;
   struct  mynode *mlh_Tail;
   struct  mynode *mlh_TailPred;
};

//#define MinList List

#define islistempty(x) ( ((x)->mlh_TailPred) == (struct mynode *)(x) )
#define IsListEmpty(l) islistempty(l)

#define newminlist(lp)                                               \
	{                                                        \
	    (lp)->mlh_Head       = (struct mynode *) &(lp)->mlh_Tail;\
	    (lp)->mlh_Tail       = 0;                              \
	    (lp)->mlh_TailPred   = (struct mynode *) &(lp)->mlh_Head;\
	}

#define NewList(x) newminlist(x)

#define addhead(ls, n) do{\
                       (n)->mln_Succ = (ls)->mlh_Head;\
                       (n)->mln_Pred = (struct mynode *)(ls);\
                       (ls)->mlh_Head = (n);\
                       (n)->mln_Succ->mln_Pred = (n);\
                       } while(0)


#define AddHead(l, n) addhead(l, n)

#define addtail(ls, n) do {\
	(n)->mln_Succ = (struct mynode *) (&((ls)->mlh_Tail));\
	(n)->mln_Pred = (ls)->mlh_TailPred;\
	(n)->mln_Pred->mln_Succ = (n);\
	(ls)->mlh_TailPred = (n);\
} while(0)

#define AddTail(ls, n) addtail(ls, n)

#define remove(n) do {\
	(n)->mln_Succ->mln_Pred = (n)->mln_Pred;\
	(n)->mln_Pred->mln_Succ = (n)->mln_Succ;\
} while(0)

/* WARNING: due to the nature of the scanning routines (see os4_parse_kickdef.c)
you mustn't fold the removed node's links into itself, otherwise an infinite loop will result.
*/

#define Remove(n) remove(n)

#endif  /* LISTSUPPORT_H */
