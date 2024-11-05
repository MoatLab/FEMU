# -*-Makefile-*-

SUBDIRS += ccan ccan/list ccan/str ccan/heap
CCAN_OBJS = list/list.o str/str.o heap/heap.o
CCAN=ccan/built-in.a

$(CCAN): $(CCAN_OBJS:%=ccan/%)

