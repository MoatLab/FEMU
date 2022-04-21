SUBDIRS += $(PLATDIR)/mambo

MAMBO_OBJS = mambo.o console.o
MAMBO = $(PLATDIR)/mambo/built-in.a
$(MAMBO): $(MAMBO_OBJS:%=$(PLATDIR)/mambo/%)

