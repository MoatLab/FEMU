SUBDIRS += $(PLATDIR)/rhesus

RHESUS_OBJS = rhesus.o gpio.o
RHESUS = $(PLATDIR)/rhesus/built-in.a
$(RHESUS): $(RHESUS_OBJS:%=$(PLATDIR)/rhesus/%)

