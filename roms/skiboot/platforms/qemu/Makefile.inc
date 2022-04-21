SUBDIRS += $(PLATDIR)/qemu

QEMU_OBJS = qemu.o
QEMU = $(PLATDIR)/qemu/built-in.a
$(QEMU): $(QEMU_OBJS:%=$(PLATDIR)/qemu/%)

