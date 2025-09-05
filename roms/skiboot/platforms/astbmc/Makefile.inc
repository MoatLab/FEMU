SUBDIRS += $(PLATDIR)/astbmc

ASTBMC_OBJS = pnor.o common.o slots.o \
	      witherspoon.o zaius.o romulus.o p9dsu.o \
	      nicole.o mihawk.o mowgli.o \
	      talos.o blackbird.o \
	      swift.o rainier.o

ifeq ($(CONFIG_P8),1)
ASTBMC_OBJS += palmetto.o habanero.o firestone.o \
	      p8dtu.o p8dnu.o \
	      garrison.o barreleye.o \
	      vesnin.o
endif

ASTBMC = $(PLATDIR)/astbmc/built-in.a
$(ASTBMC): $(ASTBMC_OBJS:%=$(PLATDIR)/astbmc/%)
