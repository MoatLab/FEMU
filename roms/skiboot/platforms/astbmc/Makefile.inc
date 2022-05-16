SUBDIRS += $(PLATDIR)/astbmc

ASTBMC_OBJS = pnor.o common.o slots.o \
	      palmetto.o habanero.o firestone.o \
	      p8dtu.o p8dnu.o \
	      garrison.o barreleye.o \
	      witherspoon.o zaius.o romulus.o p9dsu.o \
	      vesnin.o nicole.o mihawk.o mowgli.o \
	      talos.o blackbird.o \
	      swift.o rainier.o

ASTBMC = $(PLATDIR)/astbmc/built-in.a
$(ASTBMC): $(ASTBMC_OBJS:%=$(PLATDIR)/astbmc/%)
