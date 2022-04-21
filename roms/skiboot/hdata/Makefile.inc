# -*-Makefile-*-

SUBDIRS += hdata
HDATA_OBJS = naca.o spira.o pcia.o hdif.o memory.o fsp.o iohub.o vpd.o slca.o
HDATA_OBJS += cpu-common.o vpd-common.o hostservices.o i2c.o tpmrel.o
DEVSRC_OBJ = hdata/built-in.a

$(DEVSRC_OBJ): $(HDATA_OBJS:%=hdata/%)
