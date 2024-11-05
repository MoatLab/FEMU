# -*-Makefile-*-

DRIVERS_DIR = libstb/drivers

SUBDIRS += $(DRIVERS_DIR)

DRIVERS_SRCS = tpm_i2c_interface.c tpm_i2c_nuvoton.c
DRIVERS_OBJS = $(DRIVERS_SRCS:%.c=%.o)
DRIVERS = $(DRIVERS_DIR)/built-in.a

$(DRIVERS): $(DRIVERS_OBJS:%=$(DRIVERS_DIR)/%)
