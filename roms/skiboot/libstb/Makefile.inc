# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2020 IBM Corp
# -*-Makefile-*-

LIBSTB_DIR = libstb

SUBDIRS += $(LIBSTB_DIR)

LIBSTB_SRCS = container.c tpm_chip.c cvc.c secureboot.c trustedboot.c
LIBSTB_OBJS = $(LIBSTB_SRCS:%.c=%.o)
LIBSTB = $(LIBSTB_DIR)/built-in.a

include $(SRC)/$(LIBSTB_DIR)/secvar/Makefile.inc
include $(SRC)/$(LIBSTB_DIR)/drivers/Makefile.inc
include $(SRC)/$(LIBSTB_DIR)/crypto/Makefile.inc
include $(SRC)/$(LIBSTB_DIR)/tss2/Makefile.inc

CPPFLAGS += -I$(SRC)/$(LIBSTB_DIR)/crypto/mbedtls/include
CPPFLAGS += -I$(SRC)/$(LIBSTB_DIR)/ibmtpm20tss/utils
CFLAGS += -DTPM_SKIBOOT

$(LIBSTB): $(LIBSTB_OBJS:%=$(LIBSTB_DIR)/%) $(DRIVERS) $(SECVAR) $(CRYPTO) $(TSS2)

libstb/create-container: libstb/create-container.c libstb/container-utils.c
	$(call Q, HOSTCC ,$(HOSTCC) $(HOSTCFLAGS) \
	-Wpadded -O0 -g -I$(SRC) -I$(SRC)/include -o $@ $^ -lssl -lcrypto,$<)

libstb/print-container: libstb/print-container.c libstb/container-utils.c
	$(call Q, HOSTCC , $(HOSTCC) $(HOSTCFLAGS) \
	-O0 -g -I$(SRC) -I$(SRC)/include -o $@ $^ -lssl -lcrypto, $<)

clean: create-container-clean

create-container-clean:
	$(RM) libstb/create-container
