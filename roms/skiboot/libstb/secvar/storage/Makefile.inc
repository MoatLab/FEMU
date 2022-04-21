# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# -*-Makefile-*-

SECVAR_STORAGE_DIR = libstb/secvar/storage

SUBDIRS += $(SECVAR_STORAGE_DIR)

# Swap the comment on these two lines to use the fake TPM NV
# implementation hardware without a TPM
SECVAR_STORAGE_OBJS = secboot_tpm.o tpmnv_ops.o
#SECVAR_STORAGE_OBJS = secboot_tpm.o fakenv_ops.o

SECVAR_STORAGE = $(SECVAR_STORAGE_DIR)/built-in.a

$(SECVAR_STORAGE): $(SECVAR_STORAGE_OBJS:%=$(SECVAR_STORAGE_DIR)/%)

gen_tpmnv_public_name: $@
	$(HOSTCC) -o $@ $(SECVAR_STORAGE_DIR)/$@.c -I $(SRC)/libstb/tss2/ibmtpm20tss/utils/ -lmbedcrypto
