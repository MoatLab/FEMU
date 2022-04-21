# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright 2020 IBM Corp
# -*-Makefile-*-

LIBSTB_DIR = libstb
TSS2_DIR = $(LIBSTB_DIR)/tss2
IBMTSS_DIR = $(TSS2_DIR)/ibmtpm20tss/utils

SUBDIRS += $(TSS2_DIR) $(IBMTSS_DIR)

CPPFLAGS += -I$(SRC)/$(LIBSTB_DIR)
CPPFLAGS += -I$(SRC)/$(TSS2_DIR)
CPPFLAGS += -I$(SRC)/$(IBMTSS_DIR)

TSS2LIB_SRCS = tssprint.c tssprintcmd.c tssmarshal.c Unmarshal.c Commands.c
TSS2LIB_SRCS += CommandAttributeData.c tssresponsecode.c tssccattributes.c
TSS2LIB_SRCS += tss.c tss20.c tssauth.c tssauth20.c tssproperties.c tssutils.c
TSS2LIB_SRCS += tsstransmit.c tssdevskiboot.c eventlib.c

TSS2_SRCS = $(addprefix ibmtpm20tss/utils/,$(TSS2LIB_SRCS)) tssskiboot.c eventlog.c

TSS2_OBJS = $(TSS2_SRCS:%.c=%.o)

CFLAGS_$(TSS2_DIR)/ = -DTPM_POSIX -DTPM_TPM20
CFLAGS_$(TSS2_DIR)/ += -DTPM_NOSOCKET -DTPM_TSS_NODEPRECATED
CFLAGS_$(TSS2_DIR)/ += -DTPM_TSS_NOECC -DTPM_TSS_NORSA -DTPM_TSS_NOCRYPTO
CFLAGS_$(TSS2_DIR)/ += -DTPM_TSS_NOFILE -DTPM_TSS_NOENV -DTPM_TSS_NOCMDCHECK

CFLAGS_$(IBMTSS_DIR)/ = $(CFLAGS_$(TSS2_DIR)/)

CFLAGS_SKIP_$(TSS2_DIR)/ = -Wsuggest-attribute=const
CFLAGS_SKIP_$(IBMTSS_DIR)/ = $(CFLAGS_SKIP_$(TSS2_DIR)/)

TSS2 = $(TSS2_DIR)/built-in.a

$(TSS2): $(TSS2_OBJS:%=$(TSS2_DIR)/%)
