# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
SUBDIRS += hw/ast-bmc

AST_BMC_OBJS  = ast-io.o ast-sf-ctrl.o

ifeq ($(CONFIG_PLDM),1)
CPPFLAGS += -I$(SRC)/libmctp/
#CFLAGS += -DAST_MCTP_DEBUG
AST_BMC_OBJS += ast-mctp.o
endif

AST_BMC = hw/ast-bmc/built-in.a
$(AST_BMC): $(AST_BMC_OBJS:%=hw/ast-bmc/%)
