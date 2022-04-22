# SPDX-License-Identifier: GPL-2.0+
#
# (C) Copyright 2004
# Psyent Corporation <www.psyent.com>
# Scott McNutt <smcnutt@psyent.com>

CONFIG_STANDALONE_LOAD_ADDR ?= 0x02000000

PLATFORM_CPPFLAGS += -D__NIOS2__
PLATFORM_CPPFLAGS += -G0

LDFLAGS_FINAL += --gc-sections
PLATFORM_RELFLAGS += -ffunction-sections -fdata-sections
