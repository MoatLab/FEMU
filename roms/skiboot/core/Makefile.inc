# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright 2012-2019 IBM Corp
# -*-Makefile-*-

SUBDIRS += core
CORE_OBJS = relocate.o console.o stack.o init.o chip.o mem_region.o
CORE_OBJS += malloc.o lock.o cpu.o utils.o fdt.o opal.o interrupts.o timebase.o
CORE_OBJS += opal-msg.o pci.o pci-virt.o pci-slot.o pcie-slot.o
CORE_OBJS += pci-opal.o fast-reboot.o device.o exceptions.o trace.o affinity.o
CORE_OBJS += vpd.o platform.o nvram.o nvram-format.o hmi.o mce.o
CORE_OBJS += console-log.o ipmi.o time-utils.o pel.o pool.o errorlog.o
CORE_OBJS += timer.o i2c.o rtc.o flash.o sensor.o ipmi-opal.o
CORE_OBJS += flash-subpartition.o bitmap.o buddy.o pci-quirk.o powercap.o psr.o
CORE_OBJS += pci-dt-slot.o direct-controls.o cpufeatures.o
CORE_OBJS += flash-firmware-versions.o opal-dump.o

ifeq ($(SKIBOOT_GCOV),1)
CORE_OBJS += gcov-profiling.o
CFLAGS_SKIP_core/gcov-profiling.o = -Wsuggest-attribute=const
endif

CORE=core/built-in.a

CFLAGS_SKIP_core/relocate.o = -pg -fstack-protector-all
CFLAGS_SKIP_core/relocate.o += -fstack-protector -fstack-protector-strong
CFLAGS_SKIP_core/relocate.o += -fprofile-arcs -ftest-coverage

$(CORE): $(CORE_OBJS:%=core/%)
