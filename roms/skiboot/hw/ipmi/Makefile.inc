# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

SUBDIRS += hw/ipmi

IPMI_OBJS  = ipmi-rtc.o ipmi-power.o ipmi-fru.o ipmi-sel.o
IPMI_OBJS += ipmi-watchdog.o ipmi-sensor.o ipmi-attn.o ipmi-info.o

IPMI = hw/ipmi/built-in.a
$(IPMI): $(IPMI_OBJS:%=hw/ipmi/%)
