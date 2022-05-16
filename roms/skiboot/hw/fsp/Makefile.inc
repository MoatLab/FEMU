SUBDIRS += hw/fsp

FSP_OBJS  = fsp.o fsp-console.o fsp-rtc.o fsp-nvram.o fsp-sysparam.o
FSP_OBJS += fsp-surveillance.o fsp-codeupdate.o fsp-sensor.o
FSP_OBJS += fsp-diag.o fsp-leds.o fsp-mem-err.o fsp-op-panel.o
FSP_OBJS += fsp-elog-read.o fsp-elog-write.o fsp-epow.o fsp-dpo.o
FSP_OBJS += fsp-dump.o fsp-sysdump.o fsp-chiptod.o fsp-ipmi.o
FSP_OBJS += fsp-attn.o fsp-occ.o fsp-psi.o
FSP = hw/fsp/built-in.a

ifeq ($(CONFIG_FSP),1)
$(FSP): $(FSP_OBJS:%=hw/fsp/%)
endif
