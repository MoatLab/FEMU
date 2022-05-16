# SeaBIOS build system
#
# Copyright (C) 2008-2012  Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU LGPLv3 license.

# Output directory
OUT=out/

# Common command definitions
export HOSTCC             := $(CC)
export CONFIG_SHELL       := sh
export KCONFIG_AUTOHEADER := autoconf.h
export KCONFIG_CONFIG     := $(CURDIR)/.config
export LC_ALL             := C
CROSS_PREFIX=
ifneq ($(CROSS_PREFIX),)
CC=$(CROSS_PREFIX)gcc
endif
AS=$(CROSS_PREFIX)as
LD=$(CROSS_PREFIX)ld
OBJCOPY=$(CROSS_PREFIX)objcopy
OBJDUMP=$(CROSS_PREFIX)objdump
STRIP=$(CROSS_PREFIX)strip
PYTHON=python
CPP=cpp
IASL:=iasl
LD32BIT_FLAG:=-melf_i386

# Source files
SRCBOTH=misc.c stacks.c output.c string.c block.c cdrom.c disk.c	\
    mouse.c kbd.c system.c serial.c sercon.c clock.c resume.c		\
    pnpbios.c vgahooks.c pcibios.c apm.c cp437.c hw/pci.c hw/timer.c	\
    hw/rtc.c hw/dma.c hw/pic.c hw/ps2port.c hw/serialio.c hw/usb.c	\
    hw/usb-uhci.c hw/usb-ohci.c hw/usb-ehci.c hw/usb-hid.c		\
    hw/usb-msc.c hw/usb-uas.c hw/blockcmd.c hw/floppy.c hw/ata.c	\
    hw/ramdisk.c hw/lsi-scsi.c hw/esp-scsi.c hw/megasas.c		\
    hw/mpt-scsi.c
SRC16=$(SRCBOTH)
SRC32FLAT=$(SRCBOTH) post.c e820map.c malloc.c romfile.c x86.c		\
    optionroms.c pmm.c font.c boot.c bootsplash.c jpeg.c bmp.c		\
    tcgbios.c sha1.c hw/pcidevice.c hw/ahci.c hw/pvscsi.c		\
    hw/usb-xhci.c hw/usb-hub.c hw/sdcard.c fw/coreboot.c		\
    fw/lzmadecode.c fw/multiboot.c fw/csm.c fw/biostables.c		\
    fw/paravirt.c fw/shadow.c fw/pciinit.c fw/smm.c fw/smp.c		\
    fw/mtrr.c fw/xen.c fw/acpi.c fw/mptable.c fw/pirtable.c		\
    fw/smbios.c fw/romfile_loader.c fw/dsdt_parser.c hw/virtio-ring.c	\
    hw/virtio-pci.c hw/virtio-mmio.c hw/virtio-blk.c hw/virtio-scsi.c	\
    hw/tpm_drivers.c hw/nvme.c sha256.c sha512.c
SRC32SEG=string.c output.c pcibios.c apm.c stacks.c hw/pci.c hw/serialio.c
DIRS=src src/hw src/fw vgasrc

# Default compiler flags
cc-option=$(shell if test -z "`$(1) $(2) -S -o /dev/null -xc /dev/null 2>&1`" \
    ; then echo "$(2)"; else echo "$(3)"; fi ;)

EXTRAVERSION=

CPPFLAGS = -P -MD -MT $@

COMMONCFLAGS := -I$(OUT) -Isrc -Os -MD -g \
    -Wall -Wno-strict-aliasing -Wold-style-definition \
    $(call cc-option,$(CC),-Wtype-limits,) \
    -m32 -march=i386 -mregparm=3 -mpreferred-stack-boundary=2 \
    -minline-all-stringops -fomit-frame-pointer \
    -freg-struct-return -ffreestanding -fno-delete-null-pointer-checks \
    -ffunction-sections -fdata-sections -fno-common -fno-merge-constants
COMMONCFLAGS += $(call cc-option,$(CC),-nopie,)
COMMONCFLAGS += $(call cc-option,$(CC),-fno-pie,)
COMMONCFLAGS += $(call cc-option,$(CC),-fno-stack-protector,)
COMMONCFLAGS += $(call cc-option,$(CC),-fno-stack-protector-all,)
COMMONCFLAGS += $(call cc-option,$(CC),-fstack-check=no,)
COMMONCFLAGS += $(call cc-option,$(CC),-Wno-address-of-packed-member,)
COMMONCFLAGS += $(call cc-option,$(CC),-fcf-protection=none,)
COMMA := ,

CFLAGS32FLAT := $(COMMONCFLAGS) -DMODE16=0 -DMODESEGMENT=0
CFLAGSSEG := $(COMMONCFLAGS) -DMODESEGMENT=1 -fno-defer-pop \
    $(call cc-option,$(CC),-fno-jump-tables,-DMANUAL_NO_JUMP_TABLE) \
    $(call cc-option,$(CC),-fno-tree-switch-conversion,)
CFLAGS32SEG := $(CFLAGSSEG) -DMODE16=0
CFLAGS16 := $(CFLAGSSEG) -DMODE16=1 \
    $(call cc-option,$(CC),-m16,-Wa$(COMMA)src/code16gcc.s) \
    $(call cc-option,$(CC),--param large-stack-frame=4,-fno-inline)

# Run with "make V=1" to see the actual compile commands
ifdef V
Q=
else
Q=@
MAKEFLAGS += --no-print-directory
endif

# Default targets
-include $(KCONFIG_CONFIG)

target-y :=
target-$(CONFIG_QEMU) += $(OUT)bios.bin
target-$(CONFIG_CSM) += $(OUT)Csm16.bin
target-$(CONFIG_COREBOOT) += $(OUT)bios.bin.elf
target-$(CONFIG_BUILD_VGABIOS) += $(OUT)vgabios.bin

all: $(target-y)

# Make definitions
.PHONY : all clean distclean FORCE
.DELETE_ON_ERROR:


################ Common build rules

# Verify the build environment works.
TESTGCC:=$(shell OUT="$(OUT)" CC="$(CC)" LD="$(LD)" IASL="$(IASL)" scripts/test-build.sh)
ifeq "$(TESTGCC)" "-1"
$(error "Please upgrade the build environment")
endif

ifeq "$(TESTGCC)" "0"
# Use -fwhole-program
CFLAGSWHOLE=-fwhole-program -DWHOLE_PROGRAM
endif

# Do a whole file compile by textually including all C code.
define whole-compile
@echo "  Compiling whole program $3"
$(Q)printf '$(foreach i,$2,#include "$i"\n)' > $3.tmp.c
$(Q)$(CC) -I. $1 $(CFLAGSWHOLE) -c $3.tmp.c -o $3
endef

%.noexec.o: %.o
	@echo "  Stripping $@"
	$(Q)$(STRIP) $< -o $<.strip.o
	$(Q)$(PYTHON) ./scripts/ldnoexec.py $<.strip.o $@

$(OUT)%.s: %.c
	@echo "  Compiling to assembler $@"
	$(Q)$(CC) $(CFLAGS16) -S -c $< -o $@

$(OUT)%.o: %.c $(OUT)autoconf.h
	@echo "  Compile checking $@"
	$(Q)$(CC) $(CFLAGS32FLAT) -c $< -o $@

$(OUT)%.lds: %.lds.S
	@echo "  Precompiling $@"
	$(Q)$(CPP) $(CPPFLAGS) -D__ASSEMBLY__ $< -o $@


################ Main BIOS build rules

$(OUT)asm-offsets.s: $(OUT)autoconf.h

$(OUT)asm-offsets.h: $(OUT)src/asm-offsets.s
	@echo "  Generating offset file $@"
	$(Q)./scripts/gen-offsets.sh $< $@

$(OUT)ccode16.o: $(OUT)autoconf.h $(patsubst %.c, $(OUT)src/%.o,$(SRC16)) ; $(call whole-compile, $(CFLAGS16), $(addprefix src/, $(SRC16)),$@)

$(OUT)code32seg.o: $(OUT)autoconf.h $(patsubst %.c, $(OUT)src/%.o,$(SRC32SEG)) ; $(call whole-compile, $(CFLAGS32SEG), $(addprefix src/, $(SRC32SEG)),$@)

$(OUT)ccode32flat.o: $(OUT)autoconf.h $(patsubst %.c, $(OUT)src/%.o,$(SRC32FLAT)) ; $(call whole-compile, $(CFLAGS32FLAT), $(addprefix src/, $(SRC32FLAT)),$@)

$(OUT)romlayout.o: src/romlayout.S $(OUT)autoconf.h $(OUT)asm-offsets.h
	@echo "  Compiling (16bit) $@"
	$(Q)$(CC) $(CFLAGS16) -c -D__ASSEMBLY__ $< -o $@

$(OUT)romlayout16.lds: $(OUT)ccode32flat.o $(OUT)code32seg.o $(OUT)ccode16.o $(OUT)romlayout.o src/version.c scripts/layoutrom.py scripts/buildversion.py
	@echo "  Building ld scripts"
	$(Q)$(PYTHON) ./scripts/buildversion.py -e "$(EXTRAVERSION)" -t "$(CC);$(AS);$(LD);$(OBJCOPY);$(OBJDUMP);$(STRIP)" $(OUT)autoversion.h
	$(Q)$(CC) $(CFLAGS32FLAT) -c src/version.c -o $(OUT)version.o
	$(Q)$(LD) $(LD32BIT_FLAG) -r $(OUT)ccode32flat.o $(OUT)version.o -o $(OUT)code32flat.o
	$(Q)$(LD) $(LD32BIT_FLAG) -r $(OUT)ccode16.o $(OUT)romlayout.o -o $(OUT)code16.o
	$(Q)$(OBJDUMP) -thr $(OUT)code32flat.o > $(OUT)code32flat.o.objdump
	$(Q)$(OBJDUMP) -thr $(OUT)code32seg.o > $(OUT)code32seg.o.objdump
	$(Q)$(OBJDUMP) -thr $(OUT)code16.o > $(OUT)code16.o.objdump
	$(Q)$(PYTHON) ./scripts/layoutrom.py $(OUT)code16.o.objdump $(OUT)code32seg.o.objdump $(OUT)code32flat.o.objdump $(OUT)$(KCONFIG_AUTOHEADER) $(OUT)romlayout16.lds $(OUT)romlayout32seg.lds $(OUT)romlayout32flat.lds

# These are actually built by scripts/layoutrom.py above, but by pulling them
# into an extra rule we prevent make -j from spawning layoutrom.py 4 times.
$(OUT)romlayout32seg.lds $(OUT)romlayout32flat.lds $(OUT)code32flat.o $(OUT)code16.o: $(OUT)romlayout16.lds

$(OUT)rom16.o: $(OUT)code16.o $(OUT)romlayout16.lds
	@echo "  Linking $@"
	$(Q)$(LD) -T $(OUT)romlayout16.lds $< -o $@

$(OUT)rom32seg.o: $(OUT)code32seg.o $(OUT)romlayout32seg.lds
	@echo "  Linking $@"
	$(Q)$(LD) -T $(OUT)romlayout32seg.lds $< -o $@

$(OUT)rom.o: $(OUT)rom16.noexec.o $(OUT)rom32seg.noexec.o $(OUT)code32flat.o $(OUT)romlayout32flat.lds
	@echo "  Linking $@"
	$(Q)$(LD) -N -T $(OUT)romlayout32flat.lds $(OUT)rom16.noexec.o $(OUT)rom32seg.noexec.o $(OUT)code32flat.o -o $@

$(OUT)bios.bin.prep: $(OUT)rom.o scripts/checkrom.py
	@echo "  Prepping $@"
	$(Q)rm -f $(OUT)bios.bin $(OUT)Csm16.bin $(OUT)bios.bin.elf
	$(Q)$(OBJDUMP) -thr $< > $<.objdump
	$(Q)$(OBJCOPY) -O binary $< $(OUT)bios.bin.raw
	$(Q)$(PYTHON) ./scripts/checkrom.py $<.objdump $(CONFIG_ROM_SIZE) $(OUT)bios.bin.raw $(OUT)bios.bin.prep

$(OUT)bios.bin: $(OUT)bios.bin.prep
	@echo "  Creating $@"
	$(Q)cp $< $@

$(OUT)Csm16.bin: $(OUT)bios.bin.prep
	@echo "  Creating $@"
	$(Q)cp $< $@

$(OUT)bios.bin.elf: $(OUT)rom.o $(OUT)bios.bin.prep
	@echo "  Creating $@"
	$(Q)$(STRIP) -R .comment $< -o $(OUT)bios.bin.elf


################ VGA build rules

# VGA src files
SRCVGA=src/output.c src/string.c src/hw/pci.c src/hw/serialio.c \
    vgasrc/vgainit.c vgasrc/vgabios.c vgasrc/vgafb.c vgasrc/swcursor.c \
    vgasrc/vgafonts.c vgasrc/vbe.c \
    vgasrc/stdvga.c vgasrc/stdvgamodes.c vgasrc/stdvgaio.c \
    vgasrc/clext.c vgasrc/svgamodes.c vgasrc/atiext.c vgasrc/bochsvga.c vgasrc/geodevga.c \
    src/fw/coreboot.c vgasrc/cbvga.c vgasrc/bochsdisplay.c vgasrc/ramfb.c

ifeq "$(CONFIG_VGA_FIXUP_ASM)" "y"
$(OUT)vgaccode16.raw.s: $(OUT)autoconf.h $(patsubst %.c, $(OUT)%.o,$(SRCVGA)) ; $(call whole-compile, $(filter-out -fomit-frame-pointer,$(CFLAGS16)) -fno-omit-frame-pointer -S -Isrc, $(SRCVGA),$@)

$(OUT)vgaccode16.o: $(OUT)vgaccode16.raw.s scripts/vgafixup.py
	@echo "  Fixup VGA rom assembler"
	$(Q)$(PYTHON) ./scripts/vgafixup.py $< $(OUT)vgaccode16.s
	$(Q)$(AS) --32 src/code16gcc.s $(OUT)vgaccode16.s -o $@
else
$(OUT)vgaccode16.o: $(OUT)autoconf.h $(patsubst %.c, $(OUT)%.o,$(SRCVGA)) ; $(call whole-compile, $(CFLAGS16) -Isrc, $(SRCVGA),$@)
endif

$(OUT)vgaentry.o: vgasrc/vgaentry.S $(OUT)autoconf.h $(OUT)asm-offsets.h
	@echo "  Compiling (16bit) $@"
	$(Q)$(CC) $(CFLAGS16) -c -D__ASSEMBLY__ $< -o $@

$(OUT)vgarom.o: $(OUT)vgaccode16.o $(OUT)vgaentry.o $(OUT)vgasrc/vgalayout.lds vgasrc/vgaversion.c scripts/buildversion.py
	@echo "  Linking $@"
	$(Q)$(PYTHON) ./scripts/buildversion.py -e "$(EXTRAVERSION)" -t "$(CC);$(AS);$(LD);$(OBJCOPY);$(OBJDUMP);$(STRIP)" $(OUT)autovgaversion.h
	$(Q)$(CC) $(CFLAGS16) -c vgasrc/vgaversion.c -o $(OUT)vgaversion.o
	$(Q)$(LD) --gc-sections -T $(OUT)vgasrc/vgalayout.lds $(OUT)vgaccode16.o $(OUT)vgaentry.o $(OUT)vgaversion.o -o $@

$(OUT)vgabios.bin.raw: $(OUT)vgarom.o
	@echo "  Extracting binary $@"
	$(Q)$(OBJCOPY) -O binary $< $@

$(OUT)vgabios.bin: $(OUT)vgabios.bin.raw scripts/buildrom.py
	@echo "  Finalizing rom $@"
	$(Q)$(PYTHON) ./scripts/buildrom.py $< $@


################ DSDT build rules

iasl-option=$(shell if test -z "`$(1) $(2) 2>&1 > /dev/null`" \
    ; then echo "$(2)"; else echo "$(3)"; fi ;)

%.hex: %.dsl ./scripts/acpi_extract_preprocess.py ./scripts/acpi_extract.py
	@echo "  Compiling IASL $@"
	$(Q)$(CPP) $(CPPFLAGS) $< -o $(OUT)$*.dsl.i.orig
	$(Q)$(PYTHON) ./scripts/acpi_extract_preprocess.py $(OUT)$*.dsl.i.orig > $(OUT)$*.dsl.i
	$(Q)$(IASL) $(call iasl-option,$(IASL),-Pn,) -vs -l -tc -p $(OUT)$* $(OUT)$*.dsl.i
	$(Q)$(PYTHON) ./scripts/acpi_extract.py $(OUT)$*.lst > $(OUT)$*.off
	$(Q)cat $(OUT)$*.off > $@

iasl: src/fw/acpi-dsdt.hex src/fw/ssdt-proc.hex src/fw/ssdt-pcihp.hex src/fw/ssdt-misc.hex

################ Kconfig rules

define do-kconfig
$(Q)mkdir -p $(OUT)/scripts/kconfig/lxdialog
$(Q)mkdir -p $(OUT)/include/config
$(Q)mkdir -p $(addprefix $(OUT), $(DIRS))
$(Q)$(MAKE) -C $(OUT) -f $(CURDIR)/scripts/kconfig/Makefile srctree=$(CURDIR) src=scripts/kconfig obj=scripts/kconfig Q=$(Q) Kconfig=$(CURDIR)/src/Kconfig $1
endef

$(OUT)autoconf.h : $(KCONFIG_CONFIG) ; $(call do-kconfig, silentoldconfig)
$(KCONFIG_CONFIG): src/Kconfig vgasrc/Kconfig ; $(call do-kconfig, olddefconfig)
%onfig: ; $(call do-kconfig, $@)
help: ; $(call do-kconfig, $@)


################ Generic rules

clean:
	$(Q)rm -rf $(OUT)

distclean: clean
	$(Q)rm -f .config .config.old

-include $(OUT)*.d $(patsubst %,$(OUT)%/*.d,$(DIRS))
