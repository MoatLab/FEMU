# Copyright 2025 Google LLC
# Copyright ASPEED Technology Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CROSS_COMPILE	?= aarch64-linux-gnu-

CC		= $(CROSS_COMPILE)gcc
OBJCOPY		= $(CROSS_COMPILE)objcopy
OBJDUMP		= $(CROSS_COMPILE)objdump

GIT_VERSION := git-$(shell git rev-parse --short HEAD)

# Why we use -no-pie -fno-pic in bare-metal builds:
#
# By default, modern GCC compilers enable PIE (Position-Independent Executable)
# and PIC (Position-Independent Code) to improve security and relocation
# flexibility.
#
# However, for raw binary (.bin) firmware and bootloaders:
# - We don't have a dynamic loader or relocation mechanism.
# - Function pointers must point to fixed physical addresses.
#
# These flags ensure that:
# - Function calls and pointers are encoded as absolute/static addresses.
# - The compiler does not emit references to the GOT (Global Offset Table),
#   which would be missing in a .bin context.
#
# Without these flags, function pointers in .data may be NULL or invalid at
# runtime.
CFLAGS		= -Os -Wall -Wextra -g -mcpu=cortex-a35 -fno-stack-protector \
		  -no-pie -fno-pic \
		  -I ./include -I ../lib/libfdt -I ../lib/libc/minimal/include
CFLAGS		+= -DGIT_VERSION=\"$(GIT_VERSION)\"
ASFLAGS		= $(CFLAGS) -Wa,-mcpu=cortex-a35
LDSCRIPT	= bootrom.ld
MAPFILE		= bootrom.map
LDFLAGS		= -Wl,--build-id=none -static -nostdlib -T $(LDSCRIPT) -Wl,-Map=$(MAPFILE)

OBJS		:= start.o image.o uart_aspeed.o uart_console.o ssp_tsp.o \
			../lib/libc/minimal/source/string/string.o \
			../lib/libfdt/fdt.o ../lib/libfdt/fdt_ro.o

.PHONY: all clean
all: ast27x0_bootrom.bin ast27x0_bootrom.asm

clean:
	rm -f *.o *.bin *.elf *.asm *.map ../lib/libfdt/*.o \
		../lib/libc/minimal/source/string/*.o

ast27x0_bootrom.bin: ast27x0_bootrom.elf
	$(OBJCOPY) -O binary $< $@

ast27x0_bootrom.asm: ast27x0_bootrom.elf
	$(OBJDUMP) -S $< > $@

ast27x0_bootrom.elf: $(OBJS) $(LDSCRIPT)
	$(CC) -o $@ $(LDFLAGS) $(OBJS)
