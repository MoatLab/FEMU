# Copyright 2020 Google LLC
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

CROSS_COMPILE	?= arm-none-eabi-

CC		= $(CROSS_COMPILE)gcc
OBJCOPY		= $(CROSS_COMPILE)objcopy

CFLAGS		= -Os -g -mcpu=cortex-a9
ASFLAGS		= $(CFLAGS) -Wa,-mcpu=cortex-a9+mp
LDSCRIPT	= bootrom.ld
LDFLAGS		= -Wl,--build-id=none -static -nostdlib -T $(LDSCRIPT)

OBJS		:= start.o image.o

.PHONY: all clean
all: npcm7xx_bootrom.bin

clean:
	rm -f *.o *.bin *.elf

npcm7xx_bootrom.bin: npcm7xx_bootrom.elf
	$(OBJCOPY) -O binary $< $@

npcm7xx_bootrom.elf: $(OBJS) $(LDSCRIPT)
	$(CC) -o $@ $(LDFLAGS) $(OBJS)
