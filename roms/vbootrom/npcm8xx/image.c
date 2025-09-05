/*
 * Boot image parsing and loading.
 *
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>

#define SPI0CS0 0x80000000
#define CLK 0xf0801000
#define FIU0 0xfb000000

#define CLK_CLKSEL  0x04
#define CLK_CLKSEL_DEFAULT 0x1f18fc9

#define FIU_DRD_CFG 0x00

#define UBOOT_TAG       0x4c42544f4f42550aULL  /* .UBOOTBL */
#define UBOOT_MAGIC     0x1400000a
#define UBOOT_SIZE      0xb0000

/*
 * This structure must reside at offset 0x100 in SRAM.
 *
 * See the Check_ROMCode_Status function in the Nuvoton bootblock:
 * https://github.com/Nuvoton-Israel/bootblock/blob/master/Src/bootblock_main.c#L795
 */
struct rom_status {
    uint8_t reserved[12];
    uint8_t start_tag[8];
    uint32_t status;
} rom_status __attribute__((section(".data.rom_status"))) = {
    .status = 0x21, /* SPI0 CS0 offset 0 */
};

extern void panic(const char *);

static void reg_write(uintptr_t base, uintptr_t offset, uint32_t value)
{
    asm volatile("str   %w0, [%1, %2]"
                 :
                 : "r"(value), "r"(base), "i"(offset)
                 : "memory");
}

static uint32_t image_read_u8(uintptr_t base, uintptr_t offset)
{
    return *(uint8_t *)(base + offset);
}

static uint32_t image_read_u32(uintptr_t base, uintptr_t offset)
{
    return *(uint32_t *)(base + offset);
}

void copy_boot_image(uintptr_t dest_addr, uintptr_t src_addr, int32_t len)
{
    uint32_t *dst = (uint32_t *)dest_addr;
    uint32_t *src = (uint32_t *)src_addr;

    while (len > 0) {
        *dst++ = *src++;
        len -= sizeof(*dst);
    }
}

static uint32_t search_and_load_uboot(uintptr_t end)
{
    uintptr_t addr;
    uintptr_t src_addr, dest_addr;
    uint32_t size;

    for (addr = 0; addr < end; addr += 0x100) {
        src_addr = SPI0CS0 + addr;
        if ((*(uint64_t *)src_addr == UBOOT_TAG) &&
            (*(uint32_t *)(src_addr + 0x200) == UBOOT_MAGIC)) {
            dest_addr = image_read_u32(src_addr, 0x1f8);
            size = image_read_u32(src_addr, 0x1fc);
            copy_boot_image(dest_addr, src_addr, size);
            return dest_addr;
        }
    }
    return 0;
}

uintptr_t load_boot_image(void)
{
    /* Set CLKSEL to similar values as NPCM7XX */
    reg_write(CLK, CLK_CLKSEL, CLK_CLKSEL_DEFAULT);
    return search_and_load_uboot(0x200000) + 0x200;
}
