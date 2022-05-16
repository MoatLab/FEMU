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
#define GCR 0xf0800000
#define CLK 0xf0801000
#define FIU0 0xfb000000

#define CLK_CLKDIV3 0x58

#define FIU_DRD_CFG 0x00
#define FIU_CFG 0x78

#define BOOT_MAGIC0 0x000
#define BOOT_MAGIC1 0x004
#define BOOT_FIU_DRD_CFG 0x108
#define BOOT_FIU_CLK_DIV 0x10c
#define BOOT_DEST_ADDR 0x140
#define BOOT_CODE_SIZE 0x144
#define BOOT_VERSION 0x148
#define BOOT_CODE_OFFSET 0x200

#define BOOT_MAGIC0_VALUE 0xaa550750
#define BOOT_MAGIC1_VALUE 0x424f4f54

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
    asm volatile("str   %0, [%1, %2]"
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

uintptr_t load_boot_image(void)
{
    uintptr_t dest_addr;
    uint32_t drd_cfg;
    uint8_t clk_div;

    reg_write(FIU0, FIU_CFG, 0x0000000b);

    if (image_read_u32(SPI0CS0, BOOT_MAGIC0) != BOOT_MAGIC0_VALUE) {
        panic("Bad image magic0 value");
    }
    if (image_read_u32(SPI0CS0, BOOT_MAGIC1) != BOOT_MAGIC1_VALUE) {
        panic("Bad image magic1 value");
    }

    clk_div = image_read_u8(SPI0CS0, BOOT_FIU_CLK_DIV);
    if (clk_div != 0) {
        reg_write(FIU0, FIU_DRD_CFG, image_read_u32(SPI0CS0, BOOT_FIU_DRD_CFG));
        reg_write(CLK, CLK_CLKDIV3, clk_div << 6);
    }

    dest_addr = image_read_u32(SPI0CS0, BOOT_DEST_ADDR);
    if (dest_addr == 0) {
        return SPI0CS0 + 0x200;
    }

    copy_boot_image(dest_addr, SPI0CS0,
                    image_read_u32(SPI0CS0, BOOT_CODE_SIZE) + 0x200);

    return dest_addr + 0x200;
}
