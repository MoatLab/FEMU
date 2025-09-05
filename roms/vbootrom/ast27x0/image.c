/*
 * Boot image parsing and loading.
 *
 * Copyright 2025 Google LLC
 * Copyright (C) ASPEED Technology Inc.
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

#include <string.h>
#include <libfdt.h>
#include <uart.h>
#include <uart_console.h>
#include <io.h>
#include <image.h>
#include <ssp_tsp.h>

#define DEBUG 0

#define FIT_SEARCH_START (FMCCS0)
#define FIT_SEARCH_END   (FMCCS0 + 0x400000)
#define FIT_SEARCH_STEP  0x10000

extern void panic(const char *);

static bool has_sspfw;
static bool has_tspfw;

/*
 * This global struct is explicitly initialized, so it is placed in the .data
 * section. The function pointer (uputc) is set to uart_aspeed_poll_out at
 * compile time, which ensures its address is embedded in the final binary.
 *
 * If the struct were uninitialized, it would be placed in the .bss section,
 * and the function pointer would default to zero (NULL).
 * This distinction is especially important in bare-metal or ROM-based
 * environments, where only initialized data (.data) is included in the final
 * .bin image.
 *
 * To prevent this:
 * - Use initialized globals (ensures placement in .data)
 *
 * In embedded systems, especially when generating stripped-down .bin
 * firmware, it's critical to ensure that essential function pointers are
 * preserved explicitly.
 */
static struct uart_console ucons = {
    .uputc = uart_aspeed_poll_out
};

static const char *splash_screen =
      " _    ______  ____  ____  __________  ____  __  ___      ___   ______________  ______  ______\n"
      "| |  / / __ )/ __ \\/ __ \\/_  __/ __ \\/ __ \\/  |/  /     /   | / ___/_  __/__ \\/__  / |/ / __ \\\n"
      "| | / / __  / / / / / / / / / / /_/ / / / / /|_/ /_____/ /| | \\__ \\ / /  __/ /  / /|   / / / /\n"
      "| |/ / /_/ / /_/ / /_/ / / / / _, _/ /_/ / /  / /_____/ ___ |___/ // /  / __/  / //   / /_/ /\n"
      "|___/_____/\\____/\\____/ /_/ /_/ |_|\\____/_/  /_/     /_/  |_/____//_/  /____/ /_//_/|_\\____/\n"
      "\n";

static void print_build_info()
{
   uprintf("%s", splash_screen);
   uprintf("Build Date : %s %s\n", __DATE__, __TIME__);
   uprintf("FW Version : %s\n", GIT_VERSION);
   uprintf("\n");
}

/*
 * Remap 32-bit BootMCU load address to 64-bit Cortex-A35 DRAM address.
 * BootMCU loads the U-BOOT FIT image to a 32-bit address (e.g. 0x80000000),
 * but Cortex-A35 accesses DRAM starting at DRAM_ADDR (e.g. 0x400000000).
 */
static inline uint64_t convert_mcu_addr_to_arm_dram(uint64_t mcu_load_addr)
{
    /*
     * If address is below 0x80000000, it's a physical address in SRAM.
     * No remapping is needed, return as-is.
     */
    if (mcu_load_addr < 0x80000000) {
        return mcu_load_addr;
    }

    return DRAM_ADDR + ((uint64_t)mcu_load_addr - 0x80000000);
}

static uint64_t read_fit_address(const void *fdt, int node,
                                 const char *prop_name)
{
    const char *node_name;
    const fdt32_t *prop;
    uint32_t addr_upper;
    uint32_t addr_lower;
    int len;

    if (!prop_name) {
        uprintf("Invalid: prop_name is NULL!\n");
        return 0;
    }

    node_name = fdt_get_name(fdt, node, NULL);
    if (!node_name) {
        node_name = "<unknown>";
    }

    prop = fdt_getprop(fdt, node, prop_name, &len);
    if (!prop) {
        uprintf("[%s] %s: property not found\n", node_name, prop_name);
        return 0;
    }

    if (len == 4) {
        return (uint64_t)fdt32_to_cpu(prop[0]);
    } else if (len == 8) {
        addr_upper = fdt32_to_cpu(prop[0]);
        addr_lower = fdt32_to_cpu(prop[1]);
        return ((uint64_t)addr_upper << 32) | addr_lower;
    } else {
        uprintf("[%s] %s: invalid length (%d bytes, expected 4 or 8)\n",
                node_name, prop_name, len);
        return 0;
    }
}

#if DEBUG
static void dump_fit_image(const void *fit_blob)
{
    uintptr_t data_offset;
    int images_offset;
    const void *data;
    int node_offset;
    const char *str;
    uint64_t addr;
    int data_len;

    images_offset = fdt_path_offset(fit_blob, "/images");
    if (images_offset < 0) {
        uprintf("No /images node found\n");
        return;
    }

    fdt_for_each_subnode(node_offset, fit_blob, images_offset) {
        str = fdt_get_name(fit_blob, node_offset, NULL);
        uprintf("Image node: %s\n", str);

        str = fdt_getprop(fit_blob, node_offset, "description", NULL);
        if (str) {
            uprintf("  description:  %s\n", str);
        }

        addr = read_fit_address(fit_blob, node_offset, "load");
        if (addr) {
            uprintf("  load address: 0x%016llx\n", (unsigned long long)addr);
        }

        addr = read_fit_address(fit_blob, node_offset, "entry");
        if (addr) {
            uprintf("  entry point:  0x%016llx\n", (unsigned long long)addr);
        }

        str = fdt_getprop(fit_blob, node_offset, "type", NULL);
        if (str) {
            uprintf("  type:         %s\n", str);
        }

        str = fdt_getprop(fit_blob, node_offset, "os", NULL);
        if (str) {
            uprintf("  os:           %s\n", str);
        }

        str = fdt_getprop(fit_blob, node_offset, "arch", NULL);
        if (str) {
            uprintf("  arch:         %s\n", str);
        }

        str = fdt_getprop(fit_blob, node_offset, "compression", NULL);
        if (str) {
            uprintf("  compression:  %s\n", str);
        }

        data = fdt_getprop(fit_blob, node_offset, "data", &data_len);
        if (data && data_len > 0) {
            data_offset = (uintptr_t)data - (uintptr_t)fit_blob;
            uprintf("  data:         %d bytes @ offset 0x%lx\n",
                    data_len, data_offset);
        } else {
            uprintf("  data:         not found or empty\n");
        }
    }
}
#endif

/*
 * Loads the "U-Boot" image from the FIT and returns its end address in memory.
 *
 * This function must be called before loading other images because some images,
 * such as "fdt", may not have an explicit "load" property defined. In those
 * cases, their load address is determined by placing them immediately after the
 * u-boot image in memory.
 *
 * Loading U-Boot first ensures a well-defined memory layout baseline for
 * subsequent images that rely on relative placement.
 */
static uint64_t load_uboot_image(const void *fit_blob)
{
    uintptr_t data_offset;
    uint64_t load_addr;
    uint64_t dram_addr;
    int images_offset;
    const void *data;
    const char *name;
    int node_offset;
    int data_len;

    images_offset = fdt_path_offset(fit_blob, "/images");
    if (images_offset < 0) {
        uprintf("No /images node found\n");
        return 0;
    }

    fdt_for_each_subnode(node_offset, fit_blob, images_offset) {
        name = fdt_get_name(fit_blob, node_offset, NULL);
        if (strcmp(name, "uboot") != 0) {
            continue;
        }

        load_addr = read_fit_address(fit_blob, node_offset, "load");
        if (!load_addr) {
            uprintf("[%s] has no load address!\n", name);
            return 0;
        }

        uprintf("[%s] load address: 0x%lx\n", name,
                (unsigned long long)load_addr);

        data = fdt_getprop(fit_blob, node_offset, "data", &data_len);
        if (!data || data_len <= 0) {
            uprintf("[%s] has no data!\n", name);
            return 0;
        }

        data_offset = (uintptr_t)data - (uintptr_t)fit_blob;
        uprintf("[%s] load end address: 0x%lx\n", name,
                (unsigned long long)(load_addr + data_len));
        uprintf("[%s] data: %d bytes @ offset 0x%lx\n", name, data_len,
                data_offset);
        dram_addr = convert_mcu_addr_to_arm_dram(load_addr);
        uprintf("[%s] loading %d bytes to 0x%lx ... ", name, data_len,
                (unsigned long long)dram_addr);
        memcpy((void *)(uintptr_t)dram_addr, data, data_len);
        uprintf("done\n");
        return load_addr + data_len;
    }

    uprintf("[uboot] not found in FIT\n");
    return 0;
}

/*
 * Loads all images from the FIT except "U-Boot".
 *
 * If an image has a "load" property, its value is remapped to the 64-bit DRAM
 * address space and used directly. If the image is "fdt" and does not have a
 * "load" property, it is placed immediately after the U-Boot image, using the
 * given uboot_end address as its load location.
 *
 * This function depends on uboot_end being correctly computed in advance by
 * load_uboot_image(). This ensures a clean and predictable memory layout even
 * if some images do not define explicit load addresses in the FIT.
 */
static void load_other_fit_images(const void *fit_blob, uint64_t uboot_end,
                                  uint64_t *dest_addr,
                                  const struct reserved_mem_info *info)
{
    uintptr_t data_offset;
    uint64_t load_addr;
    uint64_t dram_addr;
    int images_offset;
    const void *data;
    const char *name;
    int node_offset;
    int data_len;

    images_offset  = fdt_path_offset(fit_blob, "/images");
    if (images_offset < 0) {
        uprintf("No /images node found\n");
        return;
    }

    fdt_for_each_subnode(node_offset, fit_blob, images_offset) {
        name = fdt_get_name(fit_blob, node_offset, NULL);

        /* Skip U-Boot, which should already be loaded */
        if (strcmp(name, "uboot") == 0) {
            continue;
        }

        data = fdt_getprop(fit_blob, node_offset, "data", &data_len);
        if (!data || data_len <= 0) {
            uprintf("[%s] skip: no data\n", name);
            continue;
        }

        load_addr = read_fit_address(fit_blob, node_offset, "load");

        if (load_addr) {
            uprintf("[%s] load address: 0x%lx\n", name,
                    (unsigned long long)load_addr);
            /* Image has explicit load address, remap for ARM DRAM view */
            dram_addr = convert_mcu_addr_to_arm_dram(load_addr);
            /* The next image to jump to is BL31 (Trusted Firmware-A) */
            if (strcmp(name, "atf") == 0) {
                *dest_addr = dram_addr;
            }

            /* Init co-processor */
            if (strcmp(name, "sspfw") == 0) {
                ssp_init(dram_addr, info);
                has_sspfw = true;
            }

            if (strcmp(name, "tspfw") == 0) {
                tsp_init(dram_addr, info);
                has_tspfw = true;
            }
        } else if (strcmp(name, "fdt") == 0 && uboot_end) {
            /* fdt has no load address, fallback to uboot_end */
            load_addr = uboot_end;
            dram_addr = convert_mcu_addr_to_arm_dram(load_addr);
            uprintf("[%s] no load addr, fallback to u-boot end: 0x%lx\n",
                    name, (unsigned long long)load_addr);
        } else {
            uprintf("[%s] skip: no load address and no fallback\n", name);
            continue;
        }

        data_offset = (uintptr_t)data - (uintptr_t)fit_blob;
        uprintf("[%s] data: %d bytes @ offset 0x%lx\n",
                name, data_len, data_offset);
        uprintf("[%s] loading %d bytes to 0x%lx ... ",
                name, data_len, (unsigned long long)dram_addr);
        memcpy((void *)(uintptr_t)dram_addr, data, data_len);
        uprintf("done\n");
    }
}

static const void *find_fit_image(uint64_t start_addr, uint64_t end_addr,
                                  uint64_t search_step)
{
    const void *ptr = NULL;
    int total_size;
    uint64_t addr;

    if (search_step == 0) {
        uprintf("search_step cannot be zero.\n");
        return NULL;
    }

    for (addr = start_addr; addr < end_addr; addr += search_step) {
        ptr = (const void *)(uintptr_t)addr;

        if (fdt_check_header(ptr) == 0) {
            total_size = fdt_totalsize(ptr);
            uprintf("Found valid FIT image at 0x%lx (size: 0x%x bytes)\n",
                    addr, total_size);
            return ptr;
        }
    }

    uprintf("No valid FIT image found in range 0x%lx - 0x%lx (step: 0x%lx)\n",
            start_addr, end_addr, search_step);

    return NULL;
}

static int find_fmc_image(uint64_t start_addr, uint64_t end_addr,
                          uint64_t search_step, struct fmc_img_info *info)
{
    struct ast_fmc_header *hdr;
    uint32_t fmc_header_size;
    uint32_t payload_size;
    uint32_t total_size;
    uint64_t addr;

    if (info == NULL) {
        return 0;
    }

    fmc_header_size = sizeof(struct ast_fmc_header);

    for (addr = start_addr;
         addr + fmc_header_size <= end_addr;
         addr += search_step) {
        hdr = (struct ast_fmc_header *)addr;

        if (hdr->preamble.magic == FMC_HDR_MAGIC) {
            payload_size = hdr->body.size;
            total_size = fmc_header_size + payload_size;

            if (payload_size > 0 && (addr + total_size) <= end_addr) {
                info->payload_start = addr + fmc_header_size;
                info->payload_end = ALIGN_UP(addr + total_size, search_step);
                uprintf("Found valid FMC v%d image at 0x%lx (size: 0x%x)",
                        hdr->preamble.version, addr, total_size);
                uprintf(", next FIT search @ 0x%lx\n", info->payload_end);
                return 1;
            }
        }
    }

    uprintf("No valid FMC image found in range 0x%lx - 0x%lx (step: 0x%lx)\n",
            start_addr, end_addr, search_step);

    return 0;
}

static void *load_dtb_after_fmc(uint64_t fmc_end, uint64_t end_addr)
{
    void *dram_dtb_addr = (void *)(uintptr_t)DRAM_ADDR;
    const uint32_t *magic_ptr;
    size_t copy_size;
    uint64_t addr;

    for (addr = ALIGN_UP(fmc_end, 4); addr + 4 < end_addr; addr += 4) {
        /* Check for DTB magic number (aligned on 4-byte boundary) */
        magic_ptr = (const uint32_t *)(uintptr_t)addr;
        if (*magic_ptr != cpu_to_fdt32(FDT_MAGIC)) {
            continue;
        }

        /* Copy from flash to DRAM for validation */
        copy_size = end_addr - addr;
        memcpy(dram_dtb_addr, (const void *)(uintptr_t)addr, copy_size);

        /* Verify if the copied region is a valid DTB */
        if (fdt_check_header(dram_dtb_addr) == 0) {
            uprintf("Valid DTB found at 0x%lx, copied to 0x%lx\n",
                    addr, (uint64_t)dram_dtb_addr);
            return dram_dtb_addr;
        } else {
            uprintf("FDT_MAGIC at 0x%lx but invalid DTB header\n", addr);
        }
    }

    uprintf("No valid DTB found between 0x%lx and 0x%lx\n", fmc_end, end_addr);
    return NULL;
}

uint64_t load_boot_image(void)
{
    struct reserved_mem_info reservedinfo = {0};
    struct fmc_img_info fmcinfo = {0};
    uint64_t search_next_addr;
    uint64_t bl31_addr = 0;
    const void *fit_blob;
    void *dtb_ptr = NULL;
    uint64_t uboot_end;

    uart_aspeed_init(UART12);
    uart_console_register(&ucons);

    print_build_info();

    search_next_addr = FIT_SEARCH_START;

    /* Find FMC image */
    if (find_fmc_image(search_next_addr, FIT_SEARCH_END, FIT_SEARCH_STEP,
                       &fmcinfo)) {
        search_next_addr =  fmcinfo.payload_end;

        /* Try to find and load a valid SPL DTB between FMC and U-Boot FIT */
        dtb_ptr = load_dtb_after_fmc(fmcinfo.payload_start,
                                     fmcinfo.payload_end);
        if (dtb_ptr) {
            get_reserved_memory(dtb_ptr, &reservedinfo);
        }
    }

    /* Find U-Boot FIT imag */
    fit_blob = find_fit_image(search_next_addr,
                              FIT_SEARCH_END,
                              FIT_SEARCH_STEP);
    if (!fit_blob) {
        panic("");
    }

#if DEBUG
    dump_fit_image(fit_blob);
#endif

    uboot_end = load_uboot_image(fit_blob);

    if (!uboot_end) {
        panic("");
    }

    load_other_fit_images(fit_blob, uboot_end, &bl31_addr, &reservedinfo);

    if (!bl31_addr) {
        uprintf("Error: BL31 (Trusted Firmware-A) not found, halting.\n");
        panic("");
    }

    if (has_sspfw) {
        ssp_enable();
    }

    if (has_tspfw) {
        tsp_enable();
    }

    uprintf("\nJumping to BL31 (Trusted Firmware-A) at 0x%lx\n\n",
            bl31_addr);
    return bl31_addr;
}

