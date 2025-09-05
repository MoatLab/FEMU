/*
 * Copyright (C) 2025 ASPEED Technology Inc.
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

#include <io.h>
#include <libfdt.h>
#include <uart_console.h>
#include <image.h>
#include <ssp_tsp.h>

void get_reserved_memory(const void *fdt_blob, struct reserved_mem_info *info)
{
    struct {
        const char *path;
        struct mem_region *region;
    } nodes[] = {
        { SSP_MEMORY_NODE,     &info->ssp       },
        { TSP_MEMORY_NODE,     &info->tsp       },
        { ATF_MEMORY_NODE,     &info->atf       },
        { OPTEE_MEMORY_NODE,   &info->tee       },
        { IPC_SSP_MEMORY_NODE, &info->ipc_ssp   },
    };

    const fdt32_t *reg;
    const char *path;
    int offset;
    size_t i;

    for (i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
        path = nodes[i].path;

        offset = fdt_path_offset(fdt_blob, path);
        if (offset < 0) {
            uprintf("Cannot find node %s in the device tree.\n", path);
            nodes[i].region->addr = 0;
            nodes[i].region->size = 0;
            continue;
        }

        reg = fdt_getprop(fdt_blob, offset, "reg", NULL);
        if (!reg) {
            uprintf("No reg property found in %s\n", path);
            nodes[i].region->addr = 0;
            nodes[i].region->size = 0;
            continue;
        }

        nodes[i].region->addr = fdt32_to_cpu(reg[0]);
        nodes[i].region->size = fdt32_to_cpu(reg[1]);

        uprintf("[reserved] %s base: 0x%lx  size: 0x%lx\n", path,
                nodes[i].region->addr, nodes[i].region->size);
    }
}

int ssp_init(uint64_t load_addr, const struct reserved_mem_info *info)
{
    struct ast2700_scu0 *scu;
    uint32_t reg_val;

    scu = (struct ast2700_scu0 *)ASPEED_CPU_SCU_BASE;

    reg_val = readl((void *)&scu->ssp_ctrl_0);
    if (!(reg_val & SCU_CPU_SSP_TSP_RESET_STS)) {
        return 0;
    }

    writel(SCU_CPU_RST_SSP, (void *)&scu->modrst1_ctrl);
    writel(SCU_CPU_RST_SSP, (void *)&scu->modrst1_clr);

    reg_val = SCU_CPU_SSP_TSP_NIDEN | SCU_CPU_SSP_TSP_DBGEN |
              SCU_CPU_SSP_TSP_DBG_ENABLE | SCU_CPU_SSP_TSP_RESET;
    writel(reg_val, (void *)&scu->ssp_ctrl_0);

    /*
     * SSP Memory Map:
     * - 0x0000_0000 - 0x0587_FFFF: ssp_remap2 -> DRAM[load_addr]
     * - 0x0588_0000 - 0x1FFF_DFFF: ssp_remap1 -> AHB -> DRAM[0]
     * - 0x1FFF_E000 - 0x2000_0000: ssp_remap0 -> TCM (SSP stack)
     *
     * The SSP serves as the secure loader for TSP, ATF, OP-TEE, and U-Boot.
     * Therefore, their load buffers must be visible to the SSP.
     *
     * - SSP remap entry #2 (ssp_remap2_base/size) maps the load buffers
     *   for SSP, TSP, ATF, OP-TEE and IPC share memory. Ensure these buffers
     *   are contiguous.
     * - SSP remap entry #1 (ssp_remap1_base/size) maps the load buffer
     *   for U-Boot at DRAM offset 0x0.
     * - SSP remap entry #0 (ssp_remap0_base/size) maps TCM, which is used for
     *   stack.
     */
    writel(0, (void *)&scu->ssp_memory_base);
    reg_val = info->ssp.size + info->tsp.size + info->atf.size +
              info->tee.size + info->ipc_ssp.size;
    writel(reg_val, (void *)&scu->ssp_memory_size);

    writel(reg_val, (void *)&scu->ssp_ahb_base);
    writel(MAX_I_D_ADDRESS - reg_val - TCM_SIZE, (void *)&scu->ssp_ahb_size);

    writel(MAX_I_D_ADDRESS - TCM_SIZE, (void *)&scu->ssp_tcm_base);
    writel(TCM_SIZE, (void *)&scu->ssp_tcm_size);

    /* Configure physical AHB remap: through H2M, mapped to SYS_DRAM_BASE */
    writel((uint32_t)(DRAM_ADDR >> 4), (void *)&scu->ssp_ctrl_1);

    /* Configure physical DRAM remap */
    reg_val = (uint32_t)(load_addr >> 4);
    writel(reg_val, (void *)&scu->ssp_ctrl_2);

    /*
     * For A1, the Cache region can only be enabled entirely;
     * partial enabling is not supported.
     */
    writel(GENMASK(31, 0), (void *)&scu->ssp_ctrl_3);
    writel(GENMASK(31, 0), (void *)&scu->ssp_ctrl_4);

    /* Enable I and D cache as default */
    writel(SCU_CPU_SSP_TSP_CTRL_ICACHE_EN | SCU_CPU_SSP_TSP_CTRL_DCACHE_EN,
           (void *)&scu->ssp_ctrl_6);

    return 0;
}

int ssp_enable(void)
{
    struct ast2700_scu0 *scu;
    uint32_t reg_val;

    scu = (struct ast2700_scu0 *)ASPEED_CPU_SCU_BASE;
    reg_val = readl((void *)&scu->ssp_ctrl_0);
    reg_val |= SCU_CPU_SSP_TSP_ENABLE | SCU_CPU_SSP_TSP_RESET;
    writel(reg_val, (void *)&scu->ssp_ctrl_0);

    return 0;
}

int tsp_init(uint64_t load_addr, const struct reserved_mem_info *info)
{
    struct ast2700_scu0 *scu;
    uint32_t reg_val;

    scu = (struct ast2700_scu0 *)ASPEED_CPU_SCU_BASE;

    reg_val = readl((void *)&scu->tsp_ctrl_0);
    if (!(reg_val & SCU_CPU_SSP_TSP_RESET_STS)) {
        return 0;
    }

    writel(SCU_CPU_RST2_TSP, (void *)&scu->modrst2_ctrl);
    writel(SCU_CPU_RST2_TSP, (void *)&scu->modrst2_clr);

    reg_val = SCU_CPU_SSP_TSP_NIDEN | SCU_CPU_SSP_TSP_DBGEN |
              SCU_CPU_SSP_TSP_DBG_ENABLE | SCU_CPU_SSP_TSP_RESET;
    writel(reg_val, (void *)&scu->tsp_ctrl_0);

    /* TSP 0x0000_0000 - 0x0200_0000 -> DRAM */
    writel(info->tsp.size, (void *)&scu->tsp_remap_size);

    /* Configure physical DRAM remap */
    reg_val = (uint32_t)(load_addr >> 4);
    writel(reg_val, (void *)&scu->tsp_ctrl_1);

    /*
     * For A1, the Cache region can only be enabled entirely;
     * partial enabling is not supported.
     */
    writel(GENMASK(31, 0), (void *)&scu->tsp_ctrl_2);
    writel(GENMASK(31, 0), (void *)&scu->tsp_ctrl_3);

    /* Enable I and D cache as default */
    writel(SCU_CPU_SSP_TSP_CTRL_ICACHE_EN | SCU_CPU_SSP_TSP_CTRL_DCACHE_EN,
           (void *)&scu->tsp_ctrl_5);

    return 0;
}

int tsp_enable(void)
{
    struct ast2700_scu0 *scu;
    uint32_t reg_val;

    scu = (struct ast2700_scu0 *)ASPEED_CPU_SCU_BASE;
    reg_val = readl((void *)&scu->tsp_ctrl_0);
    reg_val |= SCU_CPU_SSP_TSP_ENABLE | SCU_CPU_SSP_TSP_RESET;
    writel(reg_val, (void *)&scu->tsp_ctrl_0);

    return 0;
}

