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

#ifndef __AST27X0_INCLUDE_SSP_TSP_H__
#define __AST27X0_INCLUDE_SSP_TSP_H__

#include <stdint.h>

/* MAX visible range is 512M for SSP and TSP */
#define MAX_I_D_ADDRESS (512 * 1024 * 1024)
#define TCM_SIZE    (8 * 1024) /* 8KB */

#define SSP_MEMORY_NODE     "/reserved-memory/ssp-memory"
#define TSP_MEMORY_NODE     "/reserved-memory/tsp-memory"
#define ATF_MEMORY_NODE     "/reserved-memory/trusted-firmware-a"
#define OPTEE_MEMORY_NODE   "/reserved-memory/optee-core"
#define IPC_SSP_MEMORY_NODE "/reserved-memory/ipc-ssp-share"

/* SCU */
#define ASPEED_CPU_SCU_BASE 0x12C02000
#define SCU_CPU_RST_SSP     BIT(30)
#define SCU_CPU_RST2_TSP    BIT(9)

struct ast2700_scu0 {
    uint32_t rsv_0x11c[72];     /* 0x000 ~ 0x11C */
    uint32_t ssp_ctrl_0;        /* 0x120 */
    uint32_t ssp_ctrl_1;        /* 0x124 */
    uint32_t ssp_ctrl_2;        /* 0x128 */
    uint32_t ssp_ctrl_3;        /* 0x12C */
    uint32_t ssp_ctrl_4;        /* 0x130 */
    uint32_t ssp_ctrl_5;        /* 0x134 */
    uint32_t ssp_ctrl_6;        /* 0x138 */
    uint32_t rsv_0x13c[1];      /* 0x13C */
    uint32_t ssp_tcm_base;      /* 0x140 */
    uint32_t ssp_tcm_size;      /* 0x144 */
    uint32_t ssp_ahb_base;      /* 0x148 */
    uint32_t ssp_ahb_size;      /* 0x14c */
    uint32_t ssp_memory_base;   /* 0x150 */
    uint32_t ssp_memory_size;   /* 0x154 */
    uint32_t rsv_0x158[2];      /* 0x158 ~ 0x15C */
    uint32_t tsp_ctrl_0;        /* 0x160 */
    uint32_t rsv_0x164[1];      /* 0x164 */
    uint32_t tsp_ctrl_1;        /* 0x168 */
    uint32_t tsp_ctrl_2;        /* 0x16C */
    uint32_t tsp_ctrl_3;        /* 0x170 */
    uint32_t tsp_ctrl_4;        /* 0x174 */
    uint32_t tsp_ctrl_5;        /* 0x178 */
    uint32_t rsv_0x17c[6];      /* 0x17C ~ 0x190 */
    uint32_t tsp_remap_size;    /* 0x194 */
    uint32_t rsv_0x198[26];     /* 0x198 ~ 0x1FC */
    uint32_t modrst1_ctrl;      /* 0x200 */
    uint32_t modrst1_clr;       /* 0x204 */
    uint32_t rsv_0x208[2];      /* 0x208 ~ 0x20C */
    uint32_t modrst1_lock;      /* 0x210 */
    uint32_t modrst1_prot1;     /* 0x214 */
    uint32_t modrst1_prot2;     /* 0x218 */
    uint32_t modrst1_prot3;     /* 0x21C */
    uint32_t modrst2_ctrl;      /* 0x220 */
    uint32_t modrst2_clr;       /* 0x224 */
};

/* SSP control register 0 */
#define SCU_CPU_SSP_TSP_RESET_STS               BIT(8)
#define SCU_CPU_SSP_TSP_SRAM_SD                 BIT(7)
#define SCU_CPU_SSP_TSP_SRAM_DSLP               BIT(6)
#define SCU_CPU_SSP_TSP_SRAM_SLP                BIT(5)
#define SCU_CPU_SSP_TSP_NIDEN                   BIT(4)
#define SCU_CPU_SSP_TSP_DBGEN                   BIT(3)
#define SCU_CPU_SSP_TSP_DBG_ENABLE              BIT(2)
#define SCU_CPU_SSP_TSP_RESET                   BIT(1)
#define SCU_CPU_SSP_TSP_ENABLE                  BIT(0)

/* SSP control register 6 */
#define SCU_CPU_SSP_TSP_CTRL_ICACHE_EN          BIT(1)
#define SCU_CPU_SSP_TSP_CTRL_DCACHE_EN          BIT(0)

struct mem_region {
    uint64_t addr;
    uint32_t size;
};

struct reserved_mem_info {
    struct mem_region ssp;
    struct mem_region tsp;
    struct mem_region atf;
    struct mem_region tee;
    struct mem_region ipc_ssp;
};

void get_reserved_memory(const void *fdt_blob, struct reserved_mem_info *info);
int ssp_init(uint64_t load_addr, const struct reserved_mem_info *info);
int ssp_enable(void);
int tsp_init(uint64_t load_addr, const struct reserved_mem_info *info);
int tsp_enable(void);

#endif /* __AST27X0_INCLUDE_SSP_TSP_H__ */
