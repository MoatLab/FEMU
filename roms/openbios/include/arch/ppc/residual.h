/*
 * residual.h
 *
 * Structures for build PReP residual data as used in OpenHackWare
 *
 * Copyright (c) 2004-2005 Jocelyn Mayer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* Residual data */
#define MAX_CPUS 16
#define MAX_SEGS 64
#define MAX_MEMS 64
#define MAX_DEVS 256

typedef struct vital_t {
    /* Motherboard dependents */
    uint8_t model[32];
    uint8_t serial[64];
    uint16_t version;
    uint16_t revision;
    uint32_t firmware;
    uint32_t NVRAM_size;
    uint32_t nSIMMslots;
    uint32_t nISAslots;
    uint32_t nPCIslots;
    uint32_t nPCMCIAslots;
    uint32_t nMCAslots;
    uint32_t nEISAslots;
    uint32_t CPUHz;
    uint32_t busHz;
    uint32_t PCIHz;
    uint32_t TBdiv;
    /* CPU infos */
    uint32_t wwidth;
    uint32_t page_size;
    uint32_t ChBlocSize;
    uint32_t GrSize;
    /* Cache and TLBs */
    uint32_t cache_size;
    uint32_t cache_type;
    uint32_t cache_assoc;
    uint32_t cache_lnsize;
    uint32_t Icache_size;
    uint32_t Icache_assoc;
    uint32_t Icache_lnsize;
    uint32_t Dcache_size;
    uint32_t Dcache_assoc;
    uint32_t Dcache_lnsize;
    uint32_t TLB_size;
    uint32_t TLB_type;
    uint32_t TLB_assoc;
    uint32_t ITLB_size;
    uint32_t ITLB_assoc;
    uint32_t DTLB_size;
    uint32_t DTLB_assoc;
    void *ext_vital;
} vital_t;

typedef struct PPC_CPU_t {
    uint32_t pvr;
    uint32_t serial;
    uint32_t L2_size;
    uint32_t L2_assoc;
} PPC_CPU_t;

typedef struct map_t {
    uint32_t usage;
    uint32_t base;
    uint32_t count;
} map_t;

typedef struct PPC_mem_t {
    uint32_t size;
} PPC_mem_t;

typedef struct PPC_device_t {
    uint32_t busID;
    uint32_t devID;
    uint32_t serial;
    uint32_t flags;
    uint32_t type;
    uint32_t subtype;
    uint32_t interface;
    uint32_t spare;
} PPC_device_t;

typedef struct residual_t {
    uint32_t  length;
    uint16_t  version;
    uint16_t  revision;
    vital_t   vital;
    uint32_t  nCPUs;
    PPC_CPU_t CPUs[MAX_CPUS];
    uint32_t  max_mem;
    uint32_t  good_mem;
    uint32_t  nmaps;
    map_t     maps[MAX_SEGS];
    uint32_t  nmems;
    PPC_mem_t memories[MAX_MEMS];
    uint32_t  ndevices;
    PPC_device_t devices[MAX_DEVS];
    /* TOFIX: No PNP devices */
} residual_t;
