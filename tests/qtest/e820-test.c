/*
 * qtest e820 fw_cfg test case
 *
 * Validate the "etc/e820" fw_cfg table that QEMU hands to the firmware.
 *
 * Copyright (c) 2026 Advanced Micro Devices, Inc.
 *
 * Authors:
 *  FangSheng Huang <FangSheng.Huang@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "libqtest.h"
#include "libqos/fw_cfg.h"
#include "qemu/bswap.h"
#include "qemu/units.h"

/* e820 entry layout and types (cf. hw/i386/e820_memory_layout.h) */
#define E820_RAM            1
#define E820_SOFT_RESERVED  0xefffffff

struct e820_entry {
    uint64_t address;
    uint64_t length;
    uint32_t type;
} QEMU_PACKED;

#define E820_MAX_ENTRIES    128

/*
 * Read and structurally validate "etc/e820": the file is a packed array
 * of struct e820_entry, so its size must be a whole multiple of the entry
 * size and every entry must have a non-zero length. Returns the entry
 * count and fills @table.
 */
static size_t get_e820_table(QFWCFG *fw_cfg, struct e820_entry *table)
{
    size_t filesize, n, i;

    filesize = qfw_cfg_get_file(fw_cfg, "etc/e820", table,
                                E820_MAX_ENTRIES * sizeof(*table));
    g_assert_cmpint(filesize, >, 0);
    g_assert_cmpint(filesize % sizeof(struct e820_entry), ==, 0);

    n = filesize / sizeof(struct e820_entry);
    g_assert_cmpint(n, <=, E820_MAX_ENTRIES);

    for (i = 0; i < n; i++) {
        g_assert_cmpint(le64_to_cpu(table[i].length), >, 0);
    }

    return n;
}

static void test_e820_basic(void)
{
    struct e820_entry table[E820_MAX_ENTRIES];
    QFWCFG *fw_cfg;
    QTestState *s;
    size_t n, i;
    bool found_ram = false, found_soft_reserved = false;

    s = qtest_init("-machine q35 -m 256M");
    fw_cfg = pc_fw_cfg_init(s);

    n = get_e820_table(fw_cfg, table);
    for (i = 0; i < n; i++) {
        switch (le32_to_cpu(table[i].type)) {
        case E820_RAM:
            found_ram = true;
            break;
        case E820_SOFT_RESERVED:
            found_soft_reserved = true;
            break;
        }
    }

    /* baseline: RAM present, no SOFT_RESERVED range */
    g_assert_true(found_ram);
    g_assert_false(found_soft_reserved);

    pc_fw_cfg_uninit(fw_cfg);
    qtest_quit(s);
}

static void test_e820_sp_mem(void)
{
    struct e820_entry table[E820_MAX_ENTRIES];
    QFWCFG *fw_cfg;
    QTestState *s;
    size_t n, i;
    int soft_reserved = 0;
    uint64_t soft_reserved_len = 0;

    s = qtest_init("-machine q35 -m 256M,slots=2,maxmem=2G "
                   "-object memory-backend-ram,id=ram0,size=256M "
                   "-numa node,nodeid=0,memdev=ram0 "
                   "-object memory-backend-ram,id=spm0,size=128M "
                   "-device sp-mem,id=sp0,memdev=spm0,node=0");
    fw_cfg = pc_fw_cfg_init(s);

    n = get_e820_table(fw_cfg, table);
    for (i = 0; i < n; i++) {
        if (le32_to_cpu(table[i].type) == E820_SOFT_RESERVED) {
            soft_reserved++;
            soft_reserved_len = le64_to_cpu(table[i].length);
        }
    }

    /* exactly one SOFT_RESERVED range, sized to the backend */
    g_assert_cmpint(soft_reserved, ==, 1);
    g_assert_cmpint(soft_reserved_len, ==, 128 * MiB);

    pc_fw_cfg_uninit(fw_cfg);
    qtest_quit(s);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    qtest_add_func("e820/basic", test_e820_basic);
    qtest_add_func("e820/sp-mem", test_e820_sp_mem);

    return g_test_run();
}
