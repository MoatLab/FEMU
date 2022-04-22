// SPDX-License-Identifier: GPL-2.0+
/*
 * Tests for ACPI table generation
 *
 * Copyright 2019 Google LLC
 * Written by Simon Glass <sjg@chromium.org>
 */

#include <common.h>
#include <console.h>
#include <dm.h>
#include <malloc.h>
#include <mapmem.h>
#include <version.h>
#include <tables_csum.h>
#include <version.h>
#include <acpi/acpigen.h>
#include <acpi/acpi_device.h>
#include <acpi/acpi_table.h>
#include <asm/global_data.h>
#include <dm/acpi.h>
#include <dm/test.h>
#include <test/ut.h>
#include "acpi.h"

#define BUF_SIZE		4096

/**
 * struct testacpi_plat - Platform data for the test ACPI device
 *
 * @no_name: true to emit an empty ACPI name from testacpi_get_name()
 * @return_error: true to return an error instead of a name
 */
struct testacpi_plat {
	bool return_error;
	bool no_name;
};

static int testacpi_write_tables(const struct udevice *dev,
				 struct acpi_ctx *ctx)
{
	struct acpi_dmar *dmar;
	int ret;

	dmar = (struct acpi_dmar *)ctx->current;
	acpi_create_dmar(dmar, DMAR_INTR_REMAP);
	ctx->current += sizeof(struct acpi_dmar);
	ret = acpi_add_table(ctx, dmar);
	if (ret)
		return log_msg_ret("add", ret);

	return 0;
}

static int testacpi_get_name(const struct udevice *dev, char *out_name)
{
	struct testacpi_plat *plat = dev_get_plat(dev);

	if (plat->return_error)
		return -EINVAL;
	if (plat->no_name) {
		*out_name = '\0';
		return 0;
	}
	if (device_get_uclass_id(dev->parent) == UCLASS_TEST_ACPI)
		return acpi_copy_name(out_name, ACPI_TEST_CHILD_NAME);
	else
		return acpi_copy_name(out_name, ACPI_TEST_DEV_NAME);
}

static int testacpi_fill_ssdt(const struct udevice *dev, struct acpi_ctx *ctx)
{
	const char *data;

	data = dev_read_string(dev, "acpi-ssdt-test-data");
	if (data) {
		while (*data)
			acpigen_emit_byte(ctx, *data++);
	}

	return 0;
}

static int testacpi_inject_dsdt(const struct udevice *dev, struct acpi_ctx *ctx)
{
	const char *data;

	data = dev_read_string(dev, "acpi-dsdt-test-data");
	if (data) {
		while (*data)
			acpigen_emit_byte(ctx, *data++);
	}

	return 0;
}

struct acpi_ops testacpi_ops = {
	.get_name	= testacpi_get_name,
	.write_tables	= testacpi_write_tables,
	.fill_ssdt	= testacpi_fill_ssdt,
	.inject_dsdt	= testacpi_inject_dsdt,
};

static const struct udevice_id testacpi_ids[] = {
	{ .compatible = "denx,u-boot-acpi-test" },
	{ }
};

U_BOOT_DRIVER(testacpi_drv) = {
	.name	= "testacpi_drv",
	.of_match	= testacpi_ids,
	.id	= UCLASS_TEST_ACPI,
	.bind	= dm_scan_fdt_dev,
	.plat_auto	= sizeof(struct testacpi_plat),
	ACPI_OPS_PTR(&testacpi_ops)
};

UCLASS_DRIVER(testacpi) = {
	.name		= "testacpi",
	.id		= UCLASS_TEST_ACPI,
};

/* Test ACPI get_name() */
static int dm_test_acpi_get_name(struct unit_test_state *uts)
{
	char name[ACPI_NAME_MAX];
	struct udevice *dev, *dev2, *i2c, *spi, *timer, *sound;
	struct udevice *pci, *root;

	/* Test getting the name from the driver */
	ut_assertok(uclass_first_device_err(UCLASS_TEST_ACPI, &dev));
	ut_assertok(acpi_get_name(dev, name));
	ut_asserteq_str(ACPI_TEST_DEV_NAME, name);

	/* Test getting the name from the device tree */
	ut_assertok(uclass_get_device_by_name(UCLASS_TEST_FDT, "a-test",
					      &dev2));
	ut_assertok(acpi_get_name(dev2, name));
	ut_asserteq_str("GHIJ", name);

	/* Test getting the name from acpi_device_get_name() */
	ut_assertok(uclass_first_device(UCLASS_I2C, &i2c));
	ut_assertok(acpi_get_name(i2c, name));
	ut_asserteq_str("I2C0", name);

	ut_assertok(uclass_first_device(UCLASS_SPI, &spi));
	ut_assertok(acpi_get_name(spi, name));
	ut_asserteq_str("SPI0", name);

	/* ACPI doesn't know about the timer */
	ut_assertok(uclass_first_device(UCLASS_TIMER, &timer));
	ut_asserteq(-ENOENT, acpi_get_name(timer, name));

	/* May as well test the rest of the cases */
	ut_assertok(uclass_first_device(UCLASS_SOUND, &sound));
	ut_assertok(acpi_get_name(sound, name));
	ut_asserteq_str("HDAS", name);

	ut_assertok(uclass_first_device(UCLASS_PCI, &pci));
	ut_assertok(acpi_get_name(pci, name));
	ut_asserteq_str("PCI0", name);

	ut_assertok(uclass_first_device(UCLASS_ROOT, &root));
	ut_assertok(acpi_get_name(root, name));
	ut_asserteq_str("\\_SB", name);

	/* Note that we don't have tests for acpi_name_from_id() */

	return 0;
}
DM_TEST(dm_test_acpi_get_name, UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);

/* Test acpi_get_table_revision() */
static int dm_test_acpi_get_table_revision(struct unit_test_state *uts)
{
	ut_asserteq(1, acpi_get_table_revision(ACPITAB_MCFG));
	ut_asserteq(2, acpi_get_table_revision(ACPITAB_RSDP));
	ut_asserteq(4, acpi_get_table_revision(ACPITAB_TPM2));
	ut_asserteq(-EINVAL, acpi_get_table_revision(ACPITAB_COUNT));

	return 0;
}
DM_TEST(dm_test_acpi_get_table_revision,
	UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);

/* Test acpi_create_dmar() */
static int dm_test_acpi_create_dmar(struct unit_test_state *uts)
{
	struct acpi_dmar dmar;
	struct udevice *cpu;

	ut_assertok(uclass_first_device(UCLASS_CPU, &cpu));
	ut_assertnonnull(cpu);
	ut_assertok(acpi_create_dmar(&dmar, DMAR_INTR_REMAP));
	ut_asserteq(DMAR_INTR_REMAP, dmar.flags);
	ut_asserteq(32 - 1, dmar.host_address_width);

	return 0;
}
DM_TEST(dm_test_acpi_create_dmar, UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);

/* Test acpi_fill_header() */
static int dm_test_acpi_fill_header(struct unit_test_state *uts)
{
	struct acpi_table_header hdr;

	/* Make sure these 5 fields are not changed */
	hdr.length = 0x11;
	hdr.revision = 0x22;
	hdr.checksum = 0x33;
	hdr.aslc_revision = 0x44;
	acpi_fill_header(&hdr, "ABCD");

	ut_asserteq_mem("ABCD", hdr.signature, sizeof(hdr.signature));
	ut_asserteq(0x11, hdr.length);
	ut_asserteq(0x22, hdr.revision);
	ut_asserteq(0x33, hdr.checksum);
	ut_asserteq_mem(OEM_ID, hdr.oem_id, sizeof(hdr.oem_id));
	ut_asserteq_mem(OEM_TABLE_ID, hdr.oem_table_id,
			sizeof(hdr.oem_table_id));
	ut_asserteq(U_BOOT_BUILD_DATE, hdr.oem_revision);
	ut_asserteq_mem(ASLC_ID, hdr.aslc_id, sizeof(hdr.aslc_id));
	ut_asserteq(0x44, hdr.aslc_revision);

	return 0;
}
DM_TEST(dm_test_acpi_fill_header, UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);

/* Test ACPI write_tables() */
static int dm_test_acpi_write_tables(struct unit_test_state *uts)
{
	struct acpi_dmar *dmar;
	struct acpi_ctx ctx;
	void *buf;
	int i;

	buf = malloc(BUF_SIZE);
	ut_assertnonnull(buf);

	acpi_setup_base_tables(&ctx, buf);
	dmar = ctx.current;
	ut_assertok(acpi_write_dev_tables(&ctx));

	/*
	 * We should have three dmar tables, one for each
	 * "denx,u-boot-acpi-test" device
	 */
	ut_asserteq_ptr(dmar + 3, ctx.current);
	ut_asserteq(DMAR_INTR_REMAP, dmar->flags);
	ut_asserteq(32 - 1, dmar->host_address_width);

	ut_asserteq(DMAR_INTR_REMAP, dmar[1].flags);
	ut_asserteq(32 - 1, dmar[1].host_address_width);

	ut_asserteq(DMAR_INTR_REMAP, dmar[2].flags);
	ut_asserteq(32 - 1, dmar[2].host_address_width);

	/* Check that the pointers were added correctly */
	for (i = 0; i < 3; i++) {
		ut_asserteq(map_to_sysmem(dmar + i), ctx.rsdt->entry[i]);
		ut_asserteq(map_to_sysmem(dmar + i), ctx.xsdt->entry[i]);
	}
	ut_asserteq(0, ctx.rsdt->entry[3]);
	ut_asserteq(0, ctx.xsdt->entry[3]);

	return 0;
}
DM_TEST(dm_test_acpi_write_tables, UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);

/* Test basic ACPI functions */
static int dm_test_acpi_basic(struct unit_test_state *uts)
{
	struct acpi_ctx ctx;

	/* Check align works */
	ctx.current = (void *)5;
	acpi_align(&ctx);
	ut_asserteq_ptr((void *)16, ctx.current);

	/* Check that align does nothing if already aligned */
	acpi_align(&ctx);
	ut_asserteq_ptr((void *)16, ctx.current);
	acpi_align64(&ctx);
	ut_asserteq_ptr((void *)64, ctx.current);
	acpi_align64(&ctx);
	ut_asserteq_ptr((void *)64, ctx.current);

	/* Check incrementing */
	acpi_inc(&ctx, 3);
	ut_asserteq_ptr((void *)67, ctx.current);
	acpi_inc_align(&ctx, 3);
	ut_asserteq_ptr((void *)80, ctx.current);

	return 0;
}
DM_TEST(dm_test_acpi_basic, UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);

/* Test acpi_setup_base_tables */
static int dm_test_acpi_setup_base_tables(struct unit_test_state *uts)
{
	struct acpi_rsdp *rsdp;
	struct acpi_rsdt *rsdt;
	struct acpi_xsdt *xsdt;
	struct acpi_ctx ctx;
	void *buf, *end;

	/*
	 * Use an unaligned address deliberately, by allocating an aligned
	 * address and then adding 4 to it
	 */
	buf = memalign(64, BUF_SIZE);
	ut_assertnonnull(buf);
	acpi_setup_base_tables(&ctx, buf + 4);
	ut_asserteq(map_to_sysmem(PTR_ALIGN(buf + 4, 16)), gd->arch.acpi_start);

	rsdp = buf + 16;
	ut_asserteq_ptr(rsdp, ctx.rsdp);
	ut_asserteq_mem(RSDP_SIG, rsdp->signature, sizeof(rsdp->signature));
	ut_asserteq(sizeof(*rsdp), rsdp->length);
	ut_assertok(table_compute_checksum(rsdp, 20));
	ut_assertok(table_compute_checksum(rsdp, sizeof(*rsdp)));

	rsdt = PTR_ALIGN((void *)rsdp + sizeof(*rsdp), 16);
	ut_asserteq_ptr(rsdt, ctx.rsdt);
	ut_asserteq_mem("RSDT", rsdt->header.signature, ACPI_NAME_LEN);
	ut_asserteq(sizeof(*rsdt), rsdt->header.length);
	ut_assertok(table_compute_checksum(rsdt, sizeof(*rsdt)));

	xsdt = PTR_ALIGN((void *)rsdt + sizeof(*rsdt), 16);
	ut_asserteq_ptr(xsdt, ctx.xsdt);
	ut_asserteq_mem("XSDT", xsdt->header.signature, ACPI_NAME_LEN);
	ut_asserteq(sizeof(*xsdt), xsdt->header.length);
	ut_assertok(table_compute_checksum(xsdt, sizeof(*xsdt)));

	end = PTR_ALIGN((void *)xsdt + sizeof(*xsdt), 64);
	ut_asserteq_ptr(end, ctx.current);

	ut_asserteq(map_to_sysmem(rsdt), rsdp->rsdt_address);
	ut_asserteq(map_to_sysmem(xsdt), rsdp->xsdt_address);

	return 0;
}
DM_TEST(dm_test_acpi_setup_base_tables,
	UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);

/* Test 'acpi list' command */
static int dm_test_acpi_cmd_list(struct unit_test_state *uts)
{
	struct acpi_ctx ctx;
	ulong addr;
	void *buf;

	buf = memalign(16, BUF_SIZE);
	ut_assertnonnull(buf);
	acpi_setup_base_tables(&ctx, buf);

	ut_assertok(acpi_write_dev_tables(&ctx));

	console_record_reset();
	run_command("acpi list", 0);
	addr = (ulong)map_to_sysmem(buf);
	ut_assert_nextline("ACPI tables start at %lx", addr);
	ut_assert_nextline("RSDP %08lx %06zx (v02 U-BOOT)", addr,
			   sizeof(struct acpi_rsdp));
	addr = ALIGN(addr + sizeof(struct acpi_rsdp), 16);
	ut_assert_nextline("RSDT %08lx %06zx (v01 U-BOOT U-BOOTBL %x INTL 0)",
			   addr, sizeof(struct acpi_table_header) +
			   3 * sizeof(u32), U_BOOT_BUILD_DATE);
	addr = ALIGN(addr + sizeof(struct acpi_rsdt), 16);
	ut_assert_nextline("XSDT %08lx %06zx (v01 U-BOOT U-BOOTBL %x INTL 0)",
			   addr, sizeof(struct acpi_table_header) +
			   3 * sizeof(u64), U_BOOT_BUILD_DATE);
	addr = ALIGN(addr + sizeof(struct acpi_xsdt), 64);
	ut_assert_nextline("DMAR %08lx %06zx (v01 U-BOOT U-BOOTBL %x INTL 0)",
			   addr, sizeof(struct acpi_dmar), U_BOOT_BUILD_DATE);
	addr = ALIGN(addr + sizeof(struct acpi_dmar), 16);
	ut_assert_nextline("DMAR %08lx %06zx (v01 U-BOOT U-BOOTBL %x INTL 0)",
			   addr, sizeof(struct acpi_dmar), U_BOOT_BUILD_DATE);
	addr = ALIGN(addr + sizeof(struct acpi_dmar), 16);
	ut_assert_nextline("DMAR %08lx %06zx (v01 U-BOOT U-BOOTBL %x INTL 0)",
			   addr, sizeof(struct acpi_dmar), U_BOOT_BUILD_DATE);
	ut_assert_console_end();

	return 0;
}
DM_TEST(dm_test_acpi_cmd_list, UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);

/* Test 'acpi dump' command */
static int dm_test_acpi_cmd_dump(struct unit_test_state *uts)
{
	struct acpi_ctx ctx;
	ulong addr;
	void *buf;

	buf = memalign(16, BUF_SIZE);
	ut_assertnonnull(buf);
	acpi_setup_base_tables(&ctx, buf);

	ut_assertok(acpi_write_dev_tables(&ctx));

	/* First search for a non-existent table */
	console_record_reset();
	run_command("acpi dump rdst", 0);
	ut_assert_nextline("Table 'RDST' not found");
	ut_assert_console_end();

	/* Now a real table */
	console_record_reset();
	run_command("acpi dump dmar", 0);
	addr = ALIGN(map_to_sysmem(ctx.xsdt) + sizeof(struct acpi_xsdt), 64);
	ut_assert_nextline("DMAR @ %08lx", addr);
	ut_assert_nextlines_are_dump(0x30);
	ut_assert_console_end();

	return 0;
}
DM_TEST(dm_test_acpi_cmd_dump, UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);

/* Test acpi_device_path() */
static int dm_test_acpi_device_path(struct unit_test_state *uts)
{
	struct testacpi_plat *plat;
	char buf[ACPI_PATH_MAX];
	struct udevice *dev, *child;

	ut_assertok(uclass_first_device_err(UCLASS_TEST_ACPI, &dev));
	ut_assertok(acpi_device_path(dev, buf, sizeof(buf)));
	ut_asserteq_str("\\_SB." ACPI_TEST_DEV_NAME, buf);

	/* Test running out of space */
	buf[5] = '\0';
	ut_asserteq(-ENOSPC, acpi_device_path(dev, buf, 5));
	ut_asserteq('\0', buf[5]);

	/* Test a three-component name */
	ut_assertok(device_first_child_err(dev, &child));
	ut_assertok(acpi_device_path(child, buf, sizeof(buf)));
	ut_asserteq_str("\\_SB." ACPI_TEST_DEV_NAME "." ACPI_TEST_CHILD_NAME,
			buf);

	/* Test handling of a device which doesn't produce a name */
	plat = dev_get_plat(dev);
	plat->no_name = true;
	ut_assertok(acpi_device_path(child, buf, sizeof(buf)));
	ut_asserteq_str("\\_SB." ACPI_TEST_CHILD_NAME, buf);

	/* Test handling of a device which returns an error */
	plat = dev_get_plat(dev);
	plat->return_error = true;
	ut_asserteq(-EINVAL, acpi_device_path(child, buf, sizeof(buf)));

	return 0;
}
DM_TEST(dm_test_acpi_device_path, UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);

/* Test acpi_device_status() */
static int dm_test_acpi_device_status(struct unit_test_state *uts)
{
	struct udevice *dev;

	ut_assertok(uclass_first_device_err(UCLASS_TEST_ACPI, &dev));
	ut_asserteq(ACPI_DSTATUS_ALL_ON, acpi_device_status(dev));

	return 0;
}
DM_TEST(dm_test_acpi_device_status, UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);

/* Test acpi_fill_ssdt() */
static int dm_test_acpi_fill_ssdt(struct unit_test_state *uts)
{
	struct acpi_ctx ctx;
	u8 *buf;

	buf = malloc(BUF_SIZE);
	ut_assertnonnull(buf);

	acpi_reset_items();
	ctx.current = buf;
	buf[4] = 'z';	/* sentinel */
	ut_assertok(acpi_fill_ssdt(&ctx));

	/*
	 * These values come from acpi-test2's acpi-ssdt-test-data property.
	 * This device comes first because of u-boot,acpi-ssdt-order
	 */
	ut_asserteq('c', buf[0]);
	ut_asserteq('d', buf[1]);

	/* These values come from acpi-test's acpi-ssdt-test-data property */
	ut_asserteq('a', buf[2]);
	ut_asserteq('b', buf[3]);

	ut_asserteq('z', buf[4]);

	return 0;
}
DM_TEST(dm_test_acpi_fill_ssdt, UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);

/* Test acpi_inject_dsdt() */
static int dm_test_acpi_inject_dsdt(struct unit_test_state *uts)
{
	struct acpi_ctx ctx;
	u8 *buf;

	buf = malloc(BUF_SIZE);
	ut_assertnonnull(buf);

	acpi_reset_items();
	ctx.current = buf;
	buf[4] = 'z';	/* sentinel */
	ut_assertok(acpi_inject_dsdt(&ctx));

	/*
	 * These values come from acpi-test's acpi-dsdt-test-data property.
	 * There is no u-boot,acpi-dsdt-order so device-tree order is used.
	 */
	ut_asserteq('h', buf[0]);
	ut_asserteq('i', buf[1]);

	/* These values come from acpi-test's acpi-dsdt-test-data property */
	ut_asserteq('j', buf[2]);
	ut_asserteq('k', buf[3]);

	ut_asserteq('z', buf[4]);

	return 0;
}
DM_TEST(dm_test_acpi_inject_dsdt, UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);

/* Test 'acpi items' command */
static int dm_test_acpi_cmd_items(struct unit_test_state *uts)
{
	struct acpi_ctx ctx;
	void *buf;

	buf = malloc(BUF_SIZE);
	ut_assertnonnull(buf);

	acpi_reset_items();
	ctx.current = buf;
	ut_assertok(acpi_fill_ssdt(&ctx));
	console_record_reset();
	run_command("acpi items", 0);
	ut_assert_nextline("dev 'acpi-test', type 1, size 2");
	ut_assert_nextline("dev 'acpi-test2', type 1, size 2");
	ut_assert_console_end();

	acpi_reset_items();
	ctx.current = buf;
	ut_assertok(acpi_inject_dsdt(&ctx));
	console_record_reset();
	run_command("acpi items", 0);
	ut_assert_nextline("dev 'acpi-test', type 2, size 2");
	ut_assert_nextline("dev 'acpi-test2', type 2, size 2");
	ut_assert_console_end();

	console_record_reset();
	run_command("acpi items -d", 0);
	ut_assert_nextline("dev 'acpi-test', type 2, size 2");
	ut_assert_nextlines_are_dump(2);
	ut_assert_nextline("%s", "");
	ut_assert_nextline("dev 'acpi-test2', type 2, size 2");
	ut_assert_nextlines_are_dump(2);
	ut_assert_nextline("%s", "");
	ut_assert_console_end();

	return 0;
}
DM_TEST(dm_test_acpi_cmd_items, UT_TESTF_SCAN_PDATA | UT_TESTF_SCAN_FDT);
