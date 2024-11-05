// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2015-2017 IBM Corp. */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <cpu.h>
#include <opal-api.h>
#include <opal-internal.h>
#include <time-utils.h>
#include <time.h>

#include "mambo.h"

static bool mambo_probe(void)
{
	if (!dt_find_by_path(dt_root, "/mambo"))
		return false;

	return true;
}

#define BD_INFO_SYNC		0
#define BD_INFO_STATUS		1
#define BD_INFO_BLKSZ		2
#define BD_INFO_DEVSZ		3
#define BD_INFO_CHANGE		4

#define BD_SECT_SZ		512

static inline int callthru_disk_read(int id, void *buf, unsigned long sect,
				     unsigned long nrsect)
{
	return callthru3(SIM_BOGUS_DISK_READ, (unsigned long)buf, sect,
			 (nrsect << 16) | id);
}

static inline int callthru_disk_write(int id, void *buf, unsigned long sect,
				      unsigned long nrsect)
{
	return callthru3(SIM_BOGUS_DISK_WRITE, (unsigned long)buf, sect,
			 (nrsect << 16) | id);
}

static inline unsigned long callthru_disk_info(int op, int id)
{
	return callthru2(SIM_BOGUS_DISK_INFO, (unsigned long)op,
			 (unsigned long)id);
}

extern unsigned long callthru_tcl(const char *str, int len);

unsigned long callthru_tcl(const char *str, int len)
{
	prlog(PR_DEBUG, "Sending TCL to Mambo, cmd: %s\n", str);
	return callthru2(SIM_CALL_TCL, (unsigned long)str, (unsigned long)len);
}

struct bogus_disk_info {
	unsigned long size;
	int id;
};

static int bogus_disk_read(struct blocklevel_device *bl, uint64_t pos, void *buf,
			  uint64_t len)
{
	struct bogus_disk_info *bdi = bl->priv;
	int rc, read_sectors = 0;
	char b[BD_SECT_SZ];

	if (len >= BD_SECT_SZ) {
		rc = callthru_disk_read(bdi->id, buf, pos/BD_SECT_SZ,
					  len/BD_SECT_SZ);
		if (rc)
			return rc;
		read_sectors = (len / BD_SECT_SZ);
	}

	if ((len % BD_SECT_SZ) == 0)
		return 0;

	/*
	 * Read any unaligned data into a temporaty buffer b, then copy
	 * to buf
	 */
	rc =  callthru_disk_read(bdi->id, b, (pos/BD_SECT_SZ) + read_sectors, 1);
	if (rc)
		return rc;
	memcpy(buf + (read_sectors * BD_SECT_SZ) , &b[pos % BD_SECT_SZ],
			len - (read_sectors * BD_SECT_SZ));
	return rc;
}

static int bogus_disk_write(struct blocklevel_device *bl, uint64_t pos,
			    const void *buf, uint64_t len)
{
	struct bogus_disk_info *bdi = bl->priv;

	if ((len % BD_SECT_SZ) != 0)
		return OPAL_PARAMETER;

	return callthru_disk_write(bdi->id, (void *)buf, pos/BD_SECT_SZ,
				   len/BD_SECT_SZ);

}

static int bogus_disk_erase(struct blocklevel_device *bl __unused,
			   uint64_t pos __unused, uint64_t len __unused)
{
	return 0; /* NOP */
}

static int bogus_disk_get_info(struct blocklevel_device *bl, const char **name,
			      uint64_t *total_size, uint32_t *erase_granule)
{
	struct bogus_disk_info *bdi = bl->priv;

	if (total_size)
		*total_size = bdi->size;

	if (erase_granule)
		*erase_granule = BD_SECT_SZ;

	if (name)
		*name = "mambobogus";

	return 0;
}

static void bogus_disk_flash_init(void)
{
	struct blocklevel_device *bl;
	struct bogus_disk_info *bdi;
	unsigned long id = 0, size;
	int rc;

	if (!chip_quirk(QUIRK_MAMBO_CALLOUTS))
		return;

	while (1) {

		rc = callthru_disk_info(BD_INFO_STATUS, id);
		if (rc < 0)
			return;

		size = callthru_disk_info(BD_INFO_DEVSZ, id) * 1024;
		prlog(PR_NOTICE, "mambo: Found bogus disk size: 0x%lx\n", size);

		bl = zalloc(sizeof(struct blocklevel_device));
		bdi = zalloc(sizeof(struct bogus_disk_info));
		if (!bl || !bdi) {
			free(bl);
			free(bdi);
			prerror("mambo: Failed to start bogus disk, ENOMEM\n");
			return;
		}

		bl->read = &bogus_disk_read;
		bl->write = &bogus_disk_write;
		bl->erase = &bogus_disk_erase;
		bl->get_info = &bogus_disk_get_info;
		bdi->id = id;
		bdi->size = size;
		bl->priv = bdi;
		bl->erase_mask = BD_SECT_SZ - 1;

		rc = flash_register(bl);
		if (rc)
			prerror("mambo: Failed to register bogus disk: %li\n",
				id);
		id++;
	}
}

static int64_t time_delta = 0;

static int64_t mambo_rtc_read(__be32 *ymd, __be64 *hmsm)
{
	int64_t mambo_time;
	struct tm t;
	time_t mt;
	uint32_t __ymd;
	uint64_t __hmsm;

	if (!ymd || !hmsm)
		return OPAL_PARAMETER;

	mambo_time = callthru0(SIM_GET_TIME_CODE);
	mt = mambo_time >> 32;
	mt += time_delta;
	gmtime_r(&mt, &t);
	tm_to_datetime(&t, &__ymd, &__hmsm);

	*ymd = cpu_to_be32(__ymd);
	*hmsm = cpu_to_be64(__hmsm);

	return OPAL_SUCCESS;
}

static int64_t mambo_rtc_write(uint32_t ymd, uint64_t hmsm)
{
	int64_t mambo_time;
	struct tm tm;
	time_t mt, new_mt;

	mambo_time = callthru0(SIM_GET_TIME_CODE);
	mt = mambo_time >> 32;

	datetime_to_tm(ymd, hmsm, &tm);
	new_mt = mktime(&tm);

	time_delta = new_mt - mt;

	return OPAL_SUCCESS;
}

static void mambo_rtc_init(void)
{
	struct dt_node *np = dt_new(opal_node, "rtc");
	dt_add_property_strings(np, "compatible", "ibm,opal-rtc");

	opal_register(OPAL_RTC_READ, mambo_rtc_read, 2);
	opal_register(OPAL_RTC_WRITE, mambo_rtc_write, 2);
}

static void mambo_system_reset_cpu(struct cpu_thread *cpu)
{
	uint32_t core_id;
	uint32_t thread_id;
	char tcl_cmd[50];

	core_id = pir_to_core_id(cpu->pir);
	thread_id = pir_to_thread_id(cpu->pir);

	snprintf(tcl_cmd, sizeof(tcl_cmd), "mysim cpu %i:%i interrupt SystemReset", core_id, thread_id);
	callthru_tcl(tcl_cmd, strlen(tcl_cmd));
}

#define SYS_RESET_ALL		-1
#define SYS_RESET_ALL_OTHERS	-2

static int64_t mambo_signal_system_reset(int32_t cpu_nr)
{
	struct cpu_thread *cpu;

	if (cpu_nr < 0) {
		if (cpu_nr < SYS_RESET_ALL_OTHERS)
			return OPAL_PARAMETER;

		for_each_cpu(cpu) {
			if (cpu == this_cpu())
				continue;
			mambo_system_reset_cpu(cpu);

		}
		if (cpu_nr == SYS_RESET_ALL)
			mambo_system_reset_cpu(this_cpu());

		return OPAL_SUCCESS;

	} else {
		cpu = find_cpu_by_server(cpu_nr);
		if (!cpu)
			return OPAL_PARAMETER;

		mambo_system_reset_cpu(cpu);
		return OPAL_SUCCESS;
	}
}

static void mambo_sreset_init(void)
{
	opal_register(OPAL_SIGNAL_SYSTEM_RESET, mambo_signal_system_reset, 1);
}

static void mambo_platform_init(void)
{
	mambo_sreset_init();
	mambo_rtc_init();
	bogus_disk_flash_init();
}

static int64_t mambo_cec_power_down(uint64_t request __unused)
{
	if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
		callthru0(SIM_EXIT_CODE);

	return OPAL_UNSUPPORTED;
}

static void __attribute__((noreturn)) mambo_terminate(const char *msg __unused)
{
	if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
		callthru0(SIM_EXIT_CODE);

	for (;;) ;
}

static int mambo_heartbeat_time(void)
{
	/*
	 * Mambo is slow and has no console input interrupt, so faster
	 * polling is needed to ensure its responsiveness.
	 */
	return 100;
}

DECLARE_PLATFORM(mambo) = {
	.name			= "Mambo",
	.probe			= mambo_probe,
	.init		= mambo_platform_init,
	.cec_power_down = mambo_cec_power_down,
	.terminate	= mambo_terminate,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.heartbeat_time		= mambo_heartbeat_time,
	.nvram_info		= fake_nvram_info,
	.nvram_start_read	= fake_nvram_start_read,
	.nvram_write		= fake_nvram_write,
};
