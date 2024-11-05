// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * OPAL Processor Runtime Diagnostics (PRD)
 * Runs Hostboot RunTime (HBRT) code in a userspace wrapper
 *
 * Firmware in userspace? Brilliant!
 *
 * Copyright 2014-2019 IBM Corp.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>
#include <poll.h>
#include <signal.h>
#include <dirent.h>

#include <endian.h>

#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <linux/ipmi.h>
#include <linux/limits.h>

#include <asm/opal-prd.h>

#include <opal-api.h>
#include <types.h>

#include <ccan/list/list.h>

#include "opal-prd.h"
#include "hostboot-interface.h"
#include "module.h"
#include "pnor.h"
#include "i2c.h"

struct prd_range {
	const char		*name;
	uint64_t		physaddr;
	uint64_t		size;
	void			*buf;
	bool			multiple;
	uint32_t		instance;
};

struct prd_msgq_item {
	struct list_node	list;
	struct opal_prd_msg	msg;
};

struct opal_prd_ctx {
	int			fd;
	int			socket;
	struct opal_prd_info	info;
	struct prd_range	*ranges;
	int			n_ranges;
	bool			fw_range_instances;
	long			page_size;
	void			*code_addr;
	size_t			code_size;
	bool			debug;
	struct pnor		pnor;
	char			*hbrt_file_name;
	bool			use_syslog;
	bool			expert_mode;
	struct list_head	msgq;
	struct opal_prd_msg	*msg;
	size_t			msg_alloc_len;
	void			(*vlog)(int, const char *, va_list);
};

enum control_msg_type {
	CONTROL_MSG_ENABLE_OCCS		= 0x00,
	CONTROL_MSG_DISABLE_OCCS	= 0x01,
	CONTROL_MSG_TEMP_OCC_RESET	= 0x02,
	CONTROL_MSG_TEMP_OCC_ERROR	= 0x03,
	CONTROL_MSG_ATTR_OVERRIDE	= 0x04,
	CONTROL_MSG_HTMGT_PASSTHRU	= 0x05,
	CONTROL_MSG_RUN_CMD		= 0x30,
};

struct control_msg {
	enum control_msg_type	type;
	int			response;
	union {
		struct {
			unsigned int	argc;
		} run_cmd;
		struct {
			uint64_t	chip;
		} occ_reset;
		struct {
			uint64_t	chip;
		} occ_error;
	};
	unsigned int		data_len;
	unsigned char		data[];

};

#define MAX_CONTROL_MSG_BUF	4096

static struct opal_prd_ctx *ctx;

static const char *opal_prd_devnode = "/dev/opal-prd";
static const char *opal_prd_socket = "/run/opal-prd-control";
static const char *hbrt_code_region_name = "hbrt-code-image";
static const char *hbrt_code_region_name_ibm = "ibm,hbrt-code-image";
static const int opal_prd_version = 1;
static uint64_t opal_prd_ipoll = 0xf000000000000000;

static const int max_msgq_len = 16;

static const char *ipmi_devnode = "/dev/ipmi0";
static const int ipmi_timeout_ms = 5000;

static const char *devicetree_base =
		"/sys/firmware/devicetree/base";

/* Memory error handling */
static const char *mem_offline_soft =
		"/sys/devices/system/memory/soft_offline_page";
static const char *mem_offline_hard =
		"/sys/devices/system/memory/hard_offline_page";

#define ADDR_STRING_SZ 20 /* Hold %16lx */

/* This is the "real" HBRT call table for calling into HBRT as
 * provided by it. It will be used by the assembly thunk
 */
struct runtime_interfaces *hservice_runtime;
struct runtime_interfaces hservice_runtime_fixed;

/* This is the callback table provided by assembly code */
extern struct host_interfaces hinterface;

/* Create opd to call hostservice init */
struct func_desc {
	void *addr;
	void *toc;
} hbrt_entry;

static int nr_chips;
static u64 chips[256];

static int read_prd_msg(struct opal_prd_ctx *ctx);

static struct prd_range *find_range(const char *name, uint32_t instance)
{
	struct prd_range *range;
	unsigned int i;

	for (i = 0; i < ctx->n_ranges; i++) {
		range = &ctx->ranges[i];

		if (strcmp(range->name, name))
			continue;

		if (range->multiple && range->instance != instance)
			continue;

		return range;
	}

	return NULL;
}

static void pr_log_stdio(int priority, const char *fmt, va_list ap)
{
	if (!ctx->debug && priority >= LOG_DEBUG)
		return;

	vprintf(fmt, ap);
	printf("\n");

	if (ctx->debug)
		fflush(stdout);
}

/* standard logging prefixes:
 * HBRT:  Messages from hostboot runtime code
 * FW:    Interactions with OPAL firmware
 * IMAGE: HBRT image loading
 * MEM:   Memory failure interface
 * SCOM:  Chip SCOM interface
 * IPMI:  IPMI interface
 * PNOR:  PNOR interface
 * I2C:   i2c interface
 * PM:    PM/OCC interface
 * CTRL:  User-triggered control events
 * KMOD:   Kernel module functions
 */

void pr_log(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ctx->vlog(priority, fmt, ap);
	va_end(ap);
}

static void pr_log_nocall(const char *name)
{
	pr_log(LOG_WARNING, "HBRT: Call %s not provided", name);
}

static void hexdump(const uint8_t *data, uint32_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("\n");
		else if(i % 4 == 0)
			printf(" ");

		printf("%02x", data[i]);
	}

	printf("\n");
}

static void pr_log_daemon_init(void)
{
	if (ctx->use_syslog) {
		openlog("opal-prd", LOG_NDELAY, LOG_DAEMON);
		ctx->vlog = vsyslog;
	}
}

/* Check service processor type */
static bool is_fsp_system(void)
{
	bool fsp_system = true;
	char *path;
	int rc;

	rc = asprintf(&path, "%s/fsps", devicetree_base);
	if (rc < 0) {
		pr_log(LOG_ERR, "FW: error creating '/fsps' path %m");
		return false;
	}

	if (access(path, F_OK))
		fsp_system = false;

	free(path);
	return fsp_system;
}

/**
 * ABI check that we can't perform at build-time: we want to ensure that the
 * layout of struct host_interfaces matches that defined in the thunk.
 */
static void check_abi(void)
{
	extern unsigned char __hinterface_start, __hinterface_pad,
	       __hinterface_end;

	/* ensure our struct size matches the thunk definition */
	assert((&__hinterface_end - &__hinterface_start)
			== sizeof(struct host_interfaces));

	/* ensure the padding layout is as expected */
	assert((void *)&__hinterface_start == (void *)&hinterface);
	assert((void *)&__hinterface_pad == (void *)&hinterface.reserved);
}

/* HBRT init wrappers */
extern struct runtime_interfaces *call_hbrt_init(struct host_interfaces *);

/* hservice Call wrappers */

extern void call_cxxtestExecute(void *);
extern int call_handle_attns(uint64_t i_proc,
			uint64_t i_ipollStatus,
			uint64_t i_ipollMask);
extern void call_process_occ_error (uint64_t i_chipId);
extern int call_enable_attns(void);
extern int call_enable_occ_actuation(bool i_occActivation);
extern void call_process_occ_reset(uint64_t i_chipId);
extern int call_mfg_htmgt_pass_thru(uint16_t i_cmdLength, uint8_t *i_cmdData,
				uint16_t *o_rspLength, uint8_t *o_rspData);
extern int call_apply_attr_override(uint8_t *i_data, size_t size);
extern int call_run_command(int argc, const char **argv, char **o_outString);
extern int call_sbe_message_passing(uint32_t i_chipId);
extern uint64_t call_get_ipoll_events(void);
extern int call_firmware_notify(uint64_t len, void *data);
extern int call_reset_pm_complex(uint64_t chip);
extern int call_load_pm_complex(u64 chip, u64 homer, u64 occ_common, u32 mode);
extern int call_start_pm_complex(u64 chip);

void hservice_puts(const char *str)
{
	int priority = LOG_INFO;

	/* Interpret the 2-character ERR_MRK/FAIL_MRK/WARN_MRK prefixes that
	 * may be present on HBRT log messages, and bump the log priority as
	 * appropriate.
	 */
	if (strlen(str) >= 2 && str[1] == '>') {
		switch (str[0]) {
		case 'E':
		case 'F':
			priority = LOG_ERR;
			break;
		case 'W':
			priority = LOG_WARNING;
			break;
		}
	}

	pr_log(priority, "HBRT: %s", str);
}

void hservice_assert(void)
{
	pr_log(LOG_ERR, "HBRT: Failed assertion! exiting.");
	exit(EXIT_FAILURE);
}

void *hservice_malloc(size_t size)
{
	return malloc(size);
}

void hservice_free(void *ptr)
{
	free(ptr);
}

void *hservice_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

int hservice_scom_read(uint64_t chip_id, uint64_t addr, void *buf)
{
	int rc;
	struct opal_prd_scom scom;

	scom.chip = chip_id;
	scom.addr = addr;

	rc = ioctl(ctx->fd, OPAL_PRD_SCOM_READ, &scom);
	if (rc) {
		pr_log(LOG_ERR, "SCOM: ioctl read(chip 0x%lx, addr 0x%lx) "
				"failed: %m", chip_id, addr);
		return 0;
	}
	rc = (int)scom.rc;

	pr_debug("SCOM: read: chip 0x%lx, addr 0x%lx, val 0x%lx, rc %d",
		 chip_id, addr, scom.data, rc);

	*(uint64_t *)buf = htobe64(scom.data);

	return rc;
}

int hservice_scom_write(uint64_t chip_id, uint64_t addr,
                               const void *buf)
{
	int rc;
	struct opal_prd_scom scom;

	scom.chip = chip_id;
	scom.addr = addr;
	scom.data = be64toh(*(uint64_t *)buf);

	rc = ioctl(ctx->fd, OPAL_PRD_SCOM_WRITE, &scom);
	if (rc) {
		pr_log(LOG_ERR, "SCOM: ioctl write(chip 0x%lx, addr 0x%lx) "
				"failed: %m", chip_id, addr);
		return 0;
	}
	rc = (int)scom.rc;

	pr_debug("SCOM: write: chip 0x%lx, addr 0x%lx, val 0x%lx, rc %d",
		 chip_id, addr, scom.data, rc);

	return rc;
}

uint64_t hservice_get_reserved_mem(const char *name, uint32_t instance)
{
	struct prd_range *range;

	pr_debug("IMAGE: hservice_get_reserved_mem: %s, %d", name, instance);

	range = find_range(name, instance);
	if (!range) {
		pr_log(LOG_WARNING, "IMAGE: get_reserved_mem: "
				"no such range %s", name);
		return 0;
	}

	if (!range->buf) {
		uint64_t align_physaddr, offset;

		pr_debug("IMAGE: Mapping 0x%016lx 0x%08lx %s[%d]",
				range->physaddr, range->size,
				range->name, range->instance);

		align_physaddr = range->physaddr & ~(ctx->page_size-1);
		offset = range->physaddr & (ctx->page_size-1);
		range->buf = mmap(NULL, range->size, PROT_WRITE | PROT_READ,
					MAP_SHARED, ctx->fd, align_physaddr);

		if (range->buf == MAP_FAILED)
			pr_log(LOG_ERR,
				"IMAGE: mmap of %s[%d](0x%016lx) failed: %m",
				name, instance, range->physaddr);
		else
			range->buf += offset;
	}

	if (range->buf == MAP_FAILED) {
		pr_log(LOG_WARNING,
				"IMAGE: get_reserved_mem: %s[%d] has no vaddr",
				name, instance);
		return 0;
	}

	pr_debug(
		"IMAGE: hservice_get_reserved_mem: %s[%d](0x%016lx) address %p",
			name, range->instance, range->physaddr,
			range->buf);

	return (uint64_t)range->buf;
}

void hservice_nanosleep(uint64_t i_seconds, uint64_t i_nano_seconds)
{
	const struct timespec ns = {
		.tv_sec = i_seconds,
		.tv_nsec = i_nano_seconds
	};

	nanosleep(&ns, NULL);
}

int hservice_set_page_execute(void *addr)
{
	/* HBRT calls this on the pages that are already being executed,
	 * nothing to do here */
	return -1;
}

int hservice_clock_gettime(clockid_t i_clkId, struct timespec *o_tp)
{
	struct timespec tmp;
	int rc;

	rc = clock_gettime(i_clkId, &tmp);
	if (rc)
		return rc;

	o_tp->tv_sec = htobe64(tmp.tv_sec);
	o_tp->tv_nsec = htobe64(tmp.tv_nsec);

	return 0;
}

int hservice_pnor_read(uint32_t i_proc, const char* i_partitionName,
		uint64_t i_offset, void* o_data, size_t i_sizeBytes)
{
	return pnor_operation(&ctx->pnor, i_partitionName, i_offset, o_data,
			      i_sizeBytes, PNOR_OP_READ);
}

int hservice_pnor_write(uint32_t i_proc, const char* i_partitionName,
		uint64_t i_offset, void* o_data, size_t i_sizeBytes)
{
	return pnor_operation(&ctx->pnor, i_partitionName, i_offset, o_data,
			      i_sizeBytes, PNOR_OP_WRITE);
}

int hservice_i2c_read(uint64_t i_master, uint16_t i_devAddr,
		uint32_t i_offsetSize, uint32_t i_offset,
		uint32_t i_length, void* o_data)
{
	uint32_t chip_id;
	uint8_t engine, port;

	chip_id = (i_master & HBRT_I2C_MASTER_CHIP_MASK) >>
		HBRT_I2C_MASTER_CHIP_SHIFT;
	engine = (i_master & HBRT_I2C_MASTER_ENGINE_MASK) >>
		HBRT_I2C_MASTER_ENGINE_SHIFT;
	port = (i_master & HBRT_I2C_MASTER_PORT_MASK) >>
		HBRT_I2C_MASTER_PORT_SHIFT;
	return i2c_read(chip_id, engine, port, i_devAddr, i_offsetSize,
			i_offset, i_length, o_data);
}

int hservice_i2c_write(uint64_t i_master, uint16_t i_devAddr,
		uint32_t i_offsetSize, uint32_t i_offset,
		uint32_t i_length, void* i_data)
{
	uint32_t chip_id;
	uint8_t engine, port;

	chip_id = (i_master & HBRT_I2C_MASTER_CHIP_MASK) >>
		HBRT_I2C_MASTER_CHIP_SHIFT;
	engine = (i_master & HBRT_I2C_MASTER_ENGINE_MASK) >>
		HBRT_I2C_MASTER_ENGINE_SHIFT;
	port = (i_master & HBRT_I2C_MASTER_PORT_MASK) >>
		HBRT_I2C_MASTER_PORT_SHIFT;
	return i2c_write(chip_id, engine, port, i_devAddr, i_offsetSize,
			 i_offset, i_length, i_data);
}

int hservice_wakeup(u32 core, u32 mode)
{
	struct opal_prd_msg msg;

	msg.hdr.type = OPAL_PRD_MSG_TYPE_CORE_SPECIAL_WAKEUP;
	msg.hdr.size = htobe16(sizeof(msg));
	msg.spl_wakeup.core = htobe32(core);
	msg.spl_wakeup.mode = htobe32(mode);

	if (write(ctx->fd, &msg, sizeof(msg)) != sizeof(msg)) {
		pr_log(LOG_ERR, "FW: Failed to send CORE_SPECIAL_WAKEUP msg %x : %m\n",
		       core);
		return -1;
	}

	return 0;
}

static void pnor_load_module(struct opal_prd_ctx *ctx)
{
	insert_module("powernv_flash");
}

static void ipmi_init(struct opal_prd_ctx *ctx)
{
	insert_module("ipmi_devintf");
}

static int ipmi_send(int fd, uint8_t netfn, uint8_t cmd, long seq,
		uint8_t *buf, size_t len)
{
	struct ipmi_system_interface_addr addr;
	struct ipmi_req req;
	int rc;

	memset(&addr, 0, sizeof(addr));
	addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	addr.channel = IPMI_BMC_CHANNEL;

	memset(&req, 0, sizeof(req));
	req.addr = (unsigned char *)&addr;
	req.addr_len = sizeof(addr);

	req.msgid = seq;
	req.msg.netfn = netfn;
	req.msg.cmd = cmd;
	req.msg.data = buf;
	req.msg.data_len = len;

	rc = ioctl(fd, IPMICTL_SEND_COMMAND, &req);
	if (rc < 0)
		return -1;

	return 0;
}

static int ipmi_recv(int fd, uint8_t *netfn, uint8_t *cmd, long *seq,
		uint8_t *buf, size_t *len)
{
	struct ipmi_recv recv;
	struct ipmi_addr addr;
	int rc;

	recv.addr = (unsigned char *)&addr;
	recv.addr_len = sizeof(addr);
	recv.msg.data = buf;
	recv.msg.data_len = *len;

	rc = ioctl(fd, IPMICTL_RECEIVE_MSG_TRUNC, &recv);
	if (rc < 0 && errno != EMSGSIZE) {
		pr_log(LOG_WARNING, "IPMI: recv (%zd bytes) failed: %m", *len);
		return -1;
	} else if (rc < 0 && errno == EMSGSIZE) {
		pr_log(LOG_NOTICE, "IPMI: truncated message (netfn %d, cmd %d, "
				"size %zd), continuing anyway",
				recv.msg.netfn, recv.msg.cmd, *len);
	}

	*netfn = recv.msg.netfn;
	*cmd = recv.msg.cmd;
	*seq = recv.msgid;
	*len = recv.msg.data_len;

	return 0;
}

int hservice_ipmi_msg(uint8_t netfn, uint8_t cmd,
		void *tx_buf, size_t tx_size,
		void *rx_buf, size_t *rx_size)
{
	struct timeval start, now, delta;
	struct pollfd pollfds[1];
	static long seq;
	size_t size;
	int rc, fd;

	size = be64toh(*rx_size);

	fd = open(ipmi_devnode, O_RDWR);
	if (fd < 0) {
		pr_log(LOG_WARNING, "IPMI: Failed to open IPMI device %s: %m",
				ipmi_devnode);
		return -1;
	}

	seq++;
	pr_debug("IPMI: sending %zd bytes (netfn 0x%02x, cmd 0x%02x)",
			tx_size, netfn, cmd);

	rc = ipmi_send(fd, netfn, cmd, seq, tx_buf, tx_size);
	if (rc) {
		pr_log(LOG_WARNING, "IPMI: send failed");
		goto out;
	}

	gettimeofday(&start, NULL);

	pollfds[0].fd = fd;
	pollfds[0].events = POLLIN;

	for (;;) {
		long rx_seq;
		int timeout;

		gettimeofday(&now, NULL);
		timersub(&now, &start, &delta);
		timeout = ipmi_timeout_ms - ((delta.tv_sec * 1000) +
				(delta.tv_usec / 1000));
		if (timeout < 0)
			timeout = 0;

		rc = poll(pollfds, 1, timeout);
		if (rc < 0) {
			pr_log(LOG_ERR, "IPMI: poll(%s) failed: %m",
					ipmi_devnode);
			break;
		}

		if (rc == 0) {
			pr_log(LOG_WARNING, "IPMI: response timeout (>%dms)",
					ipmi_timeout_ms);
			rc = -1;
			break;
		}

		rc = ipmi_recv(fd, &netfn, &cmd, &rx_seq, rx_buf, &size);
		if (rc)
			break;

		if (seq != rx_seq) {
			pr_log(LOG_NOTICE, "IPMI: out-of-sequence reply: %ld, "
					"expected %ld. Dropping message.",
					rx_seq, seq);
			continue;
		}

		pr_debug("IPMI: received %zd bytes", tx_size);
		*rx_size = be64toh(size);
		rc = 0;
		break;
	}

out:
	close(fd);
	return rc;
}

static int memory_error_worker(const char *sysfsfile, const char *type,
			       uint64_t i_start_addr, uint64_t i_endAddr)
{
	int memfd, rc, n, ret = 0;
	char buf[ADDR_STRING_SZ];
	uint64_t addr;

	memfd = open(sysfsfile, O_WRONLY);
	if (memfd < 0) {
		pr_log(LOG_CRIT, "MEM: Failed to offline memory! "
				"Unable to open sysfs node %s: %m", sysfsfile);
		return -1;
	}

	for (addr = i_start_addr; addr <= i_endAddr; addr += ctx->page_size) {
		n = snprintf(buf, ADDR_STRING_SZ, "0x%lx", addr);
		rc = write(memfd, buf, n);
		if (rc != n) {
			pr_log(LOG_CRIT, "MEM: Failed to offline memory! "
					"page addr: %016lx type: %s: %m",
				addr, type);
			ret = 1;
		}
	}
	pr_log(LOG_CRIT, "MEM: Offlined %016lx,%016lx, type %s: %m\n",
			i_start_addr, addr, type);

	close(memfd);
	return ret;
}

int hservice_memory_error(uint64_t i_start_addr, uint64_t i_endAddr,
		enum MemoryError_t i_errorType)
{
	const char *sysfsfile, *typestr;
	pid_t pid;

	switch(i_errorType) {
	case MEMORY_ERROR_CE:
		sysfsfile = mem_offline_soft;
		typestr = "correctable";
		break;
	case MEMORY_ERROR_UE:
		sysfsfile = mem_offline_hard;
		typestr = "uncorrectable";
		break;
	default:
		pr_log(LOG_WARNING, "MEM: Invalid memory error type %d",
				i_errorType);
		return -1;
	}

	pr_log(LOG_ERR, "MEM: Memory error: range %016lx-%016lx, type: %s",
			i_start_addr, i_endAddr, typestr);

	/*
	 * HBRT expects the memory offlining process to happen in the background
	 * after the notification is delivered.
	 */
	pid = fork();
	if (pid > 0)
		exit(memory_error_worker(sysfsfile, typestr, i_start_addr, i_endAddr));

	if (pid < 0) {
		perror("MEM: unable to fork worker to offline memory!\n");
		return -1;
	}

	pr_log(LOG_INFO, "MEM: forked off %d to handle mem error\n", pid);
	return 0;
}

uint64_t hservice_get_interface_capabilities(uint64_t set)
{
	if (set == HBRT_CAPS_SET1_OPAL)
		return HBRT_CAPS_OPAL_HAS_XSCOM_RC ||
			HBRT_CAPS_OPAL_HAS_WAKEUP_SUPPORT;

	return 0;
}

uint64_t hservice_firmware_request(uint64_t req_len, void *req,
		uint64_t *resp_lenp, void *resp)
{
	struct opal_prd_msg *msg = ctx->msg;
	uint64_t resp_len;
	size_t size;
	int rc, n;

	resp_len = be64_to_cpu(*resp_lenp);

	pr_log(LOG_DEBUG,
			"HBRT: firmware request: %lu bytes req, %lu bytes resp",
			req_len, resp_len);

	/* sanity check for potential overflows */
	if (req_len > 0xffff || resp_len > 0xffff)
		return -1;

	size = sizeof(msg->hdr) + sizeof(msg->token) +
		sizeof(msg->fw_req) + req_len;

	/* we need the entire message to fit within the 2-byte size field */
	if (size > 0xffff)
		return -1;

	/* variable sized message, so we may need to expand our buffer */
	if (size > ctx->msg_alloc_len) {
		msg = realloc(ctx->msg, size);
		if (!msg) {
			pr_log(LOG_ERR,
				"FW: failed to expand message buffer: %m");
			return -1;
		}
		ctx->msg = msg;
		ctx->msg_alloc_len = size;
	}

	memset(msg, 0, size);

	/* construct request message... */
	msg->hdr.type = OPAL_PRD_MSG_TYPE_FIRMWARE_REQUEST;
	msg->hdr.size = htobe16(size);
	msg->fw_req.req_len = htobe64(req_len);
	msg->fw_req.resp_len = htobe64(resp_len);
	memcpy(msg->fw_req.data, req, req_len);

	hexdump((void *)msg, size);

	/* ... and send to firmware */
	rc = write(ctx->fd, msg, size);
	if (rc != size) {
		pr_log(LOG_WARNING,
			"FW: Failed to send FIRMWARE_REQUEST message: %m");
		return -1;
	}

	/* We have an "inner" poll loop here, as we want to ensure that the
	 * next entry into HBRT is the return from this function. So, only
	 * read from the prd fd, and queue anything that isn't a response
	 * to this request
	 */
	n = 0;
	for (;;) {
		struct prd_msgq_item *item;

		rc = read_prd_msg(ctx);
		if (rc)
			return -1;

		msg = ctx->msg;
		if (msg->hdr.type == OPAL_PRD_MSG_TYPE_FIRMWARE_RESPONSE) {
			size = be64toh(msg->fw_resp.len);
			if (size > resp_len)
				return -1;

			/* success! a valid response that fits into HBRT's
			 * resp buffer */
			memcpy(resp, msg->fw_resp.data, size);
			*resp_lenp = htobe64(size);
			return 0;
		}

		/* not a response? queue up for later consumption */
		if (++n > max_msgq_len) {
			pr_log(LOG_ERR,
				"FW: too many messages queued (%d) while "
				"waiting for FIRMWARE_RESPONSE", n);
			return -1;
		}
		size = be16toh(msg->hdr.size);
		item = malloc(sizeof(*item) + size);
		memcpy(&item->msg, msg, size);
		list_add_tail(&ctx->msgq, &item->list);
	}
}

int hservices_init(struct opal_prd_ctx *ctx, void *code)
{
	uint64_t *s, *d;
	int i, sz;

	pr_debug("IMAGE: code address: %p", code);

	/* We enter at 0x100 into the image. */
	/* Load func desc in BE since we reverse it in thunk */

	hbrt_entry.addr = (void *)htobe64((unsigned long)code + 0x100);
	hbrt_entry.toc = 0; /* No toc for init entry point */

	if (memcmp(code, "HBRTVERS", 8) != 0) {
		pr_log(LOG_ERR, "IMAGE: Bad signature for "
				"ibm,hbrt-code-image! exiting");
		return -1;
	}

	pr_debug("IMAGE: calling ibm,hbrt_init()");
	hservice_runtime = call_hbrt_init(&hinterface);
	if (!hservice_runtime) {
		pr_log(LOG_ERR, "IMAGE: hbrt_init failed, exiting");
		return -1;
	}

	pr_log(LOG_NOTICE, "IMAGE: hbrt_init complete, version %016lx",
			hservice_runtime->interface_version);

	sz = sizeof(struct runtime_interfaces)/sizeof(uint64_t);
	s = (uint64_t *)hservice_runtime;
	d = (uint64_t *)&hservice_runtime_fixed;
	/* Byte swap the function pointers */
	for (i = 0; i < sz; i++)
		d[i] = be64toh(s[i]);

	return 0;
}

static void fixup_hinterface_table(void)
{
	uint64_t *t64;
	unsigned int i, sz;

	/* Swap interface version */
	hinterface.interface_version =
		htobe64(hinterface.interface_version);

	/* Swap OPDs */
	sz = sizeof(struct host_interfaces) / sizeof(uint64_t);
	t64 = (uint64_t *)&hinterface;
	for (i = 1; i < sz; i++) {
		uint64_t *opd = (uint64_t *)t64[i];
		if (!opd)
			continue;
		t64[i] = htobe64(t64[i]);
		opd[0] = htobe64(opd[0]);
		opd[1] = htobe64(opd[1]);
		opd[2] = htobe64(opd[2]);
	}
}

static int map_hbrt_file(struct opal_prd_ctx *ctx, const char *name)
{
	struct stat statbuf;
	int fd, rc;
	void *buf;

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		pr_log(LOG_ERR, "IMAGE: HBRT file open(%s) failed: %m", name);
		return -1;
	}

	rc = fstat(fd, &statbuf);
	if (rc < 0) {
		pr_log(LOG_ERR, "IMAGE: HBRT file fstat(%s) failed: %m", name);
		close(fd);
		return -1;
	}

	buf = mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE, fd, 0);
	close(fd);

	if (buf == MAP_FAILED) {
		pr_log(LOG_ERR, "IMAGE: HBRT file mmap(%s, 0x%zx) failed: %m",
				name, statbuf.st_size);
		return -1;
	}

	ctx->code_addr = buf;
	ctx->code_size = statbuf.st_size;
	return -0;
}

static int map_hbrt_physmem(struct opal_prd_ctx *ctx, const char *name)
{
	struct prd_range *range;
	int rc;
	void *buf;
	void *ro_buf;

	range = find_range(name, 0);
	if (!range) {
		pr_log(LOG_ERR, "IMAGE: can't find code region %s", name);
		return -1;
	}

	ro_buf = mmap(NULL, range->size, PROT_READ,
			MAP_PRIVATE, ctx->fd, range->physaddr);
	if (ro_buf == MAP_FAILED) {
		pr_log(LOG_ERR, "IMAGE: mmap(range:%s, "
				"phys:0x%016lx, size:0x%016lx) failed: %m",
				name, range->physaddr, range->size);
		return -1;
	}

	buf = mmap(NULL, range->size, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1 , 0);
	if (buf == MAP_FAILED) {
		pr_log(LOG_ERR, "IMAGE: anon mmap(size:0x%016lx) failed: %m",
				range->size);
		return -1;
	}

	memcpy(buf, ro_buf, range->size);

	rc = munmap(ro_buf, range->size);
	if (rc < 0) {
		pr_log(LOG_ERR, "IMAGE: munmap("
				"phys:0x%016lx, size:0x%016lx) failed: %m",
				range->physaddr, range->size);
		return -1;
	}

	/*
	 * FIXME: We shouldn't be mapping the memory as RWX, but HBRT appears to
	 * require the ability to write into the image at runtime.
	 */
	rc = mprotect(buf, range->size, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (rc < 0) {
		pr_log(LOG_ERR, "IMAGE: mprotect(phys:%p, "
			"size:0x%016lx, rwx) failed: %m",
			buf, range->size);
		return -1;
	}

	ctx->code_addr = buf;
	ctx->code_size = range->size;
	return 0;
}

static void dump_hbrt_map(struct opal_prd_ctx *ctx)
{
	const char *dump_name = "hbrt.bin";
	int fd, rc;

	if (!ctx->debug)
		return;

	fd = open(dump_name, O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		pr_log(LOG_NOTICE, "IMAGE: couldn't debug image %s for writing",
				dump_name);
		return;
	}

	rc = ftruncate(fd, 0);
	if (rc < 0) {
		pr_log(LOG_NOTICE, "IMAGE: couldn't truncate image %s for writing",
				dump_name);
		return;
	}
	rc = write(fd, ctx->code_addr, ctx->code_size);
	close(fd);

	if (rc != ctx->code_size)
		pr_log(LOG_NOTICE, "IMAGE: write to %s failed: %m", dump_name);
	else
		pr_debug("IMAGE: dumped HBRT binary to %s", dump_name);
}

static int open_and_read(const char *path, void **bufp, int *lenp)
{
	struct stat statbuf;
	int fd, rc, bytes;
	void *buf;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	rc = fstat(fd, &statbuf);
	if (rc) {
		close(fd);
		return -1;
	}

	buf = malloc(statbuf.st_size);
	if (!buf) {
		close(fd);
		return -1;
	}

	for (rc = bytes = 0; bytes < statbuf.st_size; bytes += rc) {
		rc = read(fd, buf + bytes, statbuf.st_size - bytes);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			break;
		} else if (rc == 0)
			break;
	}

	if (bytes == statbuf.st_size)
		rc = 0;

	if (rc == 0) {
		if (lenp)
			*lenp = bytes;
		if (bufp)
			*bufp = buf;
	} else {
		free(buf);
	}

	close(fd);

	return rc == 0 ? 0 : -1;
}

static int prd_init_one_range(struct opal_prd_ctx *ctx, const char *path,
		struct dirent *dirent)
{
	char *label_path, *reg_path, *instance_path;
	struct prd_range *range;
	int label_len, len, rc;
	__be64 *reg;
	char *label;
	void *buf;

	rc = asprintf(&label_path, "%s/%s/ibm,prd-label", path, dirent->d_name);
	if (rc < 0) {
		pr_log(LOG_ERR, "FW: error creating 'ibm,prd-label' path "
				"node: %m");
		return -1;
	}
	rc = asprintf(&instance_path, "%s/%s/ibm,prd-instance",
			path, dirent->d_name);
	if (rc < 0) {
		pr_log(LOG_ERR, "FW: error creating 'ibm,prd-instance' path "
				"node: %m");
		return -1;
	}
	rc = asprintf(&reg_path, "%s/%s/reg", path, dirent->d_name);
	if (rc < 0) {
		pr_log(LOG_ERR, "FW: error creating 'reg' path "
				" node: %m");
		return -1;
	}

	reg = NULL;
	label = NULL;
	rc = -1;

	rc = open_and_read(label_path, &buf, &label_len);
	if (rc)
		goto out_free;

	label = buf;

	if (label[label_len-1] != '\0')
		pr_log(LOG_INFO, "FW: node %s has invalid ibm,prd-label - "
				"not nul-terminated",
				dirent->d_name);

	rc = open_and_read(reg_path, &buf, &len);
	if (rc)
		goto out_free;

	reg = buf;

	if (len != 2 * sizeof(*reg)) {
		pr_log(LOG_ERR, "FW: node %s has invalid 'reg' size: %d",
				dirent->d_name, len);
		goto out_free;
	}


	ctx->ranges = realloc(ctx->ranges, ++ctx->n_ranges * sizeof(*range));
	range = &ctx->ranges[ctx->n_ranges - 1];
	range->name = strndup(label, label_len);
	range->physaddr = be64toh(reg[0]);
	range->size = be64toh(reg[1]);
	range->buf = NULL;
	range->multiple = false;
	range->instance = 0;

	/* optional instance */
	rc = open_and_read(instance_path, &buf, &len);
	if (!rc && len == sizeof(uint32_t)) {
		range->multiple = true;
		range->instance = be32toh(*(uint32_t *)buf);
		ctx->fw_range_instances = true;
	}
	rc = 0;

out_free:
	free(reg);
	free(label);
	free(instance_path);
	free(reg_path);
	free(label_path);
	return rc;
}

static int compare_ranges(const void *ap, const void *bp)
{
	const struct prd_range *a = ap, *b = bp;
	int rc;

	rc = strcmp(a->name, b->name);
	if (rc)
		return rc;

	if (a->physaddr < b->physaddr)
		return -1;
	else if (a->physaddr > b->physaddr)
		return 1;

	return 0;
}

static void assign_range_instances(struct opal_prd_ctx *ctx)
{
	int i;

	if (!ctx->n_ranges)
		return;

	ctx->ranges[0].multiple = false;
	ctx->ranges[0].instance = 0;

	for (i = 1; i < ctx->n_ranges; i++) {
		struct prd_range *cur, *prev;

		cur = &ctx->ranges[i];
		prev = &ctx->ranges[i-1];

		if (!strcmp(cur->name, prev->name)) {
			prev->multiple = true;
			cur->multiple = true;
			cur->instance = prev->instance + 1;
		} else {
			cur->multiple = false;
			cur->instance = 0;
		}
	}
}

static void print_ranges(struct opal_prd_ctx *ctx)
{
	int i;

	if (ctx->n_ranges == 0)
		pr_log(LOG_INFO, "FW: No PRD ranges");

	pr_log(LOG_DEBUG, "FW: %d PRD ranges, instances assigned by %s",
			ctx->n_ranges,
			ctx->fw_range_instances ? "firmware" : "userspace");

	for (i = 0; i < ctx->n_ranges; i++) {
		struct prd_range *range = &ctx->ranges[i];
		char instance_str[20];

		if (range->multiple)
			snprintf(instance_str, sizeof(instance_str),
					" [%d]", range->instance);
		else
			instance_str[0] = '\0';

		pr_log(LOG_DEBUG, "FW:  %016lx-%016lx %s%s", range->physaddr,
				range->physaddr + range->size - 1,
				range->name,
				instance_str);
	}
}

static int chip_init(void)
{
	struct dirent *dirent;
	char *path;
	DIR *dir;
	__be32 *chipid;
	void *buf;
	int rc, len, i;

	dir = opendir(devicetree_base);
	if (!dir) {
		pr_log(LOG_ERR, "FW: Can't open %s", devicetree_base);
		return  -1;
	}

	for (;;) {
		dirent = readdir(dir);
		if (!dirent)
			break;

		if (strncmp("xscom", dirent->d_name, 5))
			continue;

		rc = asprintf(&path, "%s/%s/ibm,chip-id", devicetree_base,
			      dirent->d_name);
		if (rc < 0) {
			pr_log(LOG_ERR, "FW: Failed to create chip-id path");
			return -1;
		}

		rc = open_and_read(path, &buf, &len);
		if (rc) {
			pr_log(LOG_ERR, "FW; Failed to read chipid");
			return -1;
		}
		chipid = buf;
		chips[nr_chips++] = be32toh(*chipid);
	}

	pr_log(LOG_DEBUG, "FW: Chip init");
	for (i = 0; i < nr_chips; i++)
		pr_log(LOG_DEBUG, "FW: Chip 0x%lx", chips[i]);

	return 0;
}

static int prd_init_ranges(struct opal_prd_ctx *ctx)
{
	struct dirent *dirent;
	char *path;
	DIR *dir;
	int rc;

	rc = asprintf(&path, "%s/reserved-memory", devicetree_base);
	if (rc < 0) {
		pr_log(LOG_ERR, "FW: error creating 'reserved-memory' path "
				"node: %m");
		return -1;
	}

	rc = -1;

	dir = opendir(path);
	if (!dir) {
		pr_log(LOG_ERR, "FW: can't open reserved-memory device-tree "
				"node: %m");
		goto out_free;
	}

	for (;;) {
		dirent = readdir(dir);
		if (!dirent)
			break;

		prd_init_one_range(ctx, path, dirent);
	}

	rc = 0;
	/* sort ranges and assign instance numbers for duplicates (if the
	 * firmware doesn't number instances for us) */
	qsort(ctx->ranges, ctx->n_ranges, sizeof(struct prd_range),
			compare_ranges);

	if (!ctx->fw_range_instances)
		assign_range_instances(ctx);

	print_ranges(ctx);

out_free:
	free(path);
	closedir(dir);
	return rc;
}

bool find_string(const char *buffer, size_t len, const char *s)
{
	const char *c, *end;

	if (!buffer)
		return false;
	c = buffer;
	end = c + len;

	while (c < end) {
		if (!strcasecmp(s, c))
			return true;
		c += strlen(c) + 1;
	}
	return false;
}

static int is_prd_supported(void)
{
	char *path;
	int rc;
	int len;
	char *buf;

	rc = asprintf(&path, "%s/ibm,opal/diagnostics/compatible",
		      devicetree_base);
	if (rc < 0) {
		pr_log(LOG_ERR, "FW: error creating 'compatible' node path: %m");
		return -1;
	}

	rc = open_and_read(path, (void *) &buf, &len);
	if (rc)
		goto out_free;

	if (buf[len - 1] != '\0')
		pr_log(LOG_INFO, "FW: node %s is not nul-terminated", path);

	rc = find_string(buf, len, "ibm,opal-prd") ? 0 : -1;

	free(buf);
out_free:
	free(path);
	return rc;
}

static int prd_init(struct opal_prd_ctx *ctx)
{
	int rc;

	ctx->page_size = sysconf(_SC_PAGE_SIZE);

	/* set up the device, and do our get_info ioctl */
	ctx->fd = open(opal_prd_devnode, O_RDWR);
	if (ctx->fd < 0) {
		pr_log(LOG_ERR, "FW: Can't open PRD device %s: %m",
				opal_prd_devnode);
		return -1;
	}

	rc = ioctl(ctx->fd, OPAL_PRD_GET_INFO, &ctx->info);
	if (rc) {
		pr_log(LOG_ERR, "FW: Can't query PRD information: %m");
		return -1;
	}

	rc = prd_init_ranges(ctx);
	if (rc) {
		pr_log(LOG_ERR, "FW: can't parse PRD memory information");
		return -1;
	}

	rc = chip_init();
	if (rc)
		pr_log(LOG_ERR, "FW: Failed to initialize chip IDs");

	return 0;
}

static int handle_msg_attn(struct opal_prd_ctx *ctx, struct opal_prd_msg *msg)
{
	uint64_t proc, ipoll_mask, ipoll_status;
	int rc;

	proc = be64toh(msg->attn.proc);
	ipoll_status = be64toh(msg->attn.ipoll_status);
	ipoll_mask = be64toh(msg->attn.ipoll_mask);

	if (!hservice_runtime->handle_attns) {
		pr_log_nocall("handle_attns");
		return -1;
	}

	rc = call_handle_attns(proc, ipoll_status, ipoll_mask);
	if (rc) {
		pr_log(LOG_ERR, "HBRT: handle_attns(%lx,%lx,%lx) failed, rc %d",
				proc, ipoll_status, ipoll_mask, rc);
		return -1;
	}

	/* send the response */
	msg->hdr.type = OPAL_PRD_MSG_TYPE_ATTN_ACK;
	msg->hdr.size = htobe16(sizeof(*msg));
	msg->attn_ack.proc = htobe64(proc);
	msg->attn_ack.ipoll_ack = htobe64(ipoll_status);
	rc = write(ctx->fd, msg, sizeof(*msg));

	if (rc != sizeof(*msg)) {
		pr_log(LOG_WARNING, "FW: Failed to send ATTN_ACK message: %m");
		return -1;
	}

	return 0;
}

static int handle_msg_occ_error(struct opal_prd_ctx *ctx,
		struct opal_prd_msg *msg)
{
	uint32_t proc;

	proc = be64toh(msg->occ_error.chip);

	pr_debug("FW: firmware signaled OCC error for proc 0x%x", proc);

	if (!hservice_runtime->process_occ_error) {
		pr_log_nocall("process_occ_error");
		return -1;
	}

	call_process_occ_error(proc);
	return 0;
}

static int pm_complex_load_start(void)
{
	struct prd_range *range;
	u64 homer, occ_common;
	int rc = -1, i;

	if (!hservice_runtime->load_pm_complex) {
		pr_log_nocall("load_pm_complex");
		return rc;
	}

	if (!hservice_runtime->start_pm_complex) {
		pr_log_nocall("start_pm_complex");
		return rc;
	}

	range = find_range("ibm,occ-common-area", 0);
	if (!range) {
		range = find_range("occ-common-area", 0);
		if (!range) {
			pr_log(LOG_ERR, "PM: occ-common-area not found");
			return rc;
		}
	}
	occ_common = range->physaddr;

	for (i = 0; i < nr_chips; i++) {
		range = find_range("ibm,homer-image", chips[i]);
		if (!range) {
			range = find_range("homer-image", chips[i]);
			if (!range) {
				pr_log(LOG_ERR, "PM: homer-image not found 0x%lx",
				       chips[i]);
				return -1;
			}
		}
		homer = range->physaddr;

		pr_debug("PM: calling load_pm_complex(0x%lx, 0x%lx, 0x%lx, LOAD)",
			 chips[i], homer, occ_common);
		rc = call_load_pm_complex(chips[i], homer, occ_common, 0);
		if (rc) {
			pr_log(LOG_ERR, "PM: Failed load_pm_complex(0x%lx) %m",
			       chips[i]);
			return rc;
		}
	}

	for (i = 0; i < nr_chips; i++) {
		pr_debug("PM: calling start_pm_complex(0x%lx)", chips[i]);
		rc = call_start_pm_complex(chips[i]);
		if (rc) {
			pr_log(LOG_ERR, "PM: Failed start_pm_complex(0x%lx): %m",
			       chips[i]);
			return rc;
		}
	}

	return rc;
}

static int pm_complex_reset(uint64_t chip)
{
	int rc;

	/*
	 * FSP system -> reset_pm_complex
	 * BMC system -> process_occ_reset
	 */
	if (is_fsp_system()) {
		int i;

		if (!hservice_runtime->reset_pm_complex) {
			pr_log_nocall("reset_pm_complex");
			return -1;
		}

		for (i = 0; i < nr_chips; i++) {
			pr_debug("PM: calling pm_complex_reset(%ld)", chips[i]);
			rc = call_reset_pm_complex(chip);
			if (rc) {
				pr_log(LOG_ERR, "PM: Failed pm_complex_reset(%ld): %m",
				       chips[i]);
				return rc;
			}
		}

		rc = pm_complex_load_start();
	} else {
		if (!hservice_runtime->process_occ_reset) {
			pr_log_nocall("process_occ_reset");
			return -1;
		}

		pr_debug("PM: calling process_occ_reset(%ld)", chip);
		call_process_occ_reset(chip);
		rc = 0;
	}

	return rc;
}

static int handle_msg_occ_reset(struct opal_prd_ctx *ctx,
		struct opal_prd_msg *msg)
{
	uint32_t proc;
	int rc;

	proc = be64toh(msg->occ_reset.chip);

	pr_debug("FW: firmware requested OCC reset for proc 0x%x", proc);

	rc = pm_complex_reset(proc);

	return rc;
}

static int handle_msg_firmware_notify(struct opal_prd_ctx *ctx,
		struct opal_prd_msg *msg)
{
	uint64_t len;
	void *buf;

	len = be64toh(msg->fw_notify.len);
	buf = msg->fw_notify.data;

	pr_debug("FW: firmware notification, %ld bytes", len);

	if (!hservice_runtime->firmware_notify) {
		pr_log_nocall("firmware_notify");
		return -1;
	}

	call_firmware_notify(len, buf);

	return 0;
}

static int handle_msg_sbe_passthrough(struct opal_prd_ctx *ctx,
				      struct opal_prd_msg *msg)
{
	uint32_t proc;
	int rc;

	proc = be64toh(msg->sbe_passthrough.chip);

	pr_debug("FW: firmware sent SBE pass through command for proc 0x%x\n",
		 proc);

	if (!hservice_runtime->sbe_message_passing) {
		pr_log_nocall("sbe_message_passing");
		return -1;
	}

	rc = call_sbe_message_passing(proc);
	return rc;
}

static int handle_msg_fsp_occ_reset(struct opal_prd_msg *msg)
{
	struct opal_prd_msg omsg;
	int rc = -1, i;

	pr_debug("FW: FSP requested OCC reset");

	if (!hservice_runtime->reset_pm_complex) {
		pr_log_nocall("reset_pm_complex");
		return rc;
	}

	for (i = 0; i < nr_chips; i++) {
		pr_debug("PM: calling pm_complex_reset(0x%lx)", chips[i]);
		rc = call_reset_pm_complex(chips[i]);
		if (rc) {
			pr_log(LOG_ERR, "PM: Failed pm_complex_reset(0x%lx) %m",
			       chips[i]);
			break;
		}
	}

	omsg.hdr.type = OPAL_PRD_MSG_TYPE_FSP_OCC_RESET_STATUS;
	omsg.hdr.size = htobe16(sizeof(omsg));
	omsg.fsp_occ_reset_status.chip = msg->occ_reset.chip;
	omsg.fsp_occ_reset_status.status = htobe64(rc);

	if (write(ctx->fd, &omsg, sizeof(omsg)) != sizeof(omsg)) {
		pr_log(LOG_ERR, "FW: Failed to send FSP_OCC_RESET_STATUS msg: %m");
		return -1;
	}

	return rc;
}

static int handle_msg_fsp_occ_load_start(struct opal_prd_msg *msg)
{
	struct opal_prd_msg omsg;
	int rc;

	pr_debug("FW: FSP requested OCC load/start");
	rc = pm_complex_load_start();

	omsg.hdr.type = OPAL_PRD_MSG_TYPE_FSP_OCC_LOAD_START_STATUS;
	omsg.hdr.size = htobe16(sizeof(omsg));
	omsg.fsp_occ_reset_status.chip = msg->occ_reset.chip;
	omsg.fsp_occ_reset_status.status = htobe64(rc);

	if (write(ctx->fd, &omsg, sizeof(omsg)) != sizeof(omsg)) {
		pr_log(LOG_ERR, "FW: Failed to send FSP_OCC_LOAD_START_STATUS msg: %m");
		return -1;
	}

	return rc;
}

static int handle_prd_msg(struct opal_prd_ctx *ctx, struct opal_prd_msg *msg)
{
	int rc = -1;

	switch (msg->hdr.type) {
	case OPAL_PRD_MSG_TYPE_ATTN:
		rc = handle_msg_attn(ctx, msg);
		break;
	case OPAL_PRD_MSG_TYPE_OCC_RESET:
		rc = handle_msg_occ_reset(ctx, msg);
		break;
	case OPAL_PRD_MSG_TYPE_OCC_ERROR:
		rc = handle_msg_occ_error(ctx, msg);
		break;
	case OPAL_PRD_MSG_TYPE_FIRMWARE_NOTIFY:
		rc = handle_msg_firmware_notify(ctx, msg);
		break;
	case OPAL_PRD_MSG_TYPE_SBE_PASSTHROUGH:
		rc = handle_msg_sbe_passthrough(ctx, msg);
		break;
	case OPAL_PRD_MSG_TYPE_FSP_OCC_RESET:
		rc = handle_msg_fsp_occ_reset(msg);
		break;
	case OPAL_PRD_MSG_TYPE_FSP_OCC_LOAD_START:
		rc = handle_msg_fsp_occ_load_start(msg);
		break;
	default:
		pr_log(LOG_WARNING, "Invalid incoming message type 0x%x",
				msg->hdr.type);
	}

	return rc;
}

#define list_for_each_pop(h, i, type, member) \
	for (i = list_pop((h), type, member); \
		i; \
		i = list_pop((h), type, member))


static int process_msgq(struct opal_prd_ctx *ctx)
{
	struct prd_msgq_item *item;

	list_for_each_pop(&ctx->msgq, item, struct prd_msgq_item, list) {
		handle_prd_msg(ctx, &item->msg);
		free(item);
	}

	return 0;
}

static int read_prd_msg(struct opal_prd_ctx *ctx)
{
	struct opal_prd_msg *msg;
	int size;
	int rc;

	msg = ctx->msg;

	rc = read(ctx->fd, msg, ctx->msg_alloc_len);
	if (rc < 0 && errno == EAGAIN)
		return -1;

	/* we need at least enough for the message header... */
	if (rc < 0) {
		pr_log(LOG_WARNING, "FW: error reading from firmware: %m");
		return -1;
	}

	if (rc < sizeof(msg->hdr)) {
		pr_log(LOG_WARNING, "FW: short message read from firmware");
		return -1;
	}

	/* ... and for the reported message size to be sane */
	size = htobe16(msg->hdr.size);
	if (size < sizeof(msg->hdr)) {
		pr_log(LOG_ERR, "FW: Mismatched message size "
				"between opal-prd and firmware "
				"(%d from FW, %zd expected)",
				size, sizeof(msg->hdr));
		return -1;
	}

	/* expand our message buffer if necessary... */
	if (size > ctx->msg_alloc_len) {
		msg = realloc(ctx->msg, size);
		if (!msg) {
			pr_log(LOG_ERR,
				"FW: Can't expand PRD message buffer: %m");
			return -1;
		}
		ctx->msg = msg;
		ctx->msg_alloc_len = size;
	}

	/* ... and complete the read */
	if (size > rc) {
		size_t pos;

		for (pos = rc; pos < size;) {
			rc = read(ctx->fd, msg + pos, size - pos);

			if (rc < 0 && errno == EAGAIN)
				continue;

			if (rc <= 0) {
				pr_log(LOG_WARNING,
					"FW: error reading from firmware: %m");
				return -1;
			}

			pos += rc;
		}
	}

	return 0;
}

static void handle_prd_control_occ_error(struct control_msg *send_msg,
		struct control_msg *recv_msg)
{
	uint64_t chip;

	if (!hservice_runtime->process_occ_error) {
		pr_log_nocall("process_occ_error");
		return;
	}

	chip = recv_msg->occ_error.chip;

	pr_debug("CTRL: calling process_occ_error(%lu)", chip);
	call_process_occ_error(chip);

	send_msg->data_len = 0;
	send_msg->response = 0;
}

static void handle_prd_control_occ_reset(struct control_msg *send_msg,
		struct control_msg *msg)
{
	struct opal_prd_msg omsg;
	uint64_t chip;
	int rc;

	/* notify OPAL of the impending reset */
	memset(&omsg, 0, sizeof(omsg));
	omsg.hdr.type = OPAL_PRD_MSG_TYPE_OCC_RESET_NOTIFY;
	omsg.hdr.size = htobe16(sizeof(omsg));
	rc = write(ctx->fd, &omsg, sizeof(omsg));
	if (rc != sizeof(omsg))
		pr_log(LOG_WARNING, "FW: Failed to send OCC_RESET message: %m");

	chip = msg->occ_reset.chip;

	/* do reset */
	pr_debug("CTRL: Calling OCC reset on chip %ld", chip);
	pm_complex_reset(chip);

	send_msg->data_len = 0;
	send_msg->response = 0;
}

static void handle_prd_control_occ_actuation(struct control_msg *msg,
					     bool enable)
{
	if (!hservice_runtime->enable_occ_actuation) {
		pr_log_nocall("enable_occ_actuation");
		return;
	}

	pr_debug("CTRL: calling enable_occ_actuation(%s)",
			enable ? "true" : "false");
	msg->data_len = 0;
	msg->response = call_enable_occ_actuation(enable);
}

static void handle_prd_control_attr_override(struct control_msg *send_msg,
					     struct control_msg *recv_msg)
{
	if (!hservice_runtime->apply_attr_override) {
		pr_log_nocall("apply_attr_override");
		return;
	}

	pr_debug("CTRL: calling apply_attr_override");
	send_msg->response = call_apply_attr_override(
			recv_msg->data, recv_msg->data_len);
	send_msg->data_len = 0;
}

static void handle_prd_control_htmgt_passthru(struct control_msg *send_msg,
					      struct control_msg *recv_msg)
{
	uint16_t rsp_len;

	if (!hservice_runtime->mfg_htmgt_pass_thru) {
		pr_log_nocall("mfg_htmgt_pass_thru");
		return;
	}

	pr_debug("CTRL: calling mfg_htmgt_pass_thru");
	send_msg->response = call_mfg_htmgt_pass_thru(recv_msg->data_len,
						      recv_msg->data, &rsp_len,
						      send_msg->data);
	send_msg->data_len = be16toh(rsp_len);
	if (send_msg->data_len > MAX_CONTROL_MSG_BUF) {
		pr_log(LOG_ERR, "CTRL: response buffer overrun, data len: %d",
				send_msg->data_len);
		send_msg->data_len = MAX_CONTROL_MSG_BUF;
	}
}

static void handle_prd_control_run_cmd(struct control_msg *send_msg,
				       struct control_msg *recv_msg)
{
	char *runcmd_output, *s;
	const char **argv;
	int i, argc;
	size_t size;

	if (!hservice_runtime->run_command) {
		pr_log_nocall("run_command");
		return;
	}

	argc = recv_msg->run_cmd.argc;
	pr_debug("CTRL: run_command, argc:%d\n", argc);

	argv = malloc(argc * sizeof(*argv));
	if (!argv) {
		pr_log(LOG_ERR, "CTRL: argv buffer malloc failed: %m");
		return;
	}

	s = (char *)recv_msg->data;
	size = 0;
	for (i = 0; i < argc; i++) {
		argv[i] = (char *)htobe64((uint64_t)&s[size]);
		size += (strlen(&s[size]) + 1);
	}

	/* Call HBRT */
	send_msg->response = call_run_command(argc, argv, &runcmd_output);
	runcmd_output = (char *)be64toh((uint64_t)runcmd_output);
	free(argv);

	s = (char *)send_msg->data;
	if (runcmd_output) {
		size = strlen(runcmd_output);
		if (size >= MAX_CONTROL_MSG_BUF) {
			pr_log(LOG_WARNING, "CTRL: output message truncated");
			runcmd_output[MAX_CONTROL_MSG_BUF] = '\0';
			size = MAX_CONTROL_MSG_BUF;
		}

		strcpy(s, runcmd_output);
		send_msg->data_len = size + 1;
		free(runcmd_output);
	} else {
		strcpy(s, "Null");
		send_msg->data_len = strlen("Null") + 1;
	}
}

static void handle_prd_control(struct opal_prd_ctx *ctx, int fd)
{
	struct control_msg msg, *recv_msg, *send_msg;
	bool enabled = false;
	int rc, size;

	/* Default reply, in the error path */
	send_msg = &msg;

	/* Peek into the socket to ascertain the size of the available data */
	rc = recv(fd, &msg, sizeof(msg), MSG_PEEK);
	if (rc != sizeof(msg)) {
		pr_log(LOG_WARNING, "CTRL: failed to receive control "
				"message: %m");
		msg.response = -1;
		msg.data_len = 0;
		goto out_send;
	}

	size = sizeof(*recv_msg) + msg.data_len;

	/* Default reply, in the error path */
	msg.data_len = 0;
	msg.response = -1;

	recv_msg = malloc(size);
	if (!recv_msg) {
		pr_log(LOG_ERR, "CTRL: message buffer malloc failed: %m");
		goto out_send;
	}

	rc = recv(fd, recv_msg, size, MSG_TRUNC);
	if (rc != size) {
		pr_log(LOG_WARNING, "CTRL: failed to receive control "
				"message: %m");
		goto out_free_recv;
	}

	send_msg = malloc(sizeof(*send_msg) + MAX_CONTROL_MSG_BUF);
	if (!send_msg) {
		pr_log(LOG_ERR, "CTRL: message buffer malloc failed: %m");
		send_msg = &msg;
		goto out_free_recv;
	}

	send_msg->type = recv_msg->type;
	send_msg->response = -1;
	switch (recv_msg->type) {
	case CONTROL_MSG_ENABLE_OCCS:
		enabled = true;
		/* fall through */
	case CONTROL_MSG_DISABLE_OCCS:
		handle_prd_control_occ_actuation(send_msg, enabled);
		break;
	case CONTROL_MSG_TEMP_OCC_RESET:
		handle_prd_control_occ_reset(send_msg, recv_msg);
		break;
	case CONTROL_MSG_TEMP_OCC_ERROR:
		handle_prd_control_occ_error(send_msg, recv_msg);
		break;
	case CONTROL_MSG_ATTR_OVERRIDE:
		handle_prd_control_attr_override(send_msg, recv_msg);
		break;
	case CONTROL_MSG_HTMGT_PASSTHRU:
		handle_prd_control_htmgt_passthru(send_msg, recv_msg);
		break;
	case CONTROL_MSG_RUN_CMD:
		handle_prd_control_run_cmd(send_msg, recv_msg);
		break;
	default:
		pr_log(LOG_WARNING, "CTRL: Unknown control message action %d",
				recv_msg->type);
		send_msg->data_len = 0;
		break;
	}

out_free_recv:
	free(recv_msg);
out_send:
	size = sizeof(*send_msg) + send_msg->data_len;
	rc = send(fd, send_msg, size, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (rc && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EPIPE))
		pr_debug("CTRL: control send() returned %d, ignoring failure",
				rc);
	else if (rc != size)
		pr_log(LOG_NOTICE, "CTRL: Failed to send control response: %m");

	if (send_msg != &msg)
		free(send_msg);
}

static int run_attn_loop(struct opal_prd_ctx *ctx)
{
	struct pollfd pollfds[2];
	struct opal_prd_msg msg;
	int rc, fd;

	if (hservice_runtime->enable_attns) {
		pr_debug("HBRT: calling enable_attns");
		rc = call_enable_attns();
		if (rc) {
			pr_log(LOG_ERR, "HBRT: enable_attns() failed, "
					"aborting");
			return -1;
		}
	}

	if (hservice_runtime->get_ipoll_events) {
		pr_debug("HBRT: calling get_ipoll_events");
		opal_prd_ipoll = call_get_ipoll_events();
	}

	pr_debug("HBRT: enabling IPOLL events 0x%016lx", opal_prd_ipoll);

	/* send init message, to unmask interrupts */
	msg.hdr.type = OPAL_PRD_MSG_TYPE_INIT;
	msg.hdr.size = htobe16(sizeof(msg));
	msg.init.version = htobe64(opal_prd_version);
	msg.init.ipoll = htobe64(opal_prd_ipoll);

	pr_debug("FW: writing init message");
	rc = write(ctx->fd, &msg, sizeof(msg));
	if (rc != sizeof(msg)) {
		pr_log(LOG_ERR, "FW: Init message failed: %m. Aborting.");
		return -1;
	}

	pollfds[0].fd = ctx->fd;
	pollfds[0].events = POLLIN | POLLERR;
	pollfds[1].fd = ctx->socket;
	pollfds[1].events = POLLIN | POLLERR;

	for (;;) {
		/* run through any pending messages */
		process_msgq(ctx);

		rc = poll(pollfds, 2, -1);
		if (rc < 0) {
			pr_log(LOG_ERR, "FW: event poll failed: %m");
			exit(EXIT_FAILURE);
		}

		if (!rc)
			continue;

		if (pollfds[0].revents & POLLIN) {
			rc = read_prd_msg(ctx);
			if (!rc)
				handle_prd_msg(ctx, ctx->msg);
		}

		if (pollfds[1].revents & POLLIN) {
			fd = accept(ctx->socket, NULL, NULL);
			if (fd < 0) {
				pr_log(LOG_NOTICE, "CTRL: accept failed: %m");
				continue;
			}
			handle_prd_control(ctx, fd);
			close(fd);
		}
	}

	return 0;
}

static int init_control_socket(struct opal_prd_ctx *ctx)
{
	struct sockaddr_un addr;
	int fd, rc;

	unlink(opal_prd_socket);

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, opal_prd_socket);

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		pr_log(LOG_WARNING, "CTRL: Can't open control socket %s: %m",
				opal_prd_socket);
		return -1;
	}

	rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc) {
		pr_log(LOG_WARNING, "CTRL: Can't bind control socket %s: %m",
				opal_prd_socket);
		close(fd);
		return -1;
	}

	rc = listen(fd, 0);
	if (rc) {
		pr_log(LOG_WARNING, "CTRL: Can't listen on "
				"control socket %s: %m", opal_prd_socket);
		close(fd);
		return -1;
	}

	pr_log(LOG_INFO, "CTRL: Listening on control socket %s",
			opal_prd_socket);

	ctx->socket = fd;
	return 0;
}

static struct sigaction sigchild_action = {
	.sa_flags = SA_NOCLDWAIT | SA_RESTART,
	.sa_handler = SIG_DFL,
};

static int run_prd_daemon(struct opal_prd_ctx *ctx)
{
	char *opal_msg_path;
	void *buf;
	int rc, len;

	/* log to syslog */
	pr_log_daemon_init();

	pr_debug("CTRL: Starting PRD daemon\n");

	ctx->fd = -1;
	ctx->socket = -1;

	/*
	 * Set up our message buffer. Use opal-msg-size device tree
	 * property to get message buffer size.
	 */
	rc = asprintf(&opal_msg_path,
		       "%s/ibm,opal/opal-msg-size", devicetree_base);
	if (rc > 0) {
		rc = open_and_read(opal_msg_path, &buf, &len);
		if (rc == 0) {
			ctx->msg_alloc_len = be32toh(*(__be32 *)buf);
			free(buf);
		}

		free(opal_msg_path);
	}

	if (ctx->msg_alloc_len == 0)
		ctx->msg_alloc_len = sizeof(*ctx->msg);

	ctx->msg = malloc(ctx->msg_alloc_len);
	if (!ctx->msg) {
		pr_log(LOG_ERR, "FW: Can't allocate PRD message buffer: %m");
		return -1;
	}
	memset(ctx->msg, 0, ctx->msg_alloc_len);

	list_head_init(&ctx->msgq);

	i2c_init();

#ifdef DEBUG_I2C
	{
		uint8_t foo[128];
		int i;

		rc = i2c_read(0, 1, 2, 0x50, 2, 0x10, 128, foo);
		pr_debug("I2C: read rc: %d", rc);
		for (i = 0; i < sizeof(foo); i += 8) {
			pr_debug("I2C: %02x %02x %02x %02x %02x %02x %02x %02x",
			       foo[i + 0], foo[i + 1], foo[i + 2], foo[i + 3],
			       foo[i + 4], foo[i + 5], foo[i + 6], foo[i + 7]);
		}
	}
#endif
	rc = init_control_socket(ctx);
	if (rc) {
		pr_log(LOG_WARNING, "CTRL: Error initialising PRD control: %m");
		goto out_close;
	}


	rc = prd_init(ctx);
	if (rc) {
		pr_log(LOG_ERR, "FW: Error initialising PRD channel");
		goto out_close;
	}

	if (ctx->hbrt_file_name) {
		rc = map_hbrt_file(ctx, ctx->hbrt_file_name);
		if (rc) {
			pr_log(LOG_ERR, "IMAGE: Can't access hbrt file %s",
					ctx->hbrt_file_name);
			goto out_close;
		}
	} else {
		rc = map_hbrt_physmem(ctx, hbrt_code_region_name);
		if (rc) {
			/* Fallback to old style ibm,prd-label */
			rc = map_hbrt_physmem(ctx, hbrt_code_region_name_ibm);
			if (rc) {
				pr_log(LOG_ERR, "IMAGE: Can't access hbrt "
						"physical memory");
				goto out_close;
			}
		}
		dump_hbrt_map(ctx);
	}

	pr_debug("IMAGE: hbrt map at %p, size 0x%zx",
			ctx->code_addr, ctx->code_size);

	fixup_hinterface_table();

	if (!is_fsp_system()) {
		pnor_load_module(ctx);

		rc = pnor_init(&ctx->pnor);
		if (rc) {
			pr_log(LOG_ERR, "PNOR: Failed to open pnor: %m");
			goto out_close;
		}
	} else {
		/* Disable PNOR function pointers */
		hinterface.pnor_read = NULL;
		hinterface.pnor_write = NULL;
	}

	ipmi_init(ctx);

	pr_debug("HBRT: calling hservices_init");
	rc = hservices_init(ctx, ctx->code_addr);
	if (rc) {
		pr_log(LOG_ERR, "HBRT: Can't initialise HBRT");
		goto out_close;
	}
	pr_debug("HBRT: hservices_init done");

	/* Test a scom */
	if (ctx->debug) {
		uint64_t val;
		pr_debug("SCOM: trying scom read");
		fflush(stdout);
		hservice_scom_read(0x00, 0xf000f, &val);
		pr_debug("SCOM:  f00f: %lx", be64toh(val));
	}

	/*
	 * Setup the SIGCHLD handler to automatically reap the worker threads
	 * we use for memory offlining. We can't do this earlier since the
	 * modprobe helper spawns workers and wants to check their exit status
	 * with waitpid(). Auto-reaping breaks that so enable it just before
	 * entering the attn loop.
	 *
	 * We also setup system call restarting on SIGCHLD since opal-prd
	 * doesn't make any real attempt to handle blocking functions exiting
	 * due to EINTR.
	 */
	if (sigaction(SIGCHLD, &sigchild_action, NULL)) {
		pr_log(LOG_ERR, "CTRL: Failed to register signal handler %m\n");
		return -1;
	}

	run_attn_loop(ctx);
	rc = 0;

out_close:
	pr_debug("CTRL: stopping PRD daemon\n");
	pnor_close(&ctx->pnor);
	if (ctx->fd != -1)
		close(ctx->fd);
	if (ctx->socket != -1)
		close(ctx->socket);
	if (ctx->msg)
		free(ctx->msg);
	return rc;
}

static int send_prd_control(struct control_msg *send_msg,
			    struct control_msg **recv_msg)
{
	struct sockaddr_un addr;
	struct control_msg *msg;
	int sd, rc, size;

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (!sd) {
		pr_log(LOG_ERR, "CTRL: Failed to create control socket: %m");
		return -1;
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, opal_prd_socket);

	rc = connect(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc) {
		pr_log(LOG_ERR, "CTRL: Failed to connect to prd daemon: %m");
		goto out_close;
	}

	size = sizeof(*send_msg) + send_msg->data_len;
	rc = send(sd, send_msg, size, 0);
	if (rc != size) {
		pr_log(LOG_ERR, "CTRL: Failed to send control message: %m");
		rc = -1;
		goto out_close;
	}

	size = sizeof(*msg) + MAX_CONTROL_MSG_BUF;
	msg = malloc(size);
	if (!msg) {
		pr_log(LOG_ERR, "CTRL: msg buffer malloc failed: %m");
		rc = -1;
		goto out_close;
	}

	*recv_msg = msg;

	/* wait for our reply */
	rc = recv(sd, msg, size, 0);
	if (rc < 0) {
		pr_log(LOG_ERR, "CTRL: Failed to receive control message: %m");
		goto out_close;

	} else if (rc != (sizeof(*msg) + msg->data_len)) {
		pr_log(LOG_WARNING, "CTRL: Short read from control socket");
		rc = -1;
		goto out_close;
	}

	rc = msg->response;

out_close:
	close(sd);
	return rc;
}

static int send_occ_control(struct opal_prd_ctx *ctx, int argc, char *argv[])
{
	struct control_msg send_msg, *recv_msg = NULL;
	unsigned long chip = 0;
	const char *op;
	int rc;

	assert(argc >= 1);
	op = argv[0];

	/* some commands accept a 'chip' argument, so parse it here */
	if (argc > 1) {
		char *arg, *end;
		arg = argv[1];
		chip = strtoul(arg, &end, 0);
		if (end == arg) {
			pr_log(LOG_ERR, "CTRL: invalid argument %s", arg);
			return -1;
		}
	}

	memset(&send_msg, 0, sizeof(send_msg));

	if (!strcmp(op, "enable"))
		send_msg.type = CONTROL_MSG_ENABLE_OCCS;
	else if (!strcmp(op, "disable"))
		send_msg.type = CONTROL_MSG_DISABLE_OCCS;

	else if (!strcmp(op, "reset")) {
		send_msg.type = CONTROL_MSG_TEMP_OCC_RESET;
		send_msg.occ_reset.chip = (uint64_t)chip;

	} else if (!strcmp(op, "process-error")) {
		send_msg.type = CONTROL_MSG_TEMP_OCC_ERROR;
		send_msg.occ_error.chip = (uint64_t)chip;
	} else {
		pr_log(LOG_ERR, "CTRL: Invalid OCC action '%s'", op);
		return -1;
	}

	rc = send_prd_control(&send_msg, &recv_msg);
	if (recv_msg) {
		if (recv_msg->response || ctx->debug)
			pr_debug("CTRL: OCC action %s returned status %d", op,
					recv_msg->response);
		free(recv_msg);
	}

	return rc;
}

static int send_attr_override(struct opal_prd_ctx *ctx, uint32_t argc,
			      char *argv[])
{
	struct control_msg *send_msg, *recv_msg = NULL;
	struct stat statbuf;
	size_t sz;
	FILE *fd;
	int rc;

	rc = stat(argv[0], &statbuf);
	if (rc) {
		pr_log(LOG_ERR, "CTRL: stat() failed on the file: %m");
		return -1;
	}

	send_msg = malloc(sizeof(*send_msg) + statbuf.st_size);
	if (!send_msg) {
		pr_log(LOG_ERR, "CTRL: msg buffer malloc failed: %m");
		return -1;
	}

	send_msg->type = CONTROL_MSG_ATTR_OVERRIDE;
	send_msg->data_len = statbuf.st_size;

	fd = fopen(argv[0], "r");
	if (!fd) {
		pr_log(LOG_NOTICE, "CTRL: can't open %s: %m", argv[0]);
		rc = -1;
		goto out_free;
	}

	sz = fread(send_msg->data, 1, send_msg->data_len, fd);
	fclose(fd);
	if (sz != statbuf.st_size) {
		pr_log(LOG_ERR, "CTRL: short read from the file");
		rc = -1;
		goto out_free;
	}

	rc = send_prd_control(send_msg, &recv_msg);
	if (recv_msg) {
		if (recv_msg->response || ctx->debug)
			pr_debug("CTRL: attribute override returned status %d",
					recv_msg->response);
		free(recv_msg);
	}

out_free:
	free(send_msg);
	return rc;
}

static int send_htmgt_passthru(struct opal_prd_ctx *ctx, int argc, char *argv[])
{
	struct control_msg *send_msg, *recv_msg = NULL;
	int rc, i;

	if (!ctx->expert_mode) {
		pr_log(LOG_WARNING, "CTRL: need to be in expert mode");
		return -1;
	}

	send_msg = malloc(sizeof(*send_msg) + argc);
	if (!send_msg) {
		pr_log(LOG_ERR, "CTRL: message buffer malloc failed: %m");
		return -1;
	}

	send_msg->type = CONTROL_MSG_HTMGT_PASSTHRU;
	send_msg->data_len = argc;

	if (ctx->debug)
		pr_debug("CTRL: HTMGT passthru arguments:");

	for (i = 0; i < argc; i++) {
		if (ctx->debug)
			pr_debug("argv[%d] = %s", i, argv[i]);

		sscanf(argv[i], "%hhx", &send_msg->data[i]);
	}

	rc = send_prd_control(send_msg, &recv_msg);
	free(send_msg);

	if (recv_msg) {
		if (recv_msg->response || ctx->debug)
			pr_debug("CTRL: HTMGT passthru returned status %d",
					recv_msg->response);
		if (recv_msg->response == 0 && recv_msg->data_len)
			hexdump(recv_msg->data, recv_msg->data_len);

		free(recv_msg);
	}

	return rc;
}

static int send_run_command(struct opal_prd_ctx *ctx, int argc, char *argv[])
{
	struct control_msg *send_msg, *recv_msg = NULL;
	uint32_t size = 0;
	int rc, i;
	char *s;

	if (!ctx->expert_mode) {
		pr_log(LOG_WARNING, "CTRL: need to be in expert mode");
		return -1;
	}

	if (ctx->debug) {
		pr_debug("CTRL: run command arguments:");
		for (i=0; i < argc; i++)
			pr_debug("argv[%d] = %s", i, argv[i]);
	}

	for (i = 0; i < argc; i++)
		size += (strlen(argv[i]) + 1);

	send_msg = malloc(sizeof(*send_msg) + size);
	if (!send_msg) {
		pr_log(LOG_ERR, "CTRL: msg buffer malloc failed: %m");
		return -1;
	}

	/* Setup message */
	send_msg->type = CONTROL_MSG_RUN_CMD;
	send_msg->run_cmd.argc = argc;
	send_msg->data_len = size;
	s = (char *)send_msg->data;
	for (i = 0; i < argc; i++) {
		strcpy(s, argv[i]);
		s = s + strlen(argv[i]) + 1;
	}

	rc = send_prd_control(send_msg, &recv_msg);
	free(send_msg);
	if (recv_msg) {
		if (!rc)
			pr_log(LOG_INFO, "Received: %s", recv_msg->data);

		if (recv_msg->response || ctx->debug)
			pr_debug("CTRL: run command returned status %d",
					recv_msg->response);
		free(recv_msg);
	}

	return rc;
}

static void usage(const char *progname)
{
	printf("Usage:\n");
	printf("\t%s [--debug] [--file <hbrt-image>] [--pnor <device>]\n",
			progname);
	printf("\t%s occ <enable|disable|reset [chip]>\n", progname);
	printf("\t%s pm-complex reset [chip]>\n", progname);
	printf("\t%s htmgt-passthru <bytes...>\n", progname);
	printf("\t%s override <FILE>\n", progname);
	printf("\t%s run [arg 0] [arg 1]..[arg n]\n", progname);
	printf("\n");
	printf("Options:\n"
"\t--debug            verbose logging for debug information\n"
"\t--pnor DEVICE      use PNOR MTD device\n"
"\t--file FILE        use FILE for hostboot runtime code (instead of code\n"
"\t                     exported by firmware)\n"
"\t--stdio            log to stdio, instead of syslog\n");
}

static void print_version(void)
{
	extern const char version[];
	printf("opal-prd %s\n", version);
}

static struct option opal_diag_options[] = {
	{"file", required_argument, NULL, 'f'},
	{"pnor", required_argument, NULL, 'p'},
	{"debug", no_argument, NULL, 'd'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"stdio", no_argument, NULL, 's'},
	{"expert-mode", no_argument, NULL, 'e'},
	{ 0 },
};

enum action {
	ACTION_RUN_DAEMON,
	ACTION_OCC_CONTROL,
	ACTION_ATTR_OVERRIDE,
	ACTION_HTMGT_PASSTHRU,
	ACTION_RUN_COMMAND,
};

static int parse_action(const char *str, enum action *action)
{
	int rc;

	if (!strcmp(str, "occ")) {
		*action = ACTION_OCC_CONTROL;
		rc = 0;

		if (is_fsp_system()) {
			pr_log(LOG_ERR, "CTRL: occ commands are not "
			       "supported on this system");
			rc = -1;
		}
	} else if (!strcmp(str, "pm-complex")) {
		*action = ACTION_OCC_CONTROL;
		rc = 0;

		if (!is_fsp_system()) {
			pr_log(LOG_ERR, "CTRL: pm-complex commands are not "
			       "supported on this system");
			rc = -1;
		}
	} else if (!strcmp(str, "daemon")) {
		*action = ACTION_RUN_DAEMON;
		rc = 0;
	} else if (!strcmp(str, "override")) {
		*action = ACTION_ATTR_OVERRIDE;
		rc = 0;
	} else if (!strcmp(str, "htmgt-passthru")) {
		*action = ACTION_HTMGT_PASSTHRU;
		rc = 0;
	} else if (!strcmp(str, "run")) {
		*action = ACTION_RUN_COMMAND;
		return 0;
	} else {
		pr_log(LOG_ERR, "CTRL: unknown argument '%s'", str);
		rc = -1;
	}

	return rc;
}

int main(int argc, char *argv[])
{
	struct opal_prd_ctx _ctx;
	enum action action;
	int rc;

	check_abi();

	ctx = &_ctx;
	memset(ctx, 0, sizeof(*ctx));
	ctx->vlog = pr_log_stdio;
	ctx->use_syslog = true;

	/* Parse options */
	for (;;) {
		int c;

		c = getopt_long(argc, argv, "f:p:dhse", opal_diag_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'f':
			ctx->hbrt_file_name = optarg;
			break;
		case 'd':
			ctx->debug = true;
			break;
		case 'p':
			ctx->pnor.path = strndup(optarg, PATH_MAX);
			break;
		case 's':
			ctx->use_syslog = false;
			break;
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
		case 'e':
			ctx->expert_mode = true;
			break;
		case 'v':
			print_version();
			return EXIT_SUCCESS;
		case '?':
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (optind < argc) {
		rc = parse_action(argv[optind], &action);
		if (rc)
			return EXIT_FAILURE;
		optind++;
	} else {
		action = ACTION_RUN_DAEMON;
	}

	if (is_prd_supported() < 0) {
		pr_log(LOG_ERR, "CTRL: PowerNV OPAL runtime diagnostic "
				"is not supported on this system");
		return -1;
	}

	switch (action) {
	case ACTION_RUN_DAEMON:
		rc = run_prd_daemon(ctx);
		break;
	case ACTION_OCC_CONTROL:
		if (optind >= argc) {
			pr_log(LOG_ERR, "CTRL: occ command requires "
					"an argument");
			return EXIT_FAILURE;
		}

		rc = send_occ_control(ctx, argc - optind, &argv[optind]);
		break;
	case ACTION_ATTR_OVERRIDE:
		if (optind >= argc) {
			pr_log(LOG_ERR, "CTRL: attribute override command "
					"requires an argument");
			return EXIT_FAILURE;
		}

		rc = send_attr_override(ctx, argc - optind, &argv[optind]);
		break;
	case ACTION_HTMGT_PASSTHRU:
		if (optind >= argc) {
			pr_log(LOG_ERR, "CTRL: htmgt passthru requires at least "
					"one argument");
			return EXIT_FAILURE;
		}

		rc = send_htmgt_passthru(ctx, argc - optind, &argv[optind]);
		break;
	case ACTION_RUN_COMMAND:
		if (optind >= argc) {
			pr_log(LOG_ERR, "CTRL: run command requires "
					"argument(s)");
			return EXIT_FAILURE;
		}

		rc = send_run_command(ctx, argc - optind, &argv[optind]);
		break;
	default:
		break;
	}

	return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
