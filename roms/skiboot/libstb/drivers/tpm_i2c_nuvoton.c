// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#include <timebase.h>
#include <skiboot.h>
#include <device.h>
#include <i2c.h>
#include "../status_codes.h"
#include "../tpm_chip.h"
#include "tpm_i2c_interface.h"
#include "tpm_i2c_nuvoton.h"
#include <opal-api.h>

//#define DBG(fmt, ...) prlog(PR_DEBUG, fmt, ##__VA_ARGS__)
#define DBG(fmt, ...)

#define DRIVER_NAME "i2c_tpm_nuvoton"

/* I2C interface offsets */
#define TPM_STS			0x00
#define TPM_BURST_COUNT		0x01
#define TPM_DATA_FIFO_W		0x20
#define TPM_DATA_FIFO_R		0x40
#define TPM_VID_DID		0x60

/* Bit masks for the TPM STATUS register */
#define TPM_STS_VALID		0x80
#define TPM_STS_COMMAND_READY	0x40
#define TPM_STS_GO		0x20
#define TPM_STS_DATA_AVAIL	0x10
#define TPM_STS_EXPECT		0x08


/* TPM Driver values */
#define MAX_STSVALID_POLLS 	5
#define TPM_TIMEOUT_INTERVAL	10
#define TPM_NUVOTON_VID		0x5010FE00
#define TPM_VENDOR_ID_MASK	0xFFFFFF00

static struct tpm_dev *tpm_device = NULL;

static int tpm_status_write_byte(uint8_t byte)
{
	uint8_t value = byte;
	return tpm_i2c_request_send(tpm_device, SMBUS_WRITE, TPM_STS, 1, &value,
				    sizeof(value));
}

static int tpm_status_read_byte(uint8_t offset, uint8_t *byte)
{
	return tpm_i2c_request_send(tpm_device, SMBUS_READ, offset, 1, byte,
				    sizeof(uint8_t));
}

static bool tpm_check_status(uint8_t status, uint8_t mask, uint8_t expected)
{
	return ((status & mask) == expected);
}

static int tpm_wait_for_command_ready(void)
{
	uint64_t start, stop, now;
	int rc;
	uint8_t status;

	start = mftb();
	stop = start + msecs_to_tb(TPM_TIMEOUT_B);

	do {
		now = mftb();
		rc = tpm_status_read_byte(TPM_STS, &status);
		if (rc < 0) {
			/**
			 * @fwts-label TPMReadCmdReady
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "NUVOTON: fail to read sts.commandReady, "
			      "rc=%d\n", rc);
			return STB_DRIVER_ERROR;
		}
		if (tpm_check_status(status,
				     TPM_STS_COMMAND_READY,
				     TPM_STS_COMMAND_READY)) {
			DBG("--- Command ready, delay=%lu/%d\n",
			    tb_to_msecs(now-start), TPM_TIMEOUT_B);
			return 0;
		}
		if (tb_compare(now, stop) == TB_ABEFOREB)
			time_wait_ms(TPM_TIMEOUT_INTERVAL);
		else
			break;
	} while (1);

	return STB_TPM_TIMEOUT;
}

static int tpm_set_command_ready(void)
{
	int rc, retries;
	/*
	 * The first write to command ready may just abort an
	 * outstanding command, so we poll twice
	 */
	for (retries = 0; retries < 2; retries++) {
		rc = tpm_status_write_byte(TPM_STS_COMMAND_READY);
		if (rc < 0) {
			/**
			 * @fwts-label TPMWriteCmdReady
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "NUVOTON: fail to write sts.commandReady, "
			      "rc=%d\n", rc);
			return STB_DRIVER_ERROR;
		}
		rc = tpm_wait_for_command_ready();
		if (rc == STB_TPM_TIMEOUT)
			continue;
		return rc;
	}
	/**
	 * @fwts-label TPMCmdReadyTimeout
	 * @fwts-advice The command ready bit of the tpm status register is
	 * taking longer to be settled. Either the wait time need to be
	 * increased or the TPM device is not functional.
	 */
	prlog(PR_ERR, "NUVOTON: timeout on sts.commandReady, delay > %d\n",
	      2*TPM_TIMEOUT_B);
	return STB_TPM_TIMEOUT;
}

static int tpm_wait_for_fifo_status(uint8_t mask, uint8_t expected)
{
	int retries, rc;
	uint8_t status;

	for(retries = 0; retries <= MAX_STSVALID_POLLS; retries++) {
		rc = tpm_status_read_byte(TPM_STS, &status);
		if (rc < 0) {
			/**
			 * @fwts-label TPMReadFifoStatus
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "NUVOTON: fail to read fifo status: "
			      "mask %x, expected %x, rc=%d\n", mask, expected,
			      rc);
			return STB_DRIVER_ERROR;
		}
		if (tpm_check_status(status, mask, expected))
			return 0;
		/* Wait TPM STS register be settled */
		time_wait_ms(5);
	}
	return STB_TPM_TIMEOUT;
}

static int tpm_wait_for_data_avail(void)
{
	uint64_t start, stop, now;
	uint8_t status;
	int rc;

	start = mftb();
	stop = start + msecs_to_tb(TPM_TIMEOUT_A);

	do {
		now = mftb();
		rc = tpm_status_read_byte(TPM_STS, &status);
		if (rc < 0) {
			/**
			 * @fwts-label TPMReadDataAvail
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "NUVOTON: fail to read sts.dataAvail, "
			      "rc=%d\n", rc);
			return STB_DRIVER_ERROR;
		}
		if (tpm_check_status(status,
				     TPM_STS_VALID | TPM_STS_DATA_AVAIL,
				     TPM_STS_VALID | TPM_STS_DATA_AVAIL)) {
			DBG("---- Data available. delay=%lu/%d\n",
			    tb_to_msecs(now-start), TPM_TIMEOUT_A);
			return 0;
		}
		if (tb_compare(now, stop) == TB_ABEFOREB)
			time_wait_ms(TPM_TIMEOUT_INTERVAL);
		else
			break;
	} while (1);
	/**
	 * @fwts-label TPMDataAvailBitTimeout
	 * @fwts-advice The data avail bit of the tpm status register is taking
	 * longer to be settled. Either the wait time need to be increased or
	 * the TPM device is not functional.
	 */
	prlog(PR_ERR, "NUVOTON: timeout on sts.dataAvail, delay=%lu/%d\n",
	      tb_to_msecs(now-start), TPM_TIMEOUT_A);
	return STB_TPM_TIMEOUT;
}

static int tpm_read_burst_count(void)
{
	uint64_t start, stop, now;
	uint8_t burst_count;
	int rc;

	start = mftb();
	stop = start + msecs_to_tb(TPM_TIMEOUT_D);
	burst_count = 0;

	do {
		now = mftb();
		/* In i2C, burstCount is 1 byte */
		rc = tpm_status_read_byte(TPM_BURST_COUNT, &burst_count);
		if (rc == 0 && burst_count > 0) {
			DBG("---- burst_count=%d, delay=%lu/%d\n", burst_count,
			    tb_to_msecs(now-start), TPM_TIMEOUT_D);
			return (int) burst_count;
		}
		if (rc < 0) {
			/**
			 * @fwts-label TPMReadBurstCount
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "NUVOTON: fail to read sts.burstCount, "
			      "rc=%d\n", rc);
			return STB_DRIVER_ERROR;
		}
		if (tb_compare(now, stop) == TB_ABEFOREB)
			time_wait_ms(TPM_TIMEOUT_INTERVAL);
		else
			break;
	} while (1);

	/**
	 * @fwts-label TPMBurstCountTimeout
	 * @fwts-advice The burstcount bit of the tpm status register is
	 * taking longer to be settled. Either the wait time need to be
	 * increased or the TPM device is not functional.
	 */
	prlog(PR_ERR, "NUVOTON: timeout on sts.burstCount, delay=%lu/%d\n",
	      tb_to_msecs(now-start), TPM_TIMEOUT_D);
	return STB_TPM_TIMEOUT;
}

static int tpm_write_fifo(uint8_t* buf, size_t buflen)
{
	int rc, burst_count;
	size_t count, bytes;

	/*
	 * We will transfer the command except for the last byte
	 * that will be transfered separately to allow for
	 * overflow checking
	 */
	count = 0;
	do {
		burst_count = tpm_read_burst_count();
		if (burst_count < 0)
			return burst_count;

		bytes = (count + burst_count > buflen - 1 ?
			  (buflen - 1 - count) : burst_count);

		rc = tpm_i2c_request_send(tpm_device,
					  SMBUS_WRITE, TPM_DATA_FIFO_W,
					  1, &buf[count], bytes);
		count += bytes;
		DBG("%s FIFO: %zd bytes written, count=%zd, rc=%d\n",
		    (rc) ? "!!!!" : "----", bytes, count, rc);
		if (rc < 0) {
			/**
			 * @fwts-label TPMWriteFifo
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "NUVOTON: fail to write fifo, "
			      "count=%zd, rc=%d\n", count, rc);
			return STB_DRIVER_ERROR;
		}

		rc = tpm_wait_for_fifo_status(TPM_STS_VALID | TPM_STS_EXPECT,
					      TPM_STS_VALID | TPM_STS_EXPECT);
		if (rc == STB_DRIVER_ERROR)
			return rc;
		if (rc == STB_TPM_TIMEOUT) {
			/**
			 * @fwts-label TPMWriteFifoNotExpecting
			 * @fwts-advice The write to the TPM FIFO overflowed,
			 * the TPM is not expecting more data. This indicates a
			 * bug in the TPM device driver.
			 */
			prlog(PR_ERR, "NUVOTON: write FIFO overflow, not expecting "
			      "more data\n");
			return STB_TPM_OVERFLOW;
		}
	} while (count < buflen - 1);

	/*
	 *  Write the last byte
	 */
	burst_count = tpm_read_burst_count();
	if (burst_count < 0)
		return burst_count;

	rc = tpm_i2c_request_send(tpm_device,
				  SMBUS_WRITE,
				  TPM_DATA_FIFO_W, 1,
				  &buf[count], 1);
	count++;
	DBG("%s FIFO: last byte written, count=%zd, rc=%d\n",
	    (rc) ? "!!!!" : "----", count, rc);

	if (rc < 0) {
		/**
		 * @fwts-label TPMWriteFifoLastByte
		 * @fwts-advice Either the tpm device or the tpm-i2c interface
		 * doesn't seem to be working properly. Check the return code
		 * (rc) for further details.
		 */
		prlog(PR_ERR, "NUVOTON: fail to write fifo (last byte), "
		      "count=%zd, rc=%d\n", count, rc);
		return STB_DRIVER_ERROR;
	}
	rc = tpm_wait_for_fifo_status(TPM_STS_VALID | TPM_STS_EXPECT,
				      TPM_STS_VALID | TPM_STS_EXPECT);
	if (rc == STB_DRIVER_ERROR)
		return rc;
	if (rc == 0) {
		 /**
		 * @fwts-label TPMWriteFifoExpecting
		 * @fwts-advice The write to the TPM FIFO overflowed.
		 * It is expecting more data even though we think we
		 * are done. This indicates a bug in the TPM device
		 * driver.
		 */
		prlog(PR_ERR, "TPM: write FIFO overflow, expecting "
		      "more data\n");
		return STB_TPM_OVERFLOW;
	}
	return 0;
}

static int tpm_read_fifo(uint8_t* buf, size_t* buflen)
{
	int rc, burst_count;
	size_t count;

	rc = tpm_wait_for_data_avail();
	if (rc < 0)
		goto error;

	count = 0;
	do {
		burst_count = tpm_read_burst_count();
		if (burst_count < 0) {
			rc = burst_count;
			goto error;
		}
		if (count + burst_count > *buflen) {
			 /**
			 * @fwts-label TPMReadFifoOverflow
			 * @fwts-advice The read from TPM FIFO overflowed. It is
			 * expecting more data even though we think we are done.
			 * This indicates a bug in the TPM device driver.
			 */
			prlog(PR_ERR, "NUVOTON: overflow on fifo read, c=%zd, "
			      "bc=%d, bl=%zd\n", count, burst_count, *buflen);
			rc = STB_TPM_OVERFLOW;
			goto error;
		}
		rc = tpm_i2c_request_send(tpm_device,
					  SMBUS_READ,
					  TPM_DATA_FIFO_R, 1,
					  &buf[count], burst_count);
		count += burst_count;
		DBG("%s FIFO: %d bytes read, count=%zd, rc=%d\n",
		    (rc) ? "!!!!" : "----", burst_count, count, rc);
		if (rc < 0) {
			/**
			 * @fwts-label TPMReadFifo
			 * @fwts-advice Either the tpm device or the tpm-i2c interface
			 * doesn't seem to be working properly. Check the return code
			 * (rc) for further details.
			 */
			prlog(PR_ERR, "NUVOTON: fail to read fifo, count=%zd, "
			      "rc=%d\n", count, rc);
			rc = STB_DRIVER_ERROR;
			goto error;
		}
		rc = tpm_wait_for_fifo_status(
					  TPM_STS_VALID | TPM_STS_DATA_AVAIL,
					  TPM_STS_VALID | TPM_STS_DATA_AVAIL);
		if (rc == STB_DRIVER_ERROR)
			goto error;
	} while (rc == 0);

	*buflen = count;
	return 0;

error:
	*buflen = 0;
	return rc;
}

static int tpm_transmit(struct tpm_dev *dev, uint8_t* buf, size_t cmdlen,
			size_t* buflen)
{
	int rc = 0;
	if (!dev) {
		/**
		 * @fwts-label TPMDeviceNotInitialized
		 * @fwts-advice TPM device is not initialized. This indicates a
		 * bug in the tpm_transmit() caller
		 */
		prlog(PR_ERR, "TPM: tpm device not initialized\n");
		return STB_ARG_ERROR;
	}
	tpm_device = dev;
	DBG("**** %s: dev %#x/%#x buf %016llx cmdlen %zu"
	    " buflen %zu ****\n",
	    __func__, dev->bus_id, dev->i2c_addr, *(uint64_t *) buf,
	    cmdlen, *buflen);

	DBG("step 1/5: set command ready\n");
	rc = tpm_set_command_ready();
	if (rc < 0)
		goto out;

	DBG("step 2/5: write FIFO\n");
	rc = tpm_write_fifo(buf, cmdlen);
	if (rc < 0)
		goto out;

	DBG("step 3/5: write sts.go\n");
	rc = tpm_status_write_byte(TPM_STS_GO);
	if (rc < 0) {
		/**
		 * @fwts-label TPMWriteGo
		 * @fwts-advice Either the tpm device or the tpm-i2c interface
		 * doesn't seem to be working properly. Check the return code
		 * (rc) for further details.
		 */
		prlog(PR_ERR, "NUVOTON: fail to write sts.go, rc=%d\n", rc);
		rc = STB_DRIVER_ERROR;
		goto out;
	}

	DBG("step 4/5: read FIFO\n");
	rc = tpm_read_fifo(buf, buflen);
	if (rc < 0)
		goto out;

	DBG("step 5/5: release tpm\n");
	rc = tpm_status_write_byte(TPM_STS_COMMAND_READY);
	if (rc < 0) {
		/**
		 * @fwts-label TPMReleaseTpm
		 * @fwts-advice Either the tpm device or the tpm-i2c interface
		 * doesn't seem to be working properly. Check the return code
		 * (rc) for further details.
		 */
		prlog(PR_ERR, "NUVOTON: fail to release tpm, rc=%d\n", rc);
		rc = STB_DRIVER_ERROR;
	}

out:
	DBG("**** tpm_transmit %s, rc=%d ****\n",
	    (rc) ? "ERROR" : "SUCCESS", rc);
	return rc;
}

static struct tpm_driver tpm_i2c_nuvoton_driver = {
	.name     = DRIVER_NAME,
	.transmit = tpm_transmit,
};

static int nuvoton_tpm_quirk(void *data, struct i2c_request *req, int *rc)
{
	struct tpm_dev *tpm_device = data;
	struct dt_node *dev;
	uint16_t addr;
	bool found;

	/*
	 * The nuvoton TPM firmware has a problem where a single byte read or
	 * zero byte write to one of its I2C addresses causes the TPM to lock
	 * up the bus. Once locked up the bus can only be recovered by power
	 * cycling the TPM. Unfortunately, we don't have the ability to
	 * power cycle the TPM because allowing it to be reset at runtime
	 * would undermine the TPM's security model (we can reset it and
	 * send it whatever measurements we like to unlock it's secrets).
	 * So the best we can do here is try avoid triggering the problem
	 * in the first place.
	 *
	 * For a bit of added fun the TPM also appears to check for traffic
	 * on a few different I2C bus addresses. It does this even when not
	 * configured to respond on those addresses so you can trigger the
	 * bug by sending traffic... somwhere. To work around this we block
	 * sending I2C requests on the TPM's bus unless the DT explicitly
	 * tells us there is a device there.
	 */

	/* first, check if this a known address */
	addr = req->dev_addr;
	found = false;

	dt_for_each_child(req->bus->dt_node, dev) {
		if (dt_prop_get_u32(dev, "reg") == addr) {
			found = true;
			break;
		}
	}

	if (!found) {
		*rc = OPAL_I2C_TIMEOUT;
		return 1;
	}

	/* second, check if it's a bad transaction to the TPM */
	if (tpm_device->bus_id == req->bus->opal_id &&
	    tpm_device->i2c_addr == req->dev_addr &&
	    ((req->op == I2C_READ && req->rw_len == 1) ||
	     (req->op == I2C_WRITE && req->rw_len == 0))) {
		*rc = OPAL_I2C_TIMEOUT;
		prlog(PR_DEBUG,"NUVOTON: Squashed i2c probe to avoid locking "
		      "I2C bus\n");
		return 1;
	}

	return 0;
}

void tpm_i2c_nuvoton_probe(void)
{
	struct tpm_dev *tpm_device = NULL;
	struct dt_node *node = NULL;
	struct i2c_bus *bus;
	const char *name;
	uint32_t vendor = 0;

	dt_for_each_compatible(dt_root, node, "nuvoton,npct650") {
		if (!dt_node_is_enabled(node))
			continue;
		tpm_device = (struct tpm_dev*) malloc(sizeof(struct tpm_dev));
		assert(tpm_device);
		/*
		 * Read TPM device address and bus id. Make sure the properties
		 * really exist if the default value is returned.
		 */
		tpm_device->i2c_addr = dt_prop_get_u32_def(node, "reg", 0);
		if (!tpm_device->i2c_addr && !dt_find_property(node, "reg")) {
			/*
			 * @fwts-label NuvotonRegNotFound
			 * @fwts-advice reg property not found. This indicates
			 * a Hostboot bug if the property really doesn't exist
			 * in the tpm node.
			 */
			prlog(PR_ERR, "NUVOTON: reg property not found, "
			      "tpm node %p\n", node);
			goto disable;
		}
		tpm_device->bus_id = dt_prop_get_u32_def(node->parent,
							 "ibm,opal-id", 0);
		if (!tpm_device->bus_id &&
		    !dt_find_property(node->parent, "ibm,opal-id")) {
			/*
			 * @fwts-label NuvotonIbmOpalIdNotFound
			 * @fwts-advice ibm,opal-id property not found. This
			 * indicates a Hostboot bug if the property really
			 * doesn't exist in the tpm node.
			 */
			prlog(PR_ERR, "NUVOTON: ibm,opal-id property not "
			      "found, tpm node parent %p\n", node->parent);
			goto disable;
		}
		/* ensure there's really the TPM we expect at that address */
		if (tpm_i2c_request_send(tpm_device, SMBUS_READ, TPM_VID_DID,
					 1, &vendor, sizeof(vendor))) {
			prlog(PR_ERR, "NUVOTON: i2c device inaccessible\n");
			goto disable;
		}
		if ((vendor & TPM_VENDOR_ID_MASK) != TPM_NUVOTON_VID) {
			prlog(PR_ERR, "NUVOTON: expected vendor id mismatch\n");
			goto disable;
		}
		if (tpm_register_chip(node, tpm_device,
				      &tpm_i2c_nuvoton_driver)) {
			free(tpm_device);
			continue;
		}
		tss_tpm_register(tpm_device, &tpm_i2c_nuvoton_driver);
		bus = i2c_find_bus_by_id(tpm_device->bus_id);
		assert(bus->check_quirk == NULL);
		bus->check_quirk = nuvoton_tpm_quirk;
		bus->check_quirk_data = tpm_device;
		name = dt_prop_get(node->parent, "ibm,port-name");

		prlog(PR_NOTICE, "NUVOTON: TPM I2C workaround applied to %s\n",
				  name);

		/*
		 * Tweak for linux. It doesn't have a driver compatible
		 * with "nuvoton,npct650"
		 */
		if (!dt_node_is_compatible(node, "nuvoton,npct601")) {
			dt_check_del_prop(node, "compatible");
			dt_add_property_strings(node, "compatible",
						"nuvoton,npct650", "nuvoton,npct601");
		}
	}
	return;
disable:
	dt_add_property_string(node, "status", "disabled");
	prlog(PR_NOTICE, "TPM: tpm node %p disabled\n", node);
	free(tpm_device);
}
