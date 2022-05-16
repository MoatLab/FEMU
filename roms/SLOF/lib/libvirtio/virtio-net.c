/******************************************************************************
 * Copyright (c) 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

/*
 * This is the implementation for the Virtio network device driver. Details
 * about the virtio-net interface can be found in Rusty Russel's "Virtio PCI
 * Card Specification v0.8.10", appendix C, which can be found here:
 *
 *        http://ozlabs.org/~rusty/virtio-spec/virtio-spec.pdf
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <helpers.h>
#include <cache.h>
#include <byteorder.h>
#include "virtio-net.h"
#include "virtio-internal.h"

#undef DEBUG
//#define DEBUG
#ifdef DEBUG
# define dprintf(fmt...) do { printf(fmt); } while(0)
#else
# define dprintf(fmt...)
#endif

#define sync()  asm volatile (" sync \n" ::: "memory")

#define DRIVER_FEATURE_SUPPORT  (VIRTIO_NET_F_MAC | VIRTIO_F_VERSION_1)

/* See Virtio Spec, appendix C, "Device Operation" */
struct virtio_net_hdr {
	uint8_t  flags;
	uint8_t  gso_type;
	uint16_t  hdr_len;
	uint16_t  gso_size;
	uint16_t  csum_start;
	uint16_t  csum_offset;
	// uint16_t  num_buffers;	/* Only if VIRTIO_NET_F_MRG_RXBUF */
};

static unsigned int net_hdr_size;

struct virtio_net_hdr_v1 {
	uint8_t  flags;
	uint8_t  gso_type;
	le16  hdr_len;
	le16  gso_size;
	le16  csum_start;
	le16  csum_offset;
	le16  num_buffers;
};

static uint16_t last_rx_idx;	/* Last index in RX "used" ring */

/**
 * Module init for virtio via PCI.
 * Checks whether we're reponsible for the given device and set up
 * the virtqueue configuration.
 */
static int virtionet_init_pci(struct virtio_net *vnet, struct virtio_device *dev)
{
	struct virtio_device *vdev = &vnet->vdev;

	dprintf("virtionet: doing virtionet_init_pci!\n");

	if (!dev)
		return -1;

	/* make a copy of the device structure */
	memcpy(vdev, dev, sizeof(struct virtio_device));

	/* Reset device */
	virtio_reset_device(vdev);

	/* Acknowledge device. */
	virtio_set_status(vdev, VIRTIO_STAT_ACKNOWLEDGE);

	return 0;
}

/**
 * Initialize the virtio-net device.
 * See the Virtio Spec, chapter 2.2.1 and Appendix C "Device Initialization"
 * for details.
 */
static int virtionet_init(struct virtio_net *vnet)
{
	int i;
	int status = VIRTIO_STAT_ACKNOWLEDGE | VIRTIO_STAT_DRIVER;
	struct virtio_device *vdev = &vnet->vdev;
	net_driver_t *driver = &vnet->driver;
	struct vqs *vq_tx, *vq_rx;

	dprintf("virtionet_init(%02x:%02x:%02x:%02x:%02x:%02x)\n",
		driver->mac_addr[0], driver->mac_addr[1],
		driver->mac_addr[2], driver->mac_addr[3],
		driver->mac_addr[4], driver->mac_addr[5]);

	if (driver->running != 0)
		return 0;

	/* Tell HV that we know how to drive the device. */
	virtio_set_status(vdev, status);

	/* Device specific setup */
	if (vdev->features & VIRTIO_F_VERSION_1) {
		if (virtio_negotiate_guest_features(vdev, DRIVER_FEATURE_SUPPORT))
			goto dev_error;
		net_hdr_size = sizeof(struct virtio_net_hdr_v1);
		virtio_get_status(vdev, &status);
	} else {
		net_hdr_size = sizeof(struct virtio_net_hdr);
		virtio_set_guest_features(vdev,  0);
	}

	/* The queue information can be retrieved via the virtio header that
	 * can be found in the I/O BAR. First queue is the receive queue,
	 * second the transmit queue, and the forth is the control queue for
	 * networking options.
	 * We are only interested in the receive and transmit queue here. */
	vq_rx = virtio_queue_init_vq(vdev, VQ_RX);
	vq_tx = virtio_queue_init_vq(vdev, VQ_TX);
	if (!vq_rx || !vq_tx) {
		virtio_set_status(vdev, VIRTIO_STAT_ACKNOWLEDGE|VIRTIO_STAT_DRIVER
				  |VIRTIO_STAT_FAILED);
		return -1;
	}

	/* Allocate memory for one transmit an multiple receive buffers */
	vq_rx->buf_mem = SLOF_alloc_mem((BUFFER_ENTRY_SIZE+net_hdr_size)
				   * RX_QUEUE_SIZE);
	if (!vq_rx->buf_mem) {
		printf("virtionet: Failed to allocate buffers!\n");
		goto dev_error;
	}

	/* Prepare receive buffer queue */
	for (i = 0; i < RX_QUEUE_SIZE; i++) {
		uint64_t addr = (uint64_t)vq_rx->buf_mem
			+ i * (BUFFER_ENTRY_SIZE+net_hdr_size);
		uint32_t id = i*2;
		/* Descriptor for net_hdr: */
		virtio_fill_desc(vq_rx, id, vdev->features, addr, net_hdr_size,
				 VRING_DESC_F_NEXT | VRING_DESC_F_WRITE, id + 1);

		/* Descriptor for data: */
		virtio_fill_desc(vq_rx, id + 1, vdev->features, addr + net_hdr_size,
				 BUFFER_ENTRY_SIZE, VRING_DESC_F_WRITE, 0);

		vq_rx->avail->ring[i] = virtio_cpu_to_modern16(vdev, id);
	}
	sync();

	vq_rx->avail->flags = virtio_cpu_to_modern16(vdev, VRING_AVAIL_F_NO_INTERRUPT);
	vq_rx->avail->idx = virtio_cpu_to_modern16(vdev, RX_QUEUE_SIZE);

	last_rx_idx = virtio_modern16_to_cpu(vdev, vq_rx->used->idx);

	vq_tx->avail->flags = virtio_cpu_to_modern16(vdev, VRING_AVAIL_F_NO_INTERRUPT);
	vq_tx->avail->idx = 0;

	/* Tell HV that setup succeeded */
	status |= VIRTIO_STAT_DRIVER_OK;
	virtio_set_status(vdev, status);

	/* Tell HV that RX queues are ready */
	virtio_queue_notify(vdev, VQ_RX);

	driver->running = 1;
	for(i = 0; i < (int)sizeof(driver->mac_addr); i++) {
		driver->mac_addr[i] = virtio_get_config(vdev, i, 1);
	}
	return 0;

dev_error:
	status |= VIRTIO_STAT_FAILED;
	virtio_set_status(vdev, status);
	return -1;
}


/**
 * Shutdown driver.
 * We've got to make sure that the hosts stops all transfers since the buffers
 * in our main memory will become invalid after this module has been terminated.
 */
static int virtionet_term(struct virtio_net *vnet)
{
	struct virtio_device *vdev = &vnet->vdev;
	net_driver_t *driver = &vnet->driver;
	struct vqs *vq_tx = &vnet->vdev.vq[VQ_TX];
	struct vqs *vq_rx = &vnet->vdev.vq[VQ_RX];

	dprintf("virtionet_term()\n");

	if (driver->running == 0)
		return 0;

	/* Quiesce device */
	virtio_set_status(vdev, VIRTIO_STAT_FAILED);

	/* Reset device */
	virtio_reset_device(vdev);

	driver->running = 0;

	SLOF_free_mem(vq_rx->buf_mem,
		      (BUFFER_ENTRY_SIZE+net_hdr_size) * RX_QUEUE_SIZE);
	vq_rx->buf_mem = NULL;

	virtio_queue_term_vq(vdev, vq_rx, VQ_RX);
	virtio_queue_term_vq(vdev, vq_tx, VQ_TX);

	return 0;
}


/**
 * Transmit a packet
 */
static int virtionet_xmit(struct virtio_net *vnet, char *buf, int len)
{
	int id, idx;
	static struct virtio_net_hdr_v1 nethdr_v1;
	static struct virtio_net_hdr nethdr_legacy;
	void *nethdr = &nethdr_legacy;
	struct virtio_device *vdev = &vnet->vdev;
	struct vqs *vq_tx = &vdev->vq[VQ_TX];

	if (len > BUFFER_ENTRY_SIZE) {
		printf("virtionet: Packet too big!\n");
		return 0;
	}

	dprintf("\nvirtionet_xmit(packet at %p, %d bytes)\n", buf, len);

	if (vdev->features & VIRTIO_F_VERSION_1)
		nethdr = &nethdr_v1;

	memset(nethdr, 0, net_hdr_size);

	/* Determine descriptor index */
	idx = virtio_modern16_to_cpu(vdev, vq_tx->avail->idx);
	id = (idx * 2) % vq_tx->size;

	virtio_free_desc(vq_tx, id, vdev->features);
	virtio_free_desc(vq_tx, id + 1, vdev->features);

	/* Set up virtqueue descriptor for header */
	virtio_fill_desc(vq_tx, id, vdev->features, (uint64_t)nethdr,
			 net_hdr_size, VRING_DESC_F_NEXT, id + 1);

	/* Set up virtqueue descriptor for data */
	virtio_fill_desc(vq_tx, id + 1, vdev->features, (uint64_t)buf, len, 0, 0);

	vq_tx->avail->ring[idx % vq_tx->size] = virtio_cpu_to_modern16(vdev, id);
	sync();
	vq_tx->avail->idx = virtio_cpu_to_modern16(vdev, idx + 1);
	sync();

	/* Tell HV that TX queue is ready */
	virtio_queue_notify(vdev, VQ_TX);

	return len;
}


/**
 * Receive a packet
 */
static int virtionet_receive(struct virtio_net *vnet, char *buf, int maxlen)
{
	uint32_t len = 0;
	uint32_t id, idx;
	uint16_t avail_idx;
	struct virtio_device *vdev = &vnet->vdev;
	struct vqs *vq_rx = &vnet->vdev.vq[VQ_RX];

	idx = virtio_modern16_to_cpu(vdev, vq_rx->used->idx);

	if (last_rx_idx == idx) {
		/* Nothing received yet */
		return 0;
	}

	id = (virtio_modern32_to_cpu(vdev, vq_rx->used->ring[last_rx_idx % vq_rx->size].id) + 1)
		% vq_rx->size;
	len = virtio_modern32_to_cpu(vdev, vq_rx->used->ring[last_rx_idx % vq_rx->size].len)
		- net_hdr_size;
	dprintf("virtionet_receive() last_rx_idx=%i, vq_rx->used->idx=%i,"
		" id=%i len=%i\n", last_rx_idx, vq_rx->used->idx, id, len);

	if (len > (uint32_t)maxlen) {
		printf("virtio-net: Receive buffer not big enough!\n");
		len = maxlen;
	}

#if 0
	/* Dump packet */
	printf("\n");
	int i;
	for (i=0; i<64; i++) {
		printf(" %02x", *(uint8_t*)(vq_rx->desc[id].addr+i));
		if ((i%16)==15)
			printf("\n");
	}
	prinfk("\n");
#endif

	/* Copy data to destination buffer */
	memcpy(buf, virtio_desc_addr(vdev, VQ_RX, id), len);

	/* Move indices to next entries */
	last_rx_idx = last_rx_idx + 1;

	avail_idx = virtio_modern16_to_cpu(vdev, vq_rx->avail->idx);
	vq_rx->avail->ring[avail_idx % vq_rx->size] = virtio_cpu_to_modern16(vdev, id - 1);
	sync();
	vq_rx->avail->idx = virtio_cpu_to_modern16(vdev, avail_idx + 1);

	/* Tell HV that RX queue entry is ready */
	virtio_queue_notify(vdev, VQ_RX);

	return len;
}

struct virtio_net *virtionet_open(struct virtio_device *dev)
{
	struct virtio_net *vnet;

	vnet = SLOF_alloc_mem(sizeof(*vnet));
	if (!vnet) {
		printf("Unable to allocate virtio-net driver\n");
		return NULL;
	}

	vnet->driver.running = 0;

	if (virtionet_init_pci(vnet, dev))
		goto FAIL;

	if (virtionet_init(vnet))
		goto FAIL;

	return vnet;

FAIL:
	SLOF_free_mem(vnet, sizeof(*vnet));
	return NULL;
}

void virtionet_close(struct virtio_net *vnet)
{
	if (vnet) {
		virtionet_term(vnet);
		SLOF_free_mem(vnet, sizeof(*vnet));
	}
}

int virtionet_read(struct virtio_net *vnet, char *buf, int len)
{
	if (vnet && buf)
		return virtionet_receive(vnet, buf, len);
	return -1;
}

int virtionet_write(struct virtio_net *vnet, char *buf, int len)
{
	if (vnet && buf)
		return virtionet_xmit(vnet, buf, len);
	return -1;
}
