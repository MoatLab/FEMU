/******************************************************************************
 * Copyright (c) 2016 IBM Corporation
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
 * Virtio serial device definitions.
 * See Virtio 1.0 - 5.3 Console Device, for details
 */
#include <stdio.h>
#include <string.h>
#include <cpu.h>
#include <helpers.h>
#include <byteorder.h>
#include "virtio.h"
#include "virtio-serial.h"
#include "virtio-internal.h"

#define DRIVER_FEATURE_SUPPORT  VIRTIO_F_VERSION_1
#define RX_ELEM_SIZE            4
#define RX_NUM_ELEMS            128

#define RX_Q 0
#define TX_Q 1

static uint16_t last_rx_idx;	/* Last index in RX "used" ring */

int virtio_serial_init(struct virtio_device *dev)
{
	struct vqs *vq_rx, *vq_tx;
	int status = VIRTIO_STAT_ACKNOWLEDGE;
	int i;

	/* Reset device */
	virtio_reset_device(dev);

	/* Acknowledge device. */
	virtio_set_status(dev, status);

	/* Tell HV that we know how to drive the device. */
	status |= VIRTIO_STAT_DRIVER;
	virtio_set_status(dev, status);

	if (dev->features & VIRTIO_F_VERSION_1) {
		/* Negotiate features and sets FEATURES_OK if successful */
		if (virtio_negotiate_guest_features(dev, DRIVER_FEATURE_SUPPORT))
			goto dev_error;

		virtio_get_status(dev, &status);
	}

	vq_rx = virtio_queue_init_vq(dev, RX_Q);
	if (!vq_rx)
		goto dev_error;

	/* Allocate memory for multiple receive buffers */
	vq_rx->buf_mem = SLOF_alloc_mem(RX_ELEM_SIZE * RX_NUM_ELEMS);
	if (!vq_rx->buf_mem) {
		printf("virtio-serial: Failed to allocate buffers!\n");
		goto dev_error;
	}

	/* Prepare receive buffer queue */
	for (i = 0; i < RX_NUM_ELEMS; i++) {
		uint64_t addr = (uint64_t)vq_rx->buf_mem + i * RX_ELEM_SIZE;

		/* Descriptor for data: */
		virtio_fill_desc(vq_rx, i, dev->features, addr, 1, VRING_DESC_F_WRITE, 0);
		vq_rx->avail->ring[i] = virtio_cpu_to_modern16(dev, i);
	}
	vq_rx->avail->idx = virtio_cpu_to_modern16(dev, RX_NUM_ELEMS);
	sync();

	last_rx_idx = virtio_modern16_to_cpu(dev, vq_rx->used->idx);

	vq_tx = virtio_queue_init_vq(dev, TX_Q);
	if (!vq_tx)
		goto dev_error;


	/* Tell HV that setup succeeded */
	status |= VIRTIO_STAT_DRIVER_OK;
	virtio_set_status(dev, status);

	return 1;
 dev_error:
	printf("%s: failed\n", __func__);
	status |= VIRTIO_STAT_FAILED;
	virtio_set_status(dev, status);
	return 0;
}

void virtio_serial_shutdown(struct virtio_device *dev)
{
	/* Quiesce device */
	virtio_set_status(dev, VIRTIO_STAT_FAILED);

	/* Stop queues */
	virtio_queue_term_vq(dev, &dev->vq[TX_Q], TX_Q);
	virtio_queue_term_vq(dev, &dev->vq[RX_Q], RX_Q);

	/* Reset device */
	virtio_reset_device(dev);
}

int virtio_serial_putchar(struct virtio_device *dev, char c)
{
	int id, ret;
	uint32_t time;
	volatile uint16_t *current_used_idx;
	uint16_t last_used_idx, avail_idx;
	struct vqs *vq = &dev->vq[TX_Q];

	if (!vq->desc)
		return 0;

	avail_idx = virtio_modern16_to_cpu(dev, vq->avail->idx);

	last_used_idx = vq->used->idx;
	current_used_idx = &vq->used->idx;

	/* Determine descriptor index */
	id = avail_idx % vq->size;

	/* Set up virtqueue descriptor for header */
	virtio_fill_desc(vq, id, dev->features, (uint64_t)&c, 1, 0, 0);

	vq->avail->ring[avail_idx % vq->size] = virtio_cpu_to_modern16 (dev, id);
	mb();
	vq->avail->idx = virtio_cpu_to_modern16(dev, avail_idx + 1);

	/* Tell HV that the queue is ready */
	virtio_queue_notify(dev, TX_Q);

	/* Wait for host to consume the descriptor */
	ret = 1;
	time = SLOF_GetTimer() + VIRTIO_TIMEOUT;
	while (*current_used_idx == last_used_idx) {
		// do something better
		mb();
		if (time < SLOF_GetTimer()) {
			printf("virtio_serial_putchar failed! \n");
			ret = 0;
			break;
		}
	}

	virtio_free_desc(vq, id, dev->features);

	return ret;
}

char virtio_serial_getchar(struct virtio_device *dev)
{
	int id, idx;
	char buf[RX_NUM_ELEMS] = {0};
	uint16_t avail_idx;
	struct vqs *vq_rx = &dev->vq[RX_Q];

	idx = virtio_modern16_to_cpu(dev, vq_rx->used->idx);
	if (last_rx_idx == idx) {
		/* Nothing received yet */
		return 0;
	}

	id = (virtio_modern32_to_cpu(dev, vq_rx->used->ring[last_rx_idx % vq_rx->size].id) + 1)
		% vq_rx->size;

	/* Copy data to destination buffer */
	memcpy(buf, virtio_desc_addr(dev, RX_Q, id - 1), RX_ELEM_SIZE);

	/* Move indices to next entries */
	last_rx_idx = last_rx_idx + 1;

	avail_idx = virtio_modern16_to_cpu(dev, vq_rx->avail->idx);
	vq_rx->avail->ring[avail_idx % vq_rx->size] = virtio_cpu_to_modern16(dev, id - 1);
	sync();
	vq_rx->avail->idx = virtio_cpu_to_modern16(dev, avail_idx + 1);
	sync();

	/* Tell HV that RX queue entry is ready */
	virtio_queue_notify(dev, RX_Q);

	return buf[0];
}

int virtio_serial_haschar(struct virtio_device *dev)
{
	struct vqs *vq_rx = &dev->vq[RX_Q];

	if (last_rx_idx == virtio_modern16_to_cpu(dev, vq_rx->used->idx))
		return 0;
	else
		return 1;
}
