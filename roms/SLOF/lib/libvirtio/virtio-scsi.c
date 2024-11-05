/******************************************************************************
 * Copyright (c) 2012 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <cpu.h>
#include <helpers.h>
#include "virtio.h"
#include "virtio-internal.h"
#include "virtio-scsi.h"

int virtioscsi_send(struct virtio_device *dev,
		    struct virtio_scsi_req_cmd *req,
		    struct virtio_scsi_resp_cmd *resp,
		    int is_read, void *buf, uint64_t buf_len)
{

	volatile uint16_t *current_used_idx;
	uint16_t last_used_idx, avail_idx;
	int id;
	uint32_t time;
	struct vqs *vq = &dev->vq[VIRTIO_SCSI_REQUEST_VQ];

	avail_idx = virtio_modern16_to_cpu(dev, vq->avail->idx);

	last_used_idx = vq->used->idx;
	current_used_idx = &vq->used->idx;

	/* Determine descriptor index */
	id = (avail_idx * 3) % vq->size;
	virtio_fill_desc(vq, id, dev->features, (uint64_t)req, sizeof(*req), VRING_DESC_F_NEXT,
			 id + 1);

	if (buf == NULL || buf_len == 0) {
		/* Set up descriptor for response information */
		virtio_fill_desc(vq, id + 1, dev->features,
				 (uint64_t)resp, sizeof(*resp),
				 VRING_DESC_F_WRITE, 0);
	} else if (is_read) {
		/* Set up descriptor for response information */
		virtio_fill_desc(vq, id + 1, dev->features,
				 (uint64_t)resp, sizeof(*resp),
				 VRING_DESC_F_NEXT | VRING_DESC_F_WRITE,
				 id + 2);
		/* Set up virtqueue descriptor for data from device */
		virtio_fill_desc(vq, id + 2, dev->features,
				 (uint64_t)buf, buf_len, VRING_DESC_F_WRITE, 0);
	} else {
		/* Set up virtqueue descriptor for data to device */
		virtio_fill_desc(vq, id + 1, dev->features,
				 (uint64_t)buf, buf_len, VRING_DESC_F_NEXT,
				 id + 2);
		/* Set up descriptor for response information */
		virtio_fill_desc(vq, id + 2, dev->features,
				 (uint64_t)resp, sizeof(*resp),
				 VRING_DESC_F_WRITE, 0);
	}

	vq->avail->ring[avail_idx % vq->size] = virtio_cpu_to_modern16(dev, id);
	mb();
	vq->avail->idx = virtio_cpu_to_modern16(dev, avail_idx + 1);

	/* Tell HV that the vq is ready */
	virtio_queue_notify(dev, VIRTIO_SCSI_REQUEST_VQ);

	/* Wait for host to consume the descriptor */
	time = SLOF_GetTimer() + VIRTIO_TIMEOUT;
	while (*current_used_idx == last_used_idx) {
		// do something better
		mb();
		if (time < SLOF_GetTimer())
			break;
	}

	virtio_free_desc(vq, id, dev->features);
	virtio_free_desc(vq, id + 1, dev->features);
	if (!(buf == NULL || buf_len == 0))
		virtio_free_desc(vq, id + 2, dev->features);

	return 0;
}

/**
 * Initialize virtio-block device.
 * @param  dev  pointer to virtio device information
 */
int virtioscsi_init(struct virtio_device *dev)
{
	struct vqs *vq_ctrl, *vq_event, *vq_request;
	int status = VIRTIO_STAT_ACKNOWLEDGE;

	/* Reset device */
	// XXX That will clear the virtq base. We need to move
	//     initializing it to here anyway
	//
	//     virtio_reset_device(dev);

	/* Acknowledge device. */
	virtio_set_status(dev, status);

	/* Tell HV that we know how to drive the device. */
	status |= VIRTIO_STAT_DRIVER;
	virtio_set_status(dev, status);

	/* Device specific setup - we do not support special features right now */
	if (dev->features & VIRTIO_F_VERSION_1) {
		if (virtio_negotiate_guest_features(dev, VIRTIO_F_VERSION_1))
			goto dev_error;
		virtio_get_status(dev, &status);
	} else {
		virtio_set_guest_features(dev, 0);
	}

	vq_ctrl = virtio_queue_init_vq(dev, VIRTIO_SCSI_CONTROL_VQ);
	vq_event = virtio_queue_init_vq(dev, VIRTIO_SCSI_EVENT_VQ);
	vq_request = virtio_queue_init_vq(dev, VIRTIO_SCSI_REQUEST_VQ);
	if (!vq_ctrl || !vq_event || !vq_request)
		goto dev_error;

	/* Tell HV that setup succeeded */
	status |= VIRTIO_STAT_DRIVER_OK;
	virtio_set_status(dev, status);

	return 0;
dev_error:
	printf("%s: failed\n", __func__);
	status |= VIRTIO_STAT_FAILED;
	virtio_set_status(dev, status);
	return -1;
}

/**
 * Shutdown the virtio-block device.
 * @param  dev  pointer to virtio device information
 */
void virtioscsi_shutdown(struct virtio_device *dev)
{
	/* Quiesce device */
	virtio_set_status(dev, VIRTIO_STAT_FAILED);

	/* Reset device */
	virtio_reset_device(dev);
}
