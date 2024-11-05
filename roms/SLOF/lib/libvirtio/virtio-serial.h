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

#ifndef _VIRTIO_SERIAL_H
#define _VIRTIO_SERIAL_H

extern int virtio_serial_init(struct virtio_device *dev);
extern void virtio_serial_shutdown(struct virtio_device *dev);
extern int virtio_serial_putchar(struct virtio_device *dev, char c);
extern char virtio_serial_getchar(struct virtio_device *dev);
extern int virtio_serial_haschar(struct virtio_device *dev);

#endif  /* _VIRTIO_SERIAL_H */
