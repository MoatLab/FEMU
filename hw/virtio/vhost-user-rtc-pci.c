/*
 * Vhost-user RTC virtio device PCI glue
 *
 * Copyright (c) 2025 Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
 * Copyright 2026 Panasonic Automotive Systems Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/virtio/vhost-user-rtc.h"
#include "hw/virtio/virtio-pci.h"

struct VHostUserRTCPCI {
    VirtIOPCIProxy parent_obj;
    VHostUserRTC vdev;
};

typedef struct VHostUserRTCPCI VHostUserRTCPCI;

#define TYPE_VHOST_USER_RTC_PCI "vhost-user-rtc-pci-base"

DECLARE_INSTANCE_CHECKER(VHostUserRTCPCI, VHOST_USER_RTC_PCI,
                         TYPE_VHOST_USER_RTC_PCI)

static void vhost_user_rtc_pci_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VHostUserRTCPCI *dev = VHOST_USER_RTC_PCI(vpci_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);

    vpci_dev->nvectors = 1;

    qdev_realize(vdev, BUS(&vpci_dev->bus), errp);
}

static void vhost_user_rtc_pci_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);
    k->realize = vhost_user_rtc_pci_realize;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    pcidev_k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    pcidev_k->device_id = 0; /* Set by virtio-pci based on virtio id */
    pcidev_k->revision = 0x00;
    pcidev_k->class_id = PCI_CLASS_SYSTEM_RTC;
}

static void vhost_user_rtc_pci_instance_init(Object *obj)
{
    VHostUserRTCPCI *dev = VHOST_USER_RTC_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VHOST_USER_RTC);
}

static const VirtioPCIDeviceTypeInfo vhost_user_rtc_pci_info = {
    .base_name = TYPE_VHOST_USER_RTC_PCI,
    .non_transitional_name = "vhost-user-rtc-pci",
    .instance_size = sizeof(VHostUserRTCPCI),
    .instance_init = vhost_user_rtc_pci_instance_init,
    .class_init = vhost_user_rtc_pci_class_init,
};

static void vhost_user_rtc_pci_register(void)
{
    virtio_pci_types_register(&vhost_user_rtc_pci_info);
}

type_init(vhost_user_rtc_pci_register);
