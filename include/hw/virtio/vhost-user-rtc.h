/*
 * Vhost-user RTC virtio device
 *
 * Copyright (c) 2025 Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
 * Copyright 2026 Panasonic Automotive Systems Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_VHOST_USER_RTC_H
#define QEMU_VHOST_USER_RTC_H

#include "hw/virtio/vhost-user-base.h"

#define TYPE_VHOST_USER_RTC "vhost-user-rtc"
OBJECT_DECLARE_SIMPLE_TYPE(VHostUserRTC, VHOST_USER_RTC)

struct VHostUserRTC {
    VHostUserBase parent_obj;
};

#endif /* QEMU_VHOST_USER_RTC_H */
