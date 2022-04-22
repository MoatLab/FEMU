/* SPDX-License-Identifier: GPL-2.0+
 *
 * Copyright (C) 2016  Nexell Co., Ltd.
 *
 * Author: junghyun, kim <jhkim@nexell.co.kr>
 */

#ifndef _NX__DISPLAY_DEV_H_
#define _NX__DISPLAY_DEV_H_

#if defined CONFIG_VIDEO || defined CONFIG_DM_VIDEO
#include <video_fb.h>
#elif defined CONFIG_LCD
#include <lcd.h>
#endif

struct nx_display_dev {
#if defined CONFIG_VIDEO || defined CONFIG_DM_VIDEO
	GraphicDevice graphic_device;
#elif defined CONFIG_LCD
	vidinfo_t *panel_info;
#endif
	unsigned long base;
	int module;
	struct dp_sync_info sync;
	struct dp_ctrl_info ctrl;
	struct dp_plane_top top;
	struct dp_plane_info planes[DP_PLANS_NUM];
	int dev_type;
	void *device;
	struct dp_plane_info *fb_plane;
	unsigned int depth;	/* byte per pixel */
	unsigned int fb_addr;
	unsigned int fb_size;
};

#endif
