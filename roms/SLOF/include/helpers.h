/******************************************************************************
 * Copyright (c) 2007, 2012, 2013 IBM Corporation
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
 * USB SLOF Prototypes
 */

#ifndef _USB_SLOF_H
#define _USB_SLOF_H

#include <stdint.h>

extern uint32_t SLOF_GetTimer(void);
extern void SLOF_msleep(uint32_t time);
extern void SLOF_usleep(uint32_t time);
extern void *SLOF_dma_alloc(long size);
extern void SLOF_dma_free(void *virt, long size);
extern void *SLOF_alloc_mem(long size);
extern void *SLOF_alloc_mem_aligned(long size, long align);
extern void SLOF_free_mem(void *addr, long size);
extern long SLOF_dma_map_in(void *virt, long size, int cacheable);
extern void SLOF_dma_map_out(long phys, void *virt, long size);
extern long SLOF_pci_config_read32(long offset);
extern long SLOF_pci_config_read16(long offset);
extern long SLOF_pci_config_read8(long offset);
extern void SLOF_pci_config_write32(long offset, long value);
extern void SLOF_pci_config_write16(long offset, long value);
extern void SLOF_pci_config_write8(long offset, long value);
extern void *SLOF_translate_my_address(void *addr);
extern int write_mm_log(char *data, unsigned int len, unsigned short type);
extern void SLOF_set_chosen_int(const char *s, long val);
extern void SLOF_set_chosen_bytes(const char *s, const char *addr, size_t size);
extern void SLOF_encode_bootp_response(void *addr, size_t size);
extern void SLOF_encode_dhcp_response(void *addr, size_t size);
extern int SLOF_get_property(const char *node, const char *propname,
                             char **addr, int *len);
extern int SLOF_get_keystroke(void);
extern void SLOF_reset(void);
extern unsigned long SLOF_get_vtpm_unit(void);

#define offset_of(type, member) ((long) &((type *)0)->member)
#define container_of(ptr, type, member) ({                      \
			const typeof(((type *)0)->member)* struct_ptr = (ptr); \
			(type *)((char *)struct_ptr - offset_of(type, member)); })
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define ROUNDUP(x,v) ((((x) + ((v) - 1)) / (v)) * (v))
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

#endif
