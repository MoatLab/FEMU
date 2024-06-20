/*
 * common header for vfio based device assignment support
 *
 * Copyright Red Hat, Inc. 2012
 *
 * Authors:
 *  Alex Williamson <alex.williamson@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Based on qemu-kvm device-assignment:
 *  Adapted for KVM by Qumranet.
 *  Copyright (c) 2007, Neocleus, Alex Novik (alex@neocleus.com)
 *  Copyright (c) 2007, Neocleus, Guy Zana (guy@neocleus.com)
 *  Copyright (C) 2008, Qumranet, Amit Shah (amit.shah@qumranet.com)
 *  Copyright (C) 2008, Red Hat, Amit Shah (amit.shah@redhat.com)
 *  Copyright (C) 2008, IBM, Muli Ben-Yehuda (muli@il.ibm.com)
 */

#ifndef HW_VFIO_VFIO_COMMON_H
#define HW_VFIO_VFIO_COMMON_H

#include "exec/memory.h"
#include "qemu/queue.h"
#include "qemu/notify.h"
#include "ui/console.h"
#include "hw/display/ramfb.h"
#ifdef CONFIG_LINUX
#include <linux/vfio.h>
#endif
#include "sysemu/sysemu.h"
#include "hw/vfio/vfio-container-base.h"

#define VFIO_MSG_PREFIX "vfio %s: "

enum {
    VFIO_DEVICE_TYPE_PCI = 0,
    VFIO_DEVICE_TYPE_PLATFORM = 1,
    VFIO_DEVICE_TYPE_CCW = 2,
    VFIO_DEVICE_TYPE_AP = 3,
};

typedef struct VFIOMmap {
    MemoryRegion mem;
    void *mmap;
    off_t offset;
    size_t size;
} VFIOMmap;

typedef struct VFIORegion {
    struct VFIODevice *vbasedev;
    off_t fd_offset; /* offset of region within device fd */
    MemoryRegion *mem; /* slow, read/write access */
    size_t size;
    uint32_t flags; /* VFIO region flags (rd/wr/mmap) */
    uint32_t nr_mmaps;
    VFIOMmap *mmaps;
    uint8_t nr; /* cache the region number for debug */
} VFIORegion;

typedef struct VFIOMigration {
    struct VFIODevice *vbasedev;
    VMChangeStateEntry *vm_state;
    NotifierWithReturn migration_state;
    uint32_t device_state;
    int data_fd;
    void *data_buffer;
    size_t data_buffer_size;
    uint64_t mig_flags;
    uint64_t precopy_init_size;
    uint64_t precopy_dirty_size;
    bool initial_data_sent;
} VFIOMigration;

struct VFIOGroup;

typedef struct VFIOContainer {
    VFIOContainerBase bcontainer;
    int fd; /* /dev/vfio/vfio, empowered by the attached groups */
    unsigned iommu_type;
    QLIST_HEAD(, VFIOGroup) group_list;
} VFIOContainer;

typedef struct VFIOHostDMAWindow {
    hwaddr min_iova;
    hwaddr max_iova;
    uint64_t iova_pgsizes;
    QLIST_ENTRY(VFIOHostDMAWindow) hostwin_next;
} VFIOHostDMAWindow;

typedef struct IOMMUFDBackend IOMMUFDBackend;

typedef struct VFIOIOMMUFDContainer {
    VFIOContainerBase bcontainer;
    IOMMUFDBackend *be;
    uint32_t ioas_id;
} VFIOIOMMUFDContainer;

typedef struct VFIODeviceOps VFIODeviceOps;

typedef struct VFIODevice {
    QLIST_ENTRY(VFIODevice) next;
    QLIST_ENTRY(VFIODevice) container_next;
    QLIST_ENTRY(VFIODevice) global_next;
    struct VFIOGroup *group;
    VFIOContainerBase *bcontainer;
    char *sysfsdev;
    char *name;
    DeviceState *dev;
    int fd;
    int type;
    bool reset_works;
    bool needs_reset;
    bool no_mmap;
    bool ram_block_discard_allowed;
    OnOffAuto enable_migration;
    VFIODeviceOps *ops;
    unsigned int num_irqs;
    unsigned int num_regions;
    unsigned int flags;
    VFIOMigration *migration;
    Error *migration_blocker;
    OnOffAuto pre_copy_dirty_page_tracking;
    bool dirty_pages_supported;
    bool dirty_tracking;
    int devid;
    IOMMUFDBackend *iommufd;
} VFIODevice;

struct VFIODeviceOps {
    void (*vfio_compute_needs_reset)(VFIODevice *vdev);
    int (*vfio_hot_reset_multi)(VFIODevice *vdev);
    void (*vfio_eoi)(VFIODevice *vdev);
    Object *(*vfio_get_object)(VFIODevice *vdev);
    void (*vfio_save_config)(VFIODevice *vdev, QEMUFile *f);
    int (*vfio_load_config)(VFIODevice *vdev, QEMUFile *f);
};

typedef struct VFIOGroup {
    int fd;
    int groupid;
    VFIOContainer *container;
    QLIST_HEAD(, VFIODevice) device_list;
    QLIST_ENTRY(VFIOGroup) next;
    QLIST_ENTRY(VFIOGroup) container_next;
    bool ram_block_discard_allowed;
} VFIOGroup;

typedef struct VFIODMABuf {
    QemuDmaBuf buf;
    uint32_t pos_x, pos_y, pos_updates;
    uint32_t hot_x, hot_y, hot_updates;
    int dmabuf_id;
    QTAILQ_ENTRY(VFIODMABuf) next;
} VFIODMABuf;

typedef struct VFIODisplay {
    QemuConsole *con;
    RAMFBState *ramfb;
    struct vfio_region_info *edid_info;
    struct vfio_region_gfx_edid *edid_regs;
    uint8_t *edid_blob;
    QEMUTimer *edid_link_timer;
    struct {
        VFIORegion buffer;
        DisplaySurface *surface;
    } region;
    struct {
        QTAILQ_HEAD(, VFIODMABuf) bufs;
        VFIODMABuf *primary;
        VFIODMABuf *cursor;
    } dmabuf;
} VFIODisplay;

VFIOAddressSpace *vfio_get_address_space(AddressSpace *as);
void vfio_put_address_space(VFIOAddressSpace *space);

/* SPAPR specific */
int vfio_spapr_container_init(VFIOContainer *container, Error **errp);
void vfio_spapr_container_deinit(VFIOContainer *container);

void vfio_disable_irqindex(VFIODevice *vbasedev, int index);
void vfio_unmask_single_irqindex(VFIODevice *vbasedev, int index);
void vfio_mask_single_irqindex(VFIODevice *vbasedev, int index);
int vfio_set_irq_signaling(VFIODevice *vbasedev, int index, int subindex,
                           int action, int fd, Error **errp);
void vfio_region_write(void *opaque, hwaddr addr,
                           uint64_t data, unsigned size);
uint64_t vfio_region_read(void *opaque,
                          hwaddr addr, unsigned size);
int vfio_region_setup(Object *obj, VFIODevice *vbasedev, VFIORegion *region,
                      int index, const char *name);
int vfio_region_mmap(VFIORegion *region);
void vfio_region_mmaps_set_enabled(VFIORegion *region, bool enabled);
void vfio_region_unmap(VFIORegion *region);
void vfio_region_exit(VFIORegion *region);
void vfio_region_finalize(VFIORegion *region);
void vfio_reset_handler(void *opaque);
struct vfio_device_info *vfio_get_device_info(int fd);
int vfio_attach_device(char *name, VFIODevice *vbasedev,
                       AddressSpace *as, Error **errp);
void vfio_detach_device(VFIODevice *vbasedev);

int vfio_kvm_device_add_fd(int fd, Error **errp);
int vfio_kvm_device_del_fd(int fd, Error **errp);

int vfio_cpr_register_container(VFIOContainerBase *bcontainer, Error **errp);
void vfio_cpr_unregister_container(VFIOContainerBase *bcontainer);

extern const MemoryRegionOps vfio_region_ops;
typedef QLIST_HEAD(VFIOGroupList, VFIOGroup) VFIOGroupList;
typedef QLIST_HEAD(VFIODeviceList, VFIODevice) VFIODeviceList;
extern VFIOGroupList vfio_group_list;
extern VFIODeviceList vfio_device_list;
extern const MemoryListener vfio_memory_listener;
extern int vfio_kvm_device_fd;

bool vfio_mig_active(void);
int vfio_block_multiple_devices_migration(VFIODevice *vbasedev, Error **errp);
void vfio_unblock_multiple_devices_migration(void);
bool vfio_viommu_preset(VFIODevice *vbasedev);
int64_t vfio_mig_bytes_transferred(void);
void vfio_reset_bytes_transferred(void);
bool vfio_device_state_is_running(VFIODevice *vbasedev);
bool vfio_device_state_is_precopy(VFIODevice *vbasedev);

#ifdef CONFIG_LINUX
int vfio_get_region_info(VFIODevice *vbasedev, int index,
                         struct vfio_region_info **info);
int vfio_get_dev_region_info(VFIODevice *vbasedev, uint32_t type,
                             uint32_t subtype, struct vfio_region_info **info);
bool vfio_has_region_cap(VFIODevice *vbasedev, int region, uint16_t cap_type);
struct vfio_info_cap_header *
vfio_get_region_info_cap(struct vfio_region_info *info, uint16_t id);
bool vfio_get_info_dma_avail(struct vfio_iommu_type1_info *info,
                             unsigned int *avail);
struct vfio_info_cap_header *
vfio_get_device_info_cap(struct vfio_device_info *info, uint16_t id);
struct vfio_info_cap_header *
vfio_get_cap(void *ptr, uint32_t cap_offset, uint16_t id);
#endif

bool vfio_migration_realize(VFIODevice *vbasedev, Error **errp);
void vfio_migration_exit(VFIODevice *vbasedev);

int vfio_bitmap_alloc(VFIOBitmap *vbmap, hwaddr size);
bool
vfio_devices_all_running_and_mig_active(const VFIOContainerBase *bcontainer);
bool
vfio_devices_all_device_dirty_tracking(const VFIOContainerBase *bcontainer);
int vfio_devices_query_dirty_bitmap(const VFIOContainerBase *bcontainer,
                                    VFIOBitmap *vbmap, hwaddr iova,
                                    hwaddr size);
int vfio_get_dirty_bitmap(const VFIOContainerBase *bcontainer, uint64_t iova,
                          uint64_t size, ram_addr_t ram_addr);

/* Returns 0 on success, or a negative errno. */
int vfio_device_get_name(VFIODevice *vbasedev, Error **errp);
void vfio_device_set_fd(VFIODevice *vbasedev, const char *str, Error **errp);
void vfio_device_init(VFIODevice *vbasedev, int type, VFIODeviceOps *ops,
                      DeviceState *dev, bool ram_discard);
#endif /* HW_VFIO_VFIO_COMMON_H */
