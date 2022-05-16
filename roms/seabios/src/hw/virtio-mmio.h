#ifndef _VIRTIO_MMIO_H
#define _VIRTIO_MMIO_H

struct vp_device;

typedef struct virtio_mmio_cfg {
    u32 magic;
    u32 version;
    u32 device_id;
    u32 vendor_id;

    u32 device_feature;
    u32 device_feature_select;
    u32 res_18;
    u32 res_1c;

    u32 guest_feature;
    u32 guest_feature_select;
    u32 legacy_guest_page_size;
    u32 res_2c;

    u32 queue_select;
    u32 queue_num_max;
    u32 queue_num;
    u32 legacy_queue_align;

    u32 legacy_queue_pfn;
    u32 queue_ready;
    u32 res_48;
    u32 res_4c;

    u32 queue_notify;
    u32 res_54;
    u32 res_58;
    u32 res_5c;

    u32 irq_status;
    u32 irq_ack;
    u32 res_68;
    u32 res_6c;

    u32 device_status;
    u32 res_74;
    u32 res_78;
    u32 res_7c;

    u32 queue_desc_lo;
    u32 queue_desc_hi;
    u32 res_88;
    u32 res_8c;

    u32 queue_driver_lo;
    u32 queue_driver_hi;
    u32 res_98;
    u32 res_9c;

    u32 queue_device_lo;
    u32 queue_device_hi;
    u32 res_a8;
    u32 shm_sel;

    u32 shmem_len_lo;
    u32 shmem_len_hi;
    u32 shmem_base_lo;
    u32 shmem_base_hi;

    u32 res_c0_f7[14];

    u32 res_f8;
    u32 config_generation;
} virtio_mmio_cfg;

void virtio_mmio_setup_acpi(void);
void virtio_mmio_setup_one(u64 mmio);
void vp_init_mmio(struct vp_device *vp, void *mmio);

#endif /* _VIRTIO_MMIO_H */
