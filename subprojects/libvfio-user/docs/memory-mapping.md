# Accessing memory with libvfio-user

A vfio-user client informs the server of its memory regions available for
access. Each DMA region might correspond, for example, to a guest VM's memory
region.

A server that wishes to access such client-shared memory must call:

```
vfu_setup_device_dma(..., register_cb, unregister_cb);
```

during initialization. The two callbacks are invoked when client regions are
added and removed.

## Memory region callbacks

For either callback, the following information is given:

```
/*
 * Info for a guest DMA region.  @iova is always valid; the other parameters
 * will only be set if the guest DMA region is mappable.
 *
 * @iova: guest DMA range. This is the guest physical range (as we don't
 *   support vIOMMU) that the guest registers for DMA, via a VFIO_USER_DMA_MAP
 *   message, and is the address space used as input to vfu_addr_to_sgl().
 * @vaddr: if the range is mapped into this process, this is the virtual address
 *   of the start of the region.
 * @mapping: if @vaddr is non-NULL, this range represents the actual range
 *   mmap()ed into the process. This might be (large) page aligned, and
 *   therefore be different from @vaddr + @iova.iov_len.
 * @page_size: if @vaddr is non-NULL, page size of the mapping (e.g. 2MB)
 * @prot: if @vaddr is non-NULL, protection settings of the mapping as per
 *   mmap(2)
 *
 * For a real example, using the gpio sample server, and a qemu configured to
 * use huge pages and share its memory:
 *
 * gpio: mapped DMA region iova=[0xf0000-0x10000000) vaddr=0x2aaaab0f0000
 * page_size=0x200000 mapping=[0x2aaaab000000-0x2aaabb000000)
 *
 *     0xf0000                    0x10000000
 *     |                                   |
 *     v                                   v
 *     +-----------------------------------+
 *     | Guest IOVA (DMA) space            |
 *  +--+-----------------------------------+--+
 *  |  |                                   |  |
 *  |  +-----------------------------------+  |
 *  |  ^ libvfio-user server address space    |
 *  +--|--------------------------------------+
 *  ^ vaddr=0x2aaaab0f0000                    ^
 *  |                                         |
 *  0x2aaaab000000               0x2aaabb000000
 *
 * This region can be directly accessed at 0x2aaaab0f0000, but the underlying
 * large page mapping is in the range [0x2aaaab000000-0x2aaabb000000).
 */
typedef struct vfu_dma_info {
    struct iovec iova;
    void *vaddr;
    struct iovec mapping;
    size_t page_size;
    uint32_t prot;
} vfu_dma_info_t;
```

The remove callback is expected to arrange for all usage of the memory region to
be stopped (or to return `EBUSY`, to trigger quiescence instead), including all
needed `vfu_sgl_put()` calls for SGLs that are within the memory region.

## Accessing mapped regions

As described above, `libvfio-user` may map remote client memory into the
process's address space, allowing direct access. To access these mappings, the
caller must first construct an SGL corresponding to the IOVA start and length:

```
dma_sg_t *sgl = calloc(2, dma_sg_size());

vfu_addr_to_sgl(vfu_ctx, iova, len, sgl, 2, PROT_READ | PROT_WRITE);
```

For example, the device may have received an IOVA from a write to PCI config
space. Due to guest memory topology, certain accesses may not fit in a single
scatter-gather entry, therefore this API allows for an array of SGs to be
provided as necessary.

If `PROT_WRITE` is given, the library presumes that the user may write to the
SGL mappings at any time; this is used for dirty page tracking.

### `iovec` construction

Next, a user wishing to directly access shared memory should convert the SGL
into an array of iovecs:

```
vfu_sgl_get(vfu_ctx, sgl, iovec, cnt, 0);
```

The caller should provide an array of `struct iovec` that correspond with the
number of SGL entries. After this call, `iovec.iov_base` is the virtual address
with which the range may be directly read from (or written to).

### Releasing SGL access

When a particular iovec is finished with, the user can call:

```
vfu_sgl_put(vfu_ctx, sgl, iovec, cnt);
```

After this call, the SGL must not be accessed via the iovec VAs. As mentioned
above, if the SGL was writeable, this will automatically mark all pages within
the SGL as dirty for live migration purposes.

### Dirty page handling

In some cases, such as when entering stop-and-copy state in live migration, it
can be useful to mark an SGL as dirty without releasing it. This can be done via
the call:

```
vfu_sgl_mark_dirty(vfu_ctx, sgl, cnt);
```

## Non-mapped region access

Clients are not required to share the memory mapping.  If this is *not* the
case, then the server may only read or write the region the slower way:


```
...
vfu_addr_to_sgl(ctx, iova, len, sg, 1, PROT_READ);

vfu_sgl_read(ctx, sg, 1, &buf);
```
