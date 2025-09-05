/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"

/* Definitions for Runtime Memory Operations */
#define LIBSPDM_RT_PAGE_SIZE   0x40
#define LIBSPDM_RT_PAGE_MASK   0x3F
#define LIBSPDM_RT_PAGE_SHIFT  6

#define LIBSPDM_RT_SIZE_TO_PAGES(a)  (((a) >> LIBSPDM_RT_PAGE_SHIFT) + \
                                      (((a) & LIBSPDM_RT_PAGE_MASK) ? 1 : 0))
#define LIBSPDM_RT_PAGES_TO_SIZE(a)  ((a) << LIBSPDM_RT_PAGE_SHIFT)

/* Page Flag Definitions*/
#define LIBSPDM_RT_PAGE_FREE  0x00000000
#define LIBSPDM_RT_PAGE_USED  0x00000001

/* Memory Page Table */
typedef struct {
    size_t start_page_offset;    /* Offset of the starting page allocated. Only available for USED pages.*/
    uint32_t page_flag;          /* Page Attributes.*/
} LIBSPDM_RT_MEMORY_PAGE_ENTRY;

typedef struct {
    size_t page_count;
    size_t last_empty_page_offset;
    uint8_t *data_area_base;       /*  Pointer to data Area. */
    LIBSPDM_RT_MEMORY_PAGE_ENTRY Pages[1];      /* Page Table Entries.*/
} LIBSPDM_RT_MEMORY_PAGE_TABLE;

/*  Global Page Table for Runtime Cryptographic Provider.*/
LIBSPDM_RT_MEMORY_PAGE_TABLE *m_libspdm_rt_page_table = NULL;

/**
 * Initializes pre-allocated memory pointed by scratch_buffer for subsequent runtime use.
 *
 * @param[in, out]  scratch_buffer      Pointer to user-supplied memory buffer.
 * @param[in]       scratch_buffer_size  Size of supplied buffer in bytes.
 *
 * @retval  true   Init successfully.
 * @retval  false  Init failed.
 **/
bool libspdm_init_scratch_memory(uint8_t *scratch_buffer, size_t scratch_buffer_size)
{
    size_t index;
    size_t memory_size;

    /* Parameters Checking*/
    if (scratch_buffer == NULL) {
        return false;
    }

    m_libspdm_rt_page_table = (LIBSPDM_RT_MEMORY_PAGE_TABLE *)scratch_buffer;

    /* Initialize Internal Page Table for Memory Management*/
    libspdm_set_mem(m_libspdm_rt_page_table, scratch_buffer_size, 0xFF);
    memory_size = scratch_buffer_size - sizeof (LIBSPDM_RT_MEMORY_PAGE_TABLE) +
                  sizeof (LIBSPDM_RT_MEMORY_PAGE_ENTRY);

    m_libspdm_rt_page_table->page_count = memory_size /
                                          (LIBSPDM_RT_PAGE_SIZE +
                                           sizeof (LIBSPDM_RT_MEMORY_PAGE_ENTRY));
    m_libspdm_rt_page_table->last_empty_page_offset = 0x0;

    for (index = 0; index < m_libspdm_rt_page_table->page_count; index++) {
        m_libspdm_rt_page_table->Pages[index].page_flag = LIBSPDM_RT_PAGE_FREE;
        m_libspdm_rt_page_table->Pages[index].start_page_offset = 0;
    }

    m_libspdm_rt_page_table->data_area_base = scratch_buffer +
                                              sizeof (LIBSPDM_RT_MEMORY_PAGE_TABLE) +
                                              (m_libspdm_rt_page_table->page_count - 1) *
                                              sizeof (LIBSPDM_RT_MEMORY_PAGE_ENTRY);

    return true;
}

/**
 * Look-up Free memory Region for object allocation.
 *
 * @param[in]  need_allocation_size  Bytes to be allocated.
 *
 * @retval  Return available page offset for object allocation. if return 0, it means find failed.
 **/
size_t libspdm_find_free_mem_region(size_t need_allocation_size)
{
    size_t start_page_index;
    size_t index;
    size_t sub_index;
    size_t required_pages;

    start_page_index = LIBSPDM_RT_SIZE_TO_PAGES (m_libspdm_rt_page_table->last_empty_page_offset);
    required_pages = LIBSPDM_RT_SIZE_TO_PAGES (need_allocation_size);
    if (required_pages > m_libspdm_rt_page_table->page_count) {
        /* No enough region for object allocation.*/
        return (size_t)(-1);
    }

    /* Look up the free memory region with in current memory map table.*/
    for (index = start_page_index;
         index <= (m_libspdm_rt_page_table->page_count - required_pages); ) {
        /* Check consecutive required_pages pages.*/
        for (sub_index = 0; sub_index < required_pages; sub_index++) {
            if ((m_libspdm_rt_page_table->Pages[sub_index + index].page_flag &
                 LIBSPDM_RT_PAGE_USED) != 0) {
                break;
            }
        }

        if (sub_index == required_pages) {
            /* Succeed! Return the Starting Offset.*/
            return LIBSPDM_RT_PAGES_TO_SIZE (index);
        }

        /* Failed! Skip current free memory pages and adjacent Used pages*/
        while ((m_libspdm_rt_page_table->Pages[sub_index + index].page_flag &
                LIBSPDM_RT_PAGE_USED) != 0) {
            sub_index++;
        }

        index += sub_index;
    }

    /* Look up the free memory region from the beginning of the memory table until the StartCursorOffset*/
    if (required_pages > start_page_index) {
        /* No enough region for object allocation.*/
        return (size_t)(-1);
    }

    for (index = 0; index < (start_page_index - required_pages); ) {
        /* Check Consecutive required_pages Pages.*/
        for (sub_index = 0; sub_index < required_pages; sub_index++) {
            if ((m_libspdm_rt_page_table->Pages[sub_index + index].page_flag &
                 LIBSPDM_RT_PAGE_USED) != 0) {
                break;
            }
        }

        if (sub_index == required_pages) {
            /* Succeed! Return the Starting Offset.*/
            return LIBSPDM_RT_PAGES_TO_SIZE (index);
        }

        /* Failed! Skip current adjacent Used pages*/
        while ((sub_index < (start_page_index - required_pages)) &&
               ((m_libspdm_rt_page_table->Pages[sub_index + index].page_flag &
                 LIBSPDM_RT_PAGE_USED) != 0)) {
            sub_index++;
        }

        index += sub_index;
    }

    /* No available region for object allocation!*/
    return (size_t)(-1);
}

/**
 * Allocates a buffer at runtime phase.
 *
 * @param[in]   need_allocation_size    Bytes to be allocated.
 *
 * @return  A pointer to the allocated buffer or NULL if allocation fails.
 **/
void *libspdm_allocate_mem(size_t need_allocation_size)
{
    uint8_t *alloc_ptr;
    size_t required_pages;
    size_t index;
    size_t start_page;
    size_t alloc_offset;

    alloc_ptr = NULL;
    required_pages = 0;

    /* Look for available consecutive memory region starting from last_empty_page_offset.
     * If no proper memory region found, look up from the beginning.
     * If still not found, return NULL to indicate failed allocation.
     */
    alloc_offset = libspdm_find_free_mem_region (need_allocation_size);
    if (alloc_offset == (size_t)(-1)) {
        return NULL;
    }

    /* Allocates consecutive memory pages with length of Size. Update the page
     * table status. Returns the starting address.
     */
    required_pages = LIBSPDM_RT_SIZE_TO_PAGES (need_allocation_size);
    alloc_ptr = m_libspdm_rt_page_table->data_area_base + alloc_offset;
    start_page = LIBSPDM_RT_SIZE_TO_PAGES (alloc_offset);
    index = 0;
    while (index < required_pages) {
        m_libspdm_rt_page_table->Pages[start_page + index].page_flag |= LIBSPDM_RT_PAGE_USED;
        m_libspdm_rt_page_table->Pages[start_page + index].start_page_offset = alloc_offset;

        index++;
    }

    m_libspdm_rt_page_table->last_empty_page_offset = alloc_offset +
                                                      LIBSPDM_RT_PAGES_TO_SIZE (required_pages);

    /* Returns a void pointer to the allocated space*/
    return alloc_ptr;
}

/**
 * Frees a buffer that was previously allocated at runtime phase.
 *
 * @param[in]   buffer  Pointer to the buffer to free.
 *
 * @return  A pointer to the allocated buffer or NULL if allocation fails.
 **/
void libspdm_free_mem(void *buffer)
{
    size_t start_offset;
    size_t start_page_index;

    start_offset = (size_t)buffer - (size_t)m_libspdm_rt_page_table->data_area_base;
    start_page_index = LIBSPDM_RT_SIZE_TO_PAGES
                           (m_libspdm_rt_page_table->Pages[LIBSPDM_RT_SIZE_TO_PAGES (
                                                               start_offset)].start_page_offset);

    while (start_page_index < m_libspdm_rt_page_table->page_count) {
        if (((m_libspdm_rt_page_table->Pages[start_page_index].page_flag &
              LIBSPDM_RT_PAGE_USED) != 0) &&
            (m_libspdm_rt_page_table->Pages[start_page_index].start_page_offset == start_offset)) {
            /* Free this page*/
            m_libspdm_rt_page_table->Pages[start_page_index].page_flag &= ~LIBSPDM_RT_PAGE_USED;
            m_libspdm_rt_page_table->Pages[start_page_index].start_page_offset = 0;

            start_page_index++;
        } else {
            break;
        }
    }

    return;
}

void *allocate_pool(size_t need_allocation_size)
{
    return libspdm_allocate_mem(need_allocation_size);
}

void *allocate_zero_pool(size_t need_allocation_size)
{
    void *buffer;
    buffer = libspdm_allocate_mem(need_allocation_size);
    if (buffer == NULL) {
        return NULL;
    }
    libspdm_set_mem(buffer, need_allocation_size, 0);
    return buffer;
}

void free_pool(void *buffer)
{
    /* In Standard C, free() handles a null pointer argument transparently. This
     * is not true of libspdm_free_mem() below, so protect it.
     */
    if (buffer != NULL) {
        libspdm_free_mem (buffer);
    }
}
