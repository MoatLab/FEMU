/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/usr/hwpf/hwp/build_winkle_images/p8_slw_build/sbe_xip_image.c $ */
/*                                                                        */
/* OpenPOWER HostBoot Project                                             */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2012,2015                        */
/* [+] International Business Machines Corp.                              */
/*                                                                        */
/*                                                                        */
/* Licensed under the Apache License, Version 2.0 (the "License");        */
/* you may not use this file except in compliance with the License.       */
/* You may obtain a copy of the License at                                */
/*                                                                        */
/*     http://www.apache.org/licenses/LICENSE-2.0                         */
/*                                                                        */
/* Unless required by applicable law or agreed to in writing, software    */
/* distributed under the License is distributed on an "AS IS" BASIS,      */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or        */
/* implied. See the License for the specific language governing           */
/* permissions and limitations under the License.                         */
/*                                                                        */
/* IBM_PROLOG_END_TAG                                                     */
// $Id: sbe_xip_image.c,v 1.31 2015/07/29 23:40:06 cmolsen Exp $
// $Source: /afs/awd/projects/eclipz/KnowledgeBase/.cvsroot/eclipz/chips/p8/working/procedures/ipl/sbe/sbe_xip_image.c,v $
//-----------------------------------------------------------------------------
// *! (C) Copyright International Business Machines Corp. 2011
// *! All Rights Reserved -- Property of IBM
// *! ***  ***
//-----------------------------------------------------------------------------
// *! OWNER NAME: Bishop Brock          Email: bcbrock@us.ibm.com
//------------------------------------------------------------------------------

/// \file sbe_xip_image.c 
/// \brief APIs for validating, normalizing, searching and manipulating
/// SBE-XIP images.
///
/// The background, APIs and implementation details are documented in the
/// document "SBE-XIP Binary format" currently available at this link:
///
/// - https://mcdoc.boeblingen.de.ibm.com/out/out.ViewDocument.php?documentid=2678
///
/// \bug The sbe_xip_validate() API should be carefully reviewed to ensure
/// that validating even a corrupt image can not lead to a segfault, i.e., to
/// ensure that no memory outside of the putative bounds of the image is ever
/// referenced during validation.

#ifndef PLIC_MODULE
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#endif // PLIC_MODULE

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sbe_xip_image.h"


////////////////////////////////////////////////////////////////////////////
// Local Functions
////////////////////////////////////////////////////////////////////////////

// PHYP has their own way of implementing the <string.h> functions. PHYP also
// does not allow static functions or data, so all of the XIP_STATIC functions
// defined here are global to PHYP.

#ifdef PPC_HYP

#ifdef PLIC_MODULE

#define strcpy(dest, src) hvstrcpy(dest, src)
#define strlen(s) hvstrlen(s)
#define strcmp(s1, s2) hvstrcmp(s1, s2)
#endif //PLIC_MODULE

#define XIP_STATIC
        
#else // PPC_HYP

#define XIP_STATIC static

#endif // PPC_HYP


#ifdef DEBUG_SBE_XIP_IMAGE

// Debugging support, normally disabled. All of the formatted I/O you see in
// the code is effectively under this switch.

#ifdef __FAPI

#include "fapi.H"
#define fprintf(stream, ...) FAPI_ERR(__VA_ARGS__)
#define printf(...) FAPI_INF(__VA_ARGS__)
#define TRACE_NEWLINE ""

#else // __FAPI

#include <stdio.h>
#define TRACE_NEWLINE "\n"

#endif // __FAPI

// Portable formatting of uint64_t.  The ISO C99 standard requires
// __STDC_FORMAT_MACROS to be defined in order for PRIx64 etc. to be defined. 

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define F0x016llx "0x%016" PRIx64
#define F0x012llx "0x%012" PRIx64

XIP_STATIC SBE_XIP_ERROR_STRINGS(sbe_xip_error_strings);

#define TRACE_ERROR(x)                                                  \
    ({                                                                  \
        fprintf(stderr, "%s:%d : Returning error code %d : %s" TRACE_NEWLINE, \
                __FILE__, __LINE__, (x),                                \
                SBE_XIP_ERROR_STRING(sbe_xip_error_strings, (x)));      \
        (x);                                                            \
    })

#define TRACE_ERRORX(x, ...)                    \
    ({                                          \
        TRACE_ERROR(x);                         \
        fprintf(stderr, ##__VA_ARGS__);         \
        (x);                                    \
    })


// Uncomment these if required for debugging, otherwise we get warnings from
// GCC as they are not otherwise used.

#if 0

XIP_STATIC uint32_t xipRevLe32(const uint32_t i_x);

XIP_STATIC SBE_XIP_TYPE_STRINGS(type_strings);

XIP_STATIC void
dumpToc(int index, SbeXipToc* toc)
{
    printf("TOC entry %d @ %p\n" 
           "    iv_id       = 0x%08x\n"
           "    iv_data     = 0x%08x\n"
           "    iv_type     = %s\n"
           "    iv_section  = 0x%02x\n"
           "    iv_elements = %d\n",
           index, toc, 
           xipRevLe32(toc->iv_id), 
           xipRevLe32(toc->iv_data), 
           SBE_XIP_TYPE_STRING(type_strings, toc->iv_type), 
           toc->iv_section, 
           toc->iv_elements);
}

#endif

#if 0

XIP_STATIC void
dumpItem(SbeXipItem* item)
{
    printf("SbeXipItem @ %p\n"
           "    iv_toc       = %p\n"
           "    iv_address   = " F0x016llx "\n"
           "    iv_imageData = %p\n"
           "    iv_id        = %s\n"
           "    iv_type      = %s\n"
           "    iv_elements  = %d\n",
           item,
           item->iv_toc,
           item->iv_address,
           item->iv_imageData,
           item->iv_id,
           SBE_XIP_TYPE_STRING(type_strings, item->iv_type),
           item->iv_elements);
    dumpToc(-1, item->iv_toc);
}

#endif  /* 0 */

XIP_STATIC void
dumpSectionTable(const void* i_image)
{
    int i, rc;
    SbeXipSection section;

    printf("Section table dump of image @ %p\n"
           "  Entry    Offset        Size\n"
           "-------------------------------\n",
           i_image);

    for (i = 0; i < SBE_XIP_SECTIONS; i++) {
        rc = sbe_xip_get_section(i_image, i, &section);
        if (rc) {
            printf(">>> dumpSectionTable got error at entry %d : %s\n",
                   i, SBE_XIP_ERROR_STRING(sbe_xip_error_strings, rc));
            break;
        }
        printf("%7d  0x%08x  0x%08x\n",
               i, section.iv_offset, section.iv_size);
    }
}
          
#else

#define TRACE_ERROR(x) (x)
#define TRACE_ERRORX(x, ...) (x)
#define dumpToc(...)
#define dumpItem(...)
#define dumpSectionTable(...)

#endif


// Note: For maximum flexibility we provide private versions of
// endian-conversion routines rather than counting on a system-specific header
// to provide these. 

/// Byte-reverse a 16-bit integer if on a little-endian machine

XIP_STATIC uint16_t
xipRevLe16(const uint16_t i_x)
{
    uint16_t rx;

#ifndef _BIG_ENDIAN
    uint8_t *pix = (uint8_t*)(&i_x);
    uint8_t *prx = (uint8_t*)(&rx);

    prx[0] = pix[1];
    prx[1] = pix[0];
#else
    rx = i_x;
#endif

    return rx;
}


/// Byte-reverse a 32-bit integer if on a little-endian machine

XIP_STATIC uint32_t
xipRevLe32(const uint32_t i_x)
{
    uint32_t rx;

#ifndef _BIG_ENDIAN
    uint8_t *pix = (uint8_t*)(&i_x);
    uint8_t *prx = (uint8_t*)(&rx);

    prx[0] = pix[3];
    prx[1] = pix[2];
    prx[2] = pix[1];
    prx[3] = pix[0];
#else
    rx = i_x;
#endif

    return rx;
}


/// Byte-reverse a 64-bit integer if on a little-endian machine

XIP_STATIC uint64_t
xipRevLe64(const uint64_t i_x)
{
    uint64_t rx;

#ifndef _BIG_ENDIAN
    uint8_t *pix = (uint8_t*)(&i_x);
    uint8_t *prx = (uint8_t*)(&rx);

    prx[0] = pix[7];
    prx[1] = pix[6];
    prx[2] = pix[5];
    prx[3] = pix[4];
    prx[4] = pix[3];
    prx[5] = pix[2];
    prx[6] = pix[1];
    prx[7] = pix[0];
#else
    rx = i_x;
#endif

    return rx;
}


/// What is the image link address?

XIP_STATIC uint64_t
xipLinkAddress(const void* i_image)
{
    return xipRevLe64(((SbeXipHeader*)i_image)->iv_linkAddress);
}


/// What is the image size?

XIP_STATIC uint32_t
xipImageSize(const void* i_image)
{
    return xipRevLe32(((SbeXipHeader*)i_image)->iv_imageSize);
}


/// Set the image size

XIP_STATIC void
xipSetImageSize(void* io_image, const size_t i_size)
{
    ((SbeXipHeader*)io_image)->iv_imageSize = xipRevLe32(i_size);
}


/// Re-establish the required final alignment

XIP_STATIC void
xipFinalAlignment(void* io_image)
{
    uint32_t size;

    size = xipImageSize(io_image);

    if ((size % SBE_XIP_FINAL_ALIGNMENT) != 0) {
        xipSetImageSize(io_image, 
                        size + (SBE_XIP_FINAL_ALIGNMENT -
                                (size % SBE_XIP_FINAL_ALIGNMENT)));
    }
}


/// Compute a host address from an image address and offset

XIP_STATIC void*
xipHostAddressFromOffset(const void* i_image, const uint32_t offset)
{
    return (void*)((unsigned long)i_image + offset);
}


/// Convert a PORE address to a host address

XIP_STATIC void*
xipPore2Host(const void* i_image, const uint64_t i_poreAddress)
{
    return xipHostAddressFromOffset(i_image, 
                                    i_poreAddress - xipLinkAddress(i_image));
}


XIP_STATIC int
xipValidatePoreAddress(const void* i_image, 
                       const uint64_t i_poreAddress, 
                       const uint32_t size)
{
    int rc;

    if ((i_poreAddress < xipLinkAddress(i_image)) ||
        (i_poreAddress > (xipLinkAddress(i_image) + 
                          xipImageSize(i_image) - 
                          size))) {
        rc = TRACE_ERRORX(SBE_XIP_INVALID_ARGUMENT,
                          "The PORE address " F0x012llx 
                          " is outside the bounds "
                          "of the image (" 
                          F0x012llx ":" F0x012llx 
                          ") for %u-byte access.\n",
                          i_poreAddress,
                          xipLinkAddress(i_image),
                          xipLinkAddress(i_image) + xipImageSize(i_image) - 1,
                          size);
    } else {
        rc = 0;
    }
    return rc;
}


/// Get the magic number from the image

XIP_STATIC uint64_t
xipMagic(const void* i_image)
{
    return xipRevLe64(((SbeXipHeader*)i_image)->iv_magic);
}


/// Get the header version from the image

XIP_STATIC uint8_t
xipHeaderVersion(const void* i_image)
{
    return ((SbeXipHeader*)i_image)->iv_headerVersion;
}


/// Has the image been normalized?

XIP_STATIC uint8_t
xipNormalized(const void* i_image)
{
    return ((SbeXipHeader*)i_image)->iv_normalized;
}


/// Has the image TOC been sorted?

XIP_STATIC uint8_t
xipSorted(const void* i_image)
{
    return ((SbeXipHeader*)i_image)->iv_tocSorted;
}


/// A quick check that the image exists, has the correct magic and header
/// version, and optionally is normalized.

XIP_STATIC int 
xipQuickCheck(const void* i_image, const int i_normalizationRequired)
{
    int rc;

    do {
        rc = 0;

        if (i_image == 0) {
            rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR, 
                              "Image pointer is NULL (0)\n");
            break;
        }
        if ((xipMagic(i_image) >> 32) != SBE_XIP_MAGIC) {
            rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR,
                              "Magic number mismatch; Found "
                              "" F0x016llx ", expected 0x%08x........\n",
                              xipMagic(i_image), SBE_XIP_MAGIC);
            break;
        }
        if ((xipHeaderVersion(i_image)) != SBE_XIP_HEADER_VERSION) {
            rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR,
                              "Header version mismatch; Expecting %d, "
                              "found %d\n",
                              SBE_XIP_HEADER_VERSION, 
                              xipHeaderVersion(i_image));
            break;
        }
        if (i_normalizationRequired && !xipNormalized(i_image)) {
            rc = TRACE_ERRORX(SBE_XIP_NOT_NORMALIZED,
                              "Image not normalized\n");
            break;
        }
    } while(0);

    return rc;
}


/// Convert a 32-bit relocatable offset to a full PORE 48-bit address

XIP_STATIC uint64_t 
xipFullAddress(const void* i_image, uint32_t offset)
{
    return (xipLinkAddress(i_image) & 0x0000ffff00000000ull) + offset;
}


/// Translate a section table entry
 
XIP_STATIC void
xipTranslateSection(SbeXipSection* o_dest, const SbeXipSection* i_src)
{
#ifndef _BIG_ENDIAN

#if SBE_XIP_HEADER_VERSION != 8
#error This code assumes the SBE-XIP header version 8 layout
#endif

    o_dest->iv_offset = xipRevLe32(i_src->iv_offset);
    o_dest->iv_size = xipRevLe32(i_src->iv_size);
    o_dest->iv_alignment = i_src->iv_alignment;
    o_dest->iv_reserved8[0] = 0;
    o_dest->iv_reserved8[1] = 0;
    o_dest->iv_reserved8[2] = 0;
#else
    if (o_dest != i_src) {
        *o_dest = *i_src;
    }
#endif  /* _BIG_ENDIAN */
}    


/// Translate a TOC entry

XIP_STATIC void
xipTranslateToc(SbeXipToc* o_dest, SbeXipToc* i_src)
{
#ifndef _BIG_ENDIAN

#if SBE_XIP_HEADER_VERSION != 8
#error This code assumes the SBE-XIP header version 8 layout
#endif

    o_dest->iv_id = xipRevLe32(i_src->iv_id);
    o_dest->iv_data = xipRevLe32(i_src->iv_data);
    o_dest->iv_type = i_src->iv_type;
    o_dest->iv_section = i_src->iv_section;
    o_dest->iv_elements = i_src->iv_elements;
    o_dest->iv_pad = 0;
#else
    if (o_dest != i_src) {
        *o_dest = *i_src;
    }
#endif  /* _BIG_ENDIAN */
}


/// Find the final (highest-address) section of the image

XIP_STATIC int
xipFinalSection(const void* i_image, int* o_sectionId)
{
    int i, rc, found;
    uint32_t offset;
    SbeXipHeader hostHeader;
    
    sbe_xip_translate_header(&hostHeader, (SbeXipHeader*)i_image);

    found = 0;
    offset = 0;
    *o_sectionId = 0;           /* Make GCC -O3 happy */
    for (i = 0; i < SBE_XIP_SECTIONS; i++) {
        if ((hostHeader.iv_section[i].iv_size != 0) && 
            (hostHeader.iv_section[i].iv_offset >= offset)) {
            *o_sectionId = i;
            offset = hostHeader.iv_section[i].iv_offset;
            found = 1;
        }
    }
    if (!found) {
        rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR, "The image is empty\n");
    } else {
        rc = 0;
    }
    return rc;
}


/// Return a pointer to an image-format section table entry

XIP_STATIC int
xipGetSectionPointer(const void* i_image,
                     const int i_sectionId,
                     SbeXipSection** o_imageSection)
{
    int rc;

    if ((i_sectionId < 0) || (i_sectionId >= SBE_XIP_SECTIONS)) {
        rc = TRACE_ERROR(SBE_XIP_INVALID_ARGUMENT);
    } else {
        *o_imageSection = 
            &(((SbeXipHeader*)i_image)->iv_section[i_sectionId]);
        rc = 0;
    }
    return rc;
}


/// Restore a section table entry from host format to image format.

XIP_STATIC int
xipPutSection(const void* i_image,
              const int i_sectionId,
              SbeXipSection* i_hostSection)
{
    int rc;
    SbeXipSection *imageSection = NULL;

    rc = xipGetSectionPointer(i_image, i_sectionId, &imageSection);

    if (!rc) {
        xipTranslateSection(imageSection, i_hostSection);
    }

    return rc;
}


/// Set the offset of a section

XIP_STATIC int
xipSetSectionOffset(void* io_image, const int i_section, 
                    const uint32_t i_offset)
{
    SbeXipSection* section = NULL;
    int rc;

    rc = xipGetSectionPointer(io_image, i_section, &section);
    if (!rc) {
        section->iv_offset = xipRevLe32(i_offset);
    }
    return rc;
}


/// Set the size of a section

XIP_STATIC int
xipSetSectionSize(void* io_image, const int i_section, const uint32_t i_size)
{
    SbeXipSection* section = NULL;
    int rc;

    rc = xipGetSectionPointer(io_image, i_section, &section);
    if (!rc) {
        section->iv_size = xipRevLe32(i_size);
    }
    return rc;
}


/// Translate a PORE address in the image to a section and offset

// We first check to be sure that the PORE address is contained in the image,
// using the full 48-bit form.  Then we scan the section table to see which
// section contains the address - if none then the image is corrupted. We can
// (must) use the 32-bit offset form of the address here.

XIP_STATIC int
xipPore2Section(const void* i_image, 
                const uint64_t i_poreAddress,
                int* o_section,
                uint32_t* o_offset)
{
    int rc, sectionId;
    SbeXipSection section;
    uint32_t addressOffset;

    do {
        rc = 0;

        if ((i_poreAddress < xipLinkAddress(i_image)) ||
            (i_poreAddress > 
             (xipLinkAddress(i_image) + xipImageSize(i_image)))) {
            rc = TRACE_ERRORX(SBE_XIP_INVALID_ARGUMENT,
                              "pore2section: The i_poreAddress argument "
                              "(" F0x016llx ")\nis outside the bounds of the "
                              "image (" F0x016llx ":" F0x016llx ")\n",
                              i_poreAddress,
                              xipLinkAddress(i_image),
                              xipLinkAddress(i_image) + xipImageSize(i_image));
            break;
        }

        addressOffset = (i_poreAddress - xipLinkAddress(i_image)) & 0xffffffff;

        for (sectionId = 0; sectionId < SBE_XIP_SECTIONS; sectionId++) {
            rc = sbe_xip_get_section(i_image, sectionId, &section);
            if (rc) {
                rc = TRACE_ERROR(SBE_XIP_BUG); /* Can't happen */
                break;
            }
            if ((section.iv_size != 0) &&
                (addressOffset >= section.iv_offset) &&
                (addressOffset < (section.iv_offset + section.iv_size))) {
                break;
            }
        }
        if (rc) break;

        if (sectionId == SBE_XIP_SECTIONS) {
            rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR,
                              "Error processing PORE address " F0x016llx ". "
                              "The address is not mapped in any section.\n"
                              "A section table dump appears below\n",
                              i_poreAddress);
            dumpSectionTable(i_image);
            break;
        }

        *o_section = sectionId;
        *o_offset = addressOffset - section.iv_offset;

    } while(0);

    return rc;
}


/// Get the information required to search the TOC.  
///
/// All return values are optional.

XIP_STATIC int
xipGetToc(void* i_image,
          SbeXipToc** o_toc,
          size_t* o_entries,
          int* o_sorted,
          char** o_strings)
{
    int rc;
    SbeXipSection tocSection, stringsSection;

    do {
        rc = sbe_xip_get_section(i_image, SBE_XIP_SECTION_TOC, &tocSection);
        if (rc) break;

        rc = sbe_xip_get_section(i_image, SBE_XIP_SECTION_STRINGS,
                                 &stringsSection);
        if (rc) break;

        if (o_toc) {
            *o_toc = (SbeXipToc*)((uint8_t*)i_image + tocSection.iv_offset);
        }
        if (o_entries) {
            *o_entries = tocSection.iv_size / sizeof(SbeXipToc);
        }
        if (o_sorted) {
            *o_sorted = xipSorted(i_image);
        }
        if (o_strings) {
            *o_strings = (char*)i_image + stringsSection.iv_offset;
        }
    } while (0);
    return rc;
}


/// Compare two normalized TOC entries for sorting.

XIP_STATIC int
xipCompareToc(const SbeXipToc* i_a, const SbeXipToc* i_b, 
              const char* i_strings)
{
    return strcmp(i_strings + xipRevLe32(i_a->iv_id),
                  i_strings + xipRevLe32(i_b->iv_id));
}


/// Iterative quicksort of the TOC

// Note: The stack requirement is limited to 256 bytes + minor local storage.

XIP_STATIC void
xipQuickSort(SbeXipToc* io_toc, int i_left, int i_right,
             const char* i_strings)
{
    int i, j, left, right, sp;
    SbeXipToc pivot, temp;
    uint32_t stack[64];

    sp = 0;
    stack[sp++] = i_left;
    stack[sp++] = i_right;

    while (sp) {

        right = stack[--sp];
        left = stack[--sp];

        i = left;
        j = right;

        pivot = io_toc[(i + j) / 2];

        while (i <= j) {
            while (xipCompareToc(&(io_toc[i]), &pivot, i_strings) < 0) {
                i++;
            }
            while (xipCompareToc(&(io_toc[j]), &pivot, i_strings) > 0) {
                j--;
            }
            if (i <= j) {
                temp = io_toc[i];
                io_toc[i] = io_toc[j];
                io_toc[j] = temp;
                i++;
                j--;
            }
        }
        if (left < j) {
            stack[sp++] = left;
            stack[sp++] = j;
        }
        if (i < right) {
            stack[sp++] = i;
            stack[sp++] = right;
        }
    }
}


/// TOC linear search

XIP_STATIC int
xipLinearSearch(void* i_image, const char* i_id, SbeXipToc** o_entry)
{
    int rc;
    SbeXipToc *imageToc, hostToc;
    size_t entries;
    char* strings;

    *o_entry = 0;
    rc = xipGetToc(i_image, &imageToc, &entries, 0, &strings);
    if (!rc) {
        for (; entries; entries--, imageToc++) {
            xipTranslateToc(&hostToc, imageToc);
            if (strcmp(i_id, strings + hostToc.iv_id) == 0) {
                break;
            }
        }
        if (entries) {
            *o_entry = imageToc;
            rc = 0;
        } else {
            *o_entry = 0;
            rc = TRACE_ERROR(SBE_XIP_ITEM_NOT_FOUND);
        }
    }
    return rc;
}


/// A classic binary search of a (presumed) sorted array

XIP_STATIC int
xipBinarySearch(void* i_image, const char* i_id, SbeXipToc** o_entry)
{
    int rc;
    SbeXipToc *imageToc;
    size_t entries;
    char* strings;
    int sorted, left, right, next, sort;

    do {
        *o_entry = 0;

        rc = xipGetToc(i_image, &imageToc, &entries, &sorted, &strings);
        if (rc) break;

        if (!sorted) {
            rc = TRACE_ERROR(SBE_XIP_BUG);
            break;
        }

        left = 0;
        right = entries - 1;
        while (left <= right) {
            next = (left + right) / 2;
            sort = strcmp(i_id, strings + xipRevLe32(imageToc[next].iv_id));
            if (sort == 0) {
                *o_entry = &(imageToc[next]);
                break;
            } else if (sort < 0) {
                right = next - 1;
            } else {
                left = next + 1;
            }
        }
        if (*o_entry == 0) {
            rc = TRACE_ERROR(SBE_XIP_ITEM_NOT_FOUND);
            break;
        }
    } while (0);
    return rc;
}


/// Validate a TOC entry as a mapping function
///
/// The TOC is validated by searching for the entry, which will uncover
/// duplicate entries or problems with sorting/searching.

XIP_STATIC int
xipValidateTocEntry(void* io_image, const SbeXipItem* i_item, void* io_arg)
{
    int rc;
    SbeXipItem found;

    (void)io_arg;

    do {
        rc = sbe_xip_find(io_image, i_item->iv_id, &found);
        if (rc) {
            rc = TRACE_ERRORX(rc, "TOC entry for %s not found\n", 
                              i_item->iv_id);
        } else if (found.iv_toc != i_item->iv_toc) {
            rc = TRACE_ERRORX(SBE_XIP_TOC_ERROR,
                              "Duplicate TOC entry for '%s'\n", i_item->iv_id);
        }
        break;
    } while (0);
    return rc;
}
    

// This is the FNV-1a hash, used for hashing symbol names in the .fixed
// section into 32-bit hashes for the mini-TOC.

// According to the authors:

// "FNV hash algorithms and source code have been released into the public
// domain. The authors of the FNV algorithmm look deliberate steps to disclose
// the algorhtm (sic) in a public forum soon after it was invented. More than
// a year passed after this public disclosure and the authors deliberately took
// no steps to patent the FNV algorithm. Therefore it is safe to say that the
// FNV authors have no patent claims on the FNV algorithm as published."

#define FNV_OFFSET_BASIS 2166136261u
#define FNV_PRIME32 16777619u

static uint32_t
xipHash32(const char* s) 
{
    uint32_t hash;

    hash = FNV_OFFSET_BASIS;
    while (*s) {
        hash ^= *s++;
        hash *= FNV_PRIME32;
    }
    return hash;
}


// Normalize a TOC entry

// Normalize the TOC entry by converting relocatable pointers into 32-bit
// offsets from the beginning of the section containing the data. All
// addresses in the TOC are actually 32-bit offsets in the address space named
// in bits 16:31 of the link address of the image.

XIP_STATIC int
xipNormalizeToc(void* io_image, SbeXipToc *io_imageToc,
                SbeXipHashedToc** io_fixedTocEntry,
                size_t* io_fixedEntriesRemaining)
{
    SbeXipToc hostToc;
    int idSection, dataSection;
    uint32_t idOffset, dataOffset;
    char* hostString;
    int rc;

    do {

        // Translate the TOC entry to host format.  Then locate the
        // sections/offsets of the Id string (which must be in .strings) and
        // the data.

        xipTranslateToc(&hostToc, io_imageToc);

        hostString = 
            (char*)xipPore2Host(io_image, 
                                xipFullAddress(io_image, hostToc.iv_id));

        rc = xipPore2Section(io_image,
                             xipFullAddress(io_image, hostToc.iv_id),
                             &idSection,
                             &idOffset);
        if (rc) break;

        if (idSection != SBE_XIP_SECTION_STRINGS) {
            rc = TRACE_ERROR(SBE_XIP_IMAGE_ERROR);
            break;
        }

        rc = xipPore2Section(io_image,
                             xipFullAddress(io_image, hostToc.iv_data),
                             &dataSection,
                             &dataOffset);
        if (rc) break;

        // Now replace the Id and data pointers with their offsets, and update
        // the data section in the TOC entry.

        hostToc.iv_id = idOffset;
        hostToc.iv_data = dataOffset;
        hostToc.iv_section = dataSection;

        // If this TOC entry is from .fixed, create a new record in .fixed_toc

        if (hostToc.iv_section == SBE_XIP_SECTION_FIXED) {

            if (*io_fixedEntriesRemaining == 0) {
                rc = TRACE_ERRORX(SBE_XIP_TOC_ERROR,
                                  "Too many TOC entries for .fixed\n");
                break;
            }
            if (hostToc.iv_data != (uint16_t)hostToc.iv_data) {
                rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR,
                                  "The .fixed section is too big to index\n");
                break;
            }

            (*io_fixedTocEntry)->iv_hash = xipRevLe32(xipHash32(hostString));
            (*io_fixedTocEntry)->iv_offset = xipRevLe16(hostToc.iv_data);
            (*io_fixedTocEntry)->iv_type = hostToc.iv_type;
            (*io_fixedTocEntry)->iv_elements = hostToc.iv_elements;
            
            (*io_fixedTocEntry)++;
            (*io_fixedEntriesRemaining)--;
        }            

        // Finally update the TOC entry

        xipTranslateToc(io_imageToc, &hostToc);

    } while (0);

    return rc;
}


// Check for hash collisions in the .fixed mini-TOC.  Note that endianness is
// not an issue here, as we're comparing for equality.

XIP_STATIC int
xipHashCollision(SbeXipHashedToc* i_fixedToc, size_t i_entries)
{
    int rc;
    size_t i, j;

    rc = 0;

    for (i = 0; i < i_entries; i++) {
        for (j = i + 1; j < i_entries; j++) {
            if (i_fixedToc[i].iv_hash == i_fixedToc[j].iv_hash) {
                rc = TRACE_ERRORX(SBE_XIP_HASH_COLLISION,
                                  "Hash collision at index %d\n",
                                  i);
                break;
            }
        }
        if (rc) break;
    }
    
    return rc;
}


/// Decode a normalized image-format TOC entry into a host-format SbeXipItem
/// structure

XIP_STATIC int
xipDecodeToc(void* i_image, 
             SbeXipToc* i_imageToc, 
             SbeXipItem* o_item)
{
    int rc;
    SbeXipToc hostToc;
    SbeXipSection dataSection, stringsSection;

    do {
        if (!xipNormalized(i_image)) {
            rc = TRACE_ERROR(SBE_XIP_NOT_NORMALIZED);
            break;
        }


        // Translate the TOC entry and set the TOC pointer, data type and
        // number of elements in the outgoing structure. The Id string is
        // always located in the TOC_STRINGS section.

        xipTranslateToc(&hostToc, i_imageToc);

        o_item->iv_toc = i_imageToc;
        o_item->iv_type = hostToc.iv_type;
        o_item->iv_elements = hostToc.iv_elements;

        rc = sbe_xip_get_section(i_image, SBE_XIP_SECTION_STRINGS,
				 &stringsSection);
        if (rc) break;

        o_item->iv_id = 
            (char*)i_image + stringsSection.iv_offset + hostToc.iv_id;
        

        // The data (or text address) are addressed by relative offsets from
        // the beginning of their section.  The TOC entry may remain in the TOC
        // even though the section has been removed from the image, so this
        // case needs to be covered. 
        
        rc = sbe_xip_get_section(i_image, hostToc.iv_section, &dataSection);
        if (rc) break;

        if (dataSection.iv_size == 0) {
            rc = TRACE_ERROR(SBE_XIP_DATA_NOT_PRESENT);
            break;
        }

        o_item->iv_imageData = 
            (void*)((uint8_t*)i_image + 
                    dataSection.iv_offset + hostToc.iv_data);

        o_item->iv_address = 
            xipLinkAddress(i_image) + dataSection.iv_offset + hostToc.iv_data;

        o_item->iv_partial = 0;
            
    } while (0);
    return rc;
}    


/// Sort the TOC

XIP_STATIC int
xipSortToc(void* io_image)
{
    int rc;
    SbeXipToc *hostToc;
    size_t entries;
    char* strings;

    do {
        rc = xipQuickCheck(io_image, 1);
        if (rc) break;

        if (xipSorted(io_image)) break;

        rc = xipGetToc(io_image, &hostToc, &entries, 0, &strings);
        if (rc) break;

        xipQuickSort(hostToc, 0, entries - 1, strings);

        ((SbeXipHeader*)io_image)->iv_tocSorted = 1;
        
    } while (0);

    return rc;
}


// Pad the image with 0 to a given power-of-2 alignment.  The image size is
// modified to reflect the pad, but the caller must modify the section size to
// reflect the pad.

XIP_STATIC int
xipPadImage(void* io_image, uint32_t i_allocation, 
            uint32_t i_align, uint32_t* pad)
{
    int rc;

    do {
        rc = 0;

        if ((i_align == 0) || ((i_align & (i_align - 1)) != 0)) {
            rc = TRACE_ERRORX(SBE_XIP_INVALID_ARGUMENT,
                              "Alignment specification (%u) "
                              "not a power-of-2\n",
                              i_align);
            break;
        }

        *pad = xipImageSize(io_image) % i_align;
        if (*pad != 0) {
            *pad = i_align - *pad;

            if ((xipImageSize(io_image) + *pad) > i_allocation) {
                rc = TRACE_ERROR(SBE_XIP_WOULD_OVERFLOW);
                break;
            }

            memset((void*)((unsigned long)io_image + xipImageSize(io_image)), 
                   0, *pad);
            xipSetImageSize(io_image, xipImageSize(io_image) + *pad);
        }
    } while (0);

    return rc;
}


//  Get the .fixed_toc section

XIP_STATIC int
xipGetFixedToc(void* io_image, 
               SbeXipHashedToc** o_imageToc, 
               size_t* o_entries)
{
    int rc;
    SbeXipSection section;

    rc = sbe_xip_get_section(io_image, SBE_XIP_SECTION_FIXED_TOC, &section);
    if (!rc) {

        *o_imageToc = 
            (SbeXipHashedToc*)((unsigned long)io_image + section.iv_offset);  

        *o_entries = section.iv_size / sizeof(SbeXipHashedToc);
    }

    return rc;
}


// Search for an item in the fixed TOC, and populate a partial TOC entry if
// requested. This table is small and unsorted so a linear search is
// adequate. The TOC structures are also small so all byte-reversal is done
// 'by hand' rather than with a translate-type API.

XIP_STATIC int
xipFixedFind(void* i_image, const char* i_id, SbeXipItem* o_item)
{
    int rc;
    SbeXipHashedToc* toc;
    size_t entries;
    uint32_t hash;
    SbeXipSection fixedSection;
    uint32_t offset;

    do {
        rc = xipGetFixedToc(i_image, &toc, &entries);
        if (rc) break;

        for (hash = xipRevLe32(xipHash32(i_id)); entries != 0; entries--, toc++) {
            if (toc->iv_hash == hash) break;
        }

        if (entries == 0) {
            rc = SBE_XIP_ITEM_NOT_FOUND;
            break;
        } else {
            rc = 0;
        }

        // The caller may have requested a lookup only (o_item == 0), in which
        // case we're done.  Otherwise we create a partial SbeXipItem and
        // populate the non-0 fields analogously to the xipDecodeToc()
        // routine. The data resides in the .fixed section in this case.

        if (o_item == 0) break;

        o_item->iv_partial = 1;
        o_item->iv_toc = 0;
        o_item->iv_id = 0;

        o_item->iv_type = toc->iv_type;
        o_item->iv_elements = toc->iv_elements;

        rc = sbe_xip_get_section(i_image, SBE_XIP_SECTION_FIXED, &fixedSection);
        if (rc) break;

        if (fixedSection.iv_size == 0) {
            rc = TRACE_ERROR(SBE_XIP_DATA_NOT_PRESENT);
            break;
        }

        offset = fixedSection.iv_offset + xipRevLe16(toc->iv_offset);

        o_item->iv_imageData = (void*)((uint8_t*)i_image + offset);
        o_item->iv_address = xipLinkAddress(i_image) + offset;

    } while (0);

    return rc;
}


// Search for an item in the special built-in TOC of header fields, and
// populate a partial TOC entry if requested. 
//
// This facility was added to allow header data to be searched by name even
// when the TOC has been stripped. This API will only be used in the case of a
// stripped TOC since the header fields are also indexed in the main TOC.
//
// The table is allocated on the stack in order to make this code concurrently
// patchable in PHYP (although PHYP applications will never use this code).
// The table is small and unsorted so a linear search is adequate, and the
// stack requirememts are small.

XIP_STATIC int
xipHeaderFind(void* i_image, const char* i_id, SbeXipItem* o_item)
{
    int rc;
    unsigned i;
    uint32_t offset;
    SbeXipSection headerSection;

#define HEADER_TOC(id, field, type)             \
    {#id, offsetof(SbeXipHeader, field), type}

    struct HeaderToc {

        const char* iv_id;
        uint16_t iv_offset;
        uint8_t iv_type;

    } toc[] = {

        HEADER_TOC(magic,        iv_magic,       SBE_XIP_UINT64),
        HEADER_TOC(entry_offset, iv_entryOffset, SBE_XIP_UINT64),
        HEADER_TOC(link_address, iv_linkAddress, SBE_XIP_UINT64),

        HEADER_TOC(image_size, iv_imageSize, SBE_XIP_UINT32),
        HEADER_TOC(build_date, iv_buildDate, SBE_XIP_UINT32),
        HEADER_TOC(build_time, iv_buildTime, SBE_XIP_UINT32),

        HEADER_TOC(header_version, iv_headerVersion, SBE_XIP_UINT8),
        HEADER_TOC(toc_normalized, iv_normalized,    SBE_XIP_UINT8),
        HEADER_TOC(toc_sorted,     iv_tocSorted,     SBE_XIP_UINT8),

        HEADER_TOC(build_user, iv_buildUser, SBE_XIP_STRING),
        HEADER_TOC(build_host, iv_buildHost, SBE_XIP_STRING),

    };

    do {

        rc = SBE_XIP_ITEM_NOT_FOUND;
        for (i = 0; i < (sizeof(toc) / sizeof(struct HeaderToc)); i++) {
            if (strcmp(i_id, toc[i].iv_id) == 0) {
                rc = 0;
                break;
            }
        }

        if (rc) break;

        // The caller may have requested a lookup only (o_item == 0), in which
        // case we're done.  Otherwise we create a partial SbeXipItem and
        // populate the non-0 fields analogously to the xipDecodeToc()
        // routine. The data resides in the .fixed section in this case.

        if (o_item == 0) break;

        o_item->iv_partial = 1;
        o_item->iv_toc = 0;
        o_item->iv_id = 0;

        o_item->iv_type = toc[i].iv_type;
        o_item->iv_elements = 1; /* True for now... */

        rc = sbe_xip_get_section(i_image, SBE_XIP_SECTION_HEADER, 
                                 &headerSection);
        if (rc) break;

        if (headerSection.iv_size == 0) {
            rc = TRACE_ERROR(SBE_XIP_DATA_NOT_PRESENT);
            break;
        }

        offset = headerSection.iv_offset + toc[i].iv_offset;

        o_item->iv_imageData = (void*)((uint8_t*)i_image + offset);
        o_item->iv_address = xipLinkAddress(i_image) + offset;

    } while (0);

    return rc;
}
        

////////////////////////////////////////////////////////////////////////////
// Published API
////////////////////////////////////////////////////////////////////////////

int
sbe_xip_validate(void* i_image, const uint32_t i_size)
{          
    SbeXipHeader hostHeader;
    int rc = 0, i;
    uint32_t linkAddress, imageSize, extent, offset, size;
    uint8_t alignment;

    sbe_xip_translate_header(&hostHeader, (SbeXipHeader*)i_image);

    do {
        
        // Validate C/Assembler constraints.

        if (sizeof(SbeXipSection) != SIZE_OF_SBE_XIP_SECTION) {
            rc = TRACE_ERRORX(SBE_XIP_BUG,
                              "C/Assembler size mismatch(%d/%d) "
                              "for SbeXipSection\n",
                              sizeof(SbeXipSection), SIZE_OF_SBE_XIP_SECTION);
            break;
        }
                              
        if (sizeof(SbeXipToc) != SIZE_OF_SBE_XIP_TOC) {
            rc = TRACE_ERRORX(SBE_XIP_BUG,
                              "C/Assembler size mismatch(%d/%d) "
                              "for SbeXipToc\n",
                              sizeof(SbeXipToc), SIZE_OF_SBE_XIP_TOC);
            break;
        }

        if (sizeof(SbeXipHashedToc) != SIZE_OF_SBE_XIP_HASHED_TOC) {
            rc = TRACE_ERRORX(SBE_XIP_BUG,
                              "C/Assembler size mismatch(%d/%d) "
                              "for SbeXipHashedToc\n",
                              sizeof(SbeXipHashedToc), 
                              SIZE_OF_SBE_XIP_HASHED_TOC);
            break;
        }

        // Validate the image pointer and magic number

        rc = xipQuickCheck(i_image, 0);
        if (rc) break;

        // Validate the image size

        linkAddress = hostHeader.iv_linkAddress;
        imageSize = hostHeader.iv_imageSize;
        extent = linkAddress + imageSize;

        if (imageSize < sizeof(SbeXipHeader)) {
            rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR,
                              "sbe_xip_validate(%p, %u) : "
                              "The image size recorded in the image "
                              "(%u) is smaller than the header size.\n",
                              i_image, i_size, imageSize);
            break;
        }
        if (imageSize != i_size) {
            rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR,
                              "sbe_xip_validate(%p, %u) : "
                              "The image size recorded in the image "
                              "(%u) does not match the i_size parameter.\n",
                              i_image, i_size, imageSize);
            break;
        }
        if (extent <= linkAddress) {
            rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR,
                              "sbe_xip_validate(%p, %u) : "
                              "Given the link address (%u) and the "
                              "image size, the image wraps the address space\n",
                              i_image, i_size, linkAddress);
            break;
        }
        if ((imageSize % SBE_XIP_FINAL_ALIGNMENT) != 0) {
            rc = TRACE_ERRORX(SBE_XIP_ALIGNMENT_ERROR,
                              "sbe_xip_validate(%p, %u) : "
                              "The image size (%u) is not a multiple of %u\n",
                              i_image, i_size, imageSize, 
                              SBE_XIP_FINAL_ALIGNMENT);
            break;
        }

        // Validate that all sections appear to be within the image
        // bounds, and are aligned correctly.

        for (i = 0; i < SBE_XIP_SECTIONS; i++) {

            offset = hostHeader.iv_section[i].iv_offset;
            size = hostHeader.iv_section[i].iv_size;
            alignment = hostHeader.iv_section[i].iv_alignment;

            if ((offset > imageSize) || 
                ((offset + size) > imageSize) ||
                ((offset + size) < offset)) {
                rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR,
                                  "Section %d does not appear to be within "
                                  "the bounds of the image\n"
                                  "offset = %u, size = %u, image size = %u\n",
                                  i, offset, size, imageSize);
                break;
            }
            if ((offset % alignment) != 0) {
                rc = TRACE_ERRORX(SBE_XIP_ALIGNMENT_ERROR,
                                  "Section %d requires %d-byte initial "
                                  "alignment but the section offset is %u\n",
                                  i, alignment, offset);
                break;
            }
        }
        if (rc) break;

        // If the TOC exists and the image is normalized, validate each TOC
        // entry. 

        size = hostHeader.iv_section[SBE_XIP_SECTION_TOC].iv_size; 
        if (size != 0) {
            if (xipNormalized(i_image)) {
                rc = sbe_xip_map_toc(i_image, xipValidateTocEntry, 0);
                if (rc) break;
            }
        }
    } while (0);
    return rc;
}


int
sbe_xip_validate2(void* i_image, const uint32_t i_size, const uint32_t i_maskIgnores)
{          
    SbeXipHeader hostHeader;
    int rc = 0, i;
    uint32_t linkAddress, imageSize, extent, offset, size;
    uint8_t alignment;

    sbe_xip_translate_header(&hostHeader, (SbeXipHeader*)i_image);

    do {
        
        // Validate C/Assembler constraints.

        if (sizeof(SbeXipSection) != SIZE_OF_SBE_XIP_SECTION) {
            rc = TRACE_ERRORX(SBE_XIP_BUG,
                              "C/Assembler size mismatch(%d/%d) "
                              "for SbeXipSection\n",
                              sizeof(SbeXipSection), SIZE_OF_SBE_XIP_SECTION);
            break;
        }
                              
        if (sizeof(SbeXipToc) != SIZE_OF_SBE_XIP_TOC) {
            rc = TRACE_ERRORX(SBE_XIP_BUG,
                              "C/Assembler size mismatch(%d/%d) "
                              "for SbeXipToc\n",
                              sizeof(SbeXipToc), SIZE_OF_SBE_XIP_TOC);
            break;
        }

        if (sizeof(SbeXipHashedToc) != SIZE_OF_SBE_XIP_HASHED_TOC) {
            rc = TRACE_ERRORX(SBE_XIP_BUG,
                              "C/Assembler size mismatch(%d/%d) "
                              "for SbeXipHashedToc\n",
                              sizeof(SbeXipHashedToc), 
                              SIZE_OF_SBE_XIP_HASHED_TOC);
            break;
        }

        // Validate the image pointer and magic number

        rc = xipQuickCheck(i_image, 0);
        if (rc) break;

        // Validate the image size

        linkAddress = hostHeader.iv_linkAddress;
        imageSize = hostHeader.iv_imageSize;
        extent = linkAddress + imageSize;

        if (imageSize < sizeof(SbeXipHeader)) {
            rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR,
                              "sbe_xip_validate2(%p, %u) : "
                              "The image size recorded in the image "
                              "(%u) is smaller than the header size.\n",
                              i_image, i_size, imageSize);
            break;
        }
        if (imageSize != i_size && !(i_maskIgnores & SBE_XIP_IGNORE_FILE_SIZE)) {
            rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR,
                              "sbe_xip_validate2(%p, %u) : "
                              "The image size recorded in the image "
                              "(%u) does not match the i_size parameter.\n",
                              i_image, i_size, imageSize);
            break;
        }
        if (extent <= linkAddress) {
            rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR,
                              "sbe_xip_validate2(%p, %u) : "
                              "Given the link address (%u) and the "
                              "image size, the image wraps the address space\n",
                              i_image, i_size, linkAddress);
            break;
        }
        if ((imageSize % SBE_XIP_FINAL_ALIGNMENT) != 0) {
            rc = TRACE_ERRORX(SBE_XIP_ALIGNMENT_ERROR,
                              "sbe_xip_validate2(%p, %u) : "
                              "The image size (%u) is not a multiple of %u\n",
                              i_image, i_size, imageSize, 
                              SBE_XIP_FINAL_ALIGNMENT);
            break;
        }

        // Validate that all sections appear to be within the image
        // bounds, and are aligned correctly.

        for (i = 0; i < SBE_XIP_SECTIONS; i++) {

            offset = hostHeader.iv_section[i].iv_offset;
            size = hostHeader.iv_section[i].iv_size;
            alignment = hostHeader.iv_section[i].iv_alignment;

            if ((offset > imageSize) || 
                ((offset + size) > imageSize) ||
                ((offset + size) < offset)) {
                rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR,
                                  "Section %d does not appear to be within "
                                  "the bounds of the image\n"
                                  "offset = %u, size = %u, image size = %u\n",
                                  i, offset, size, imageSize);
                break;
            }
            if ((offset % alignment) != 0) {
                rc = TRACE_ERRORX(SBE_XIP_ALIGNMENT_ERROR,
                                  "Section %d requires %d-byte initial "
                                  "alignment but the section offset is %u\n",
                                  i, alignment, offset);
                break;
            }
        }
        if (rc) break;

        // If the TOC exists and the image is normalized, validate each TOC
        // entry. 

        size = hostHeader.iv_section[SBE_XIP_SECTION_TOC].iv_size; 
        if (size != 0) {
            if (xipNormalized(i_image)) {
                rc = sbe_xip_map_toc(i_image, xipValidateTocEntry, 0);
                if (rc) break;
            }
        }
    } while (0);
    return rc;
}


// Normalization:
//
// 1. Normalize the TOC, unless the image is already normalized.  The image
// must be marked as normalized before sorting.
//
// 2. Sort the TOC.
//
// 3. Clear the section offsets of any empty sections to make the section
// table reports less confusing.
//
// 4. Clear normalization status on any failure.

int
sbe_xip_normalize(void* io_image)
{
    int rc, i;
    SbeXipSection section;
    SbeXipToc* imageToc;
    SbeXipHashedToc* fixedImageToc = NULL;
    SbeXipHashedToc* fixedTocEntry = NULL;
    size_t tocEntries = 0;
    size_t fixedTocEntries = 0;
    size_t fixedEntriesRemaining = 0;
       
    do {
        rc = xipQuickCheck(io_image, 0);
        if (rc) break;

        if (!xipNormalized(io_image)) {

            rc = xipGetToc(io_image, &imageToc, &tocEntries, 0, 0);
            if (rc) break;

            rc = xipGetFixedToc(io_image, &fixedImageToc, &fixedTocEntries);
            if (rc) break;

            fixedTocEntry = fixedImageToc;
            fixedEntriesRemaining = fixedTocEntries;

            for (; tocEntries--; imageToc++) {
                rc = xipNormalizeToc(io_image, imageToc, 
                                     &fixedTocEntry, &fixedEntriesRemaining);
                if (rc) break;
                                  
            }
            if (rc) break;

            if (fixedEntriesRemaining != 0) {
                rc = TRACE_ERRORX(SBE_XIP_TOC_ERROR,
                                  "Not enough TOC entries for .fixed");
                break;
            }

            rc = xipHashCollision(fixedImageToc, fixedTocEntries);
            if (rc) break;

            ((SbeXipHeader*)io_image)->iv_normalized = 1;
        }

        rc = xipSortToc(io_image);
        if (rc) break;

        for (i = 0; i < SBE_XIP_SECTIONS; i++) {
            rc = sbe_xip_get_section(io_image, i, &section);
            if (rc) break;
            if (section.iv_size == 0) {
                xipSetSectionOffset(io_image, i, 0);
            }
        }
        if (rc) break;

    } while(0);

    ((SbeXipHeader*)io_image)->iv_normalized = (rc == 0);

    return rc;
}


int
sbe_xip_image_size(void* io_image, uint32_t* o_size)
{
    int rc;

    rc = xipQuickCheck(io_image, 0);
    if (!rc) {
        *o_size = xipImageSize(io_image);
    }
    return rc;
}


int
sbe_xip_get_section(const void* i_image,
                    const int i_sectionId,
                    SbeXipSection* o_hostSection)
{
    int rc;
    SbeXipSection *imageSection = NULL;

    rc = xipGetSectionPointer(i_image, i_sectionId, &imageSection);

    if (!rc) {
        xipTranslateSection(o_hostSection, imageSection);
    }

    return rc;
}


// If the 'big' TOC is not present, search the mini-TOCs that only index the
// .fixed and .header sections.

int
sbe_xip_find(void* i_image, 
             const char* i_id,
             SbeXipItem* o_item)
{
    int rc;
    SbeXipToc* toc;
    SbeXipItem item, *pitem;
    SbeXipSection* tocSection;

    do {
        rc = xipQuickCheck(i_image, 1);
        if (rc) break;

        rc = xipGetSectionPointer(i_image, SBE_XIP_SECTION_TOC, &tocSection);
        if (rc) break;

        if (tocSection->iv_size == 0) {
            rc = xipFixedFind(i_image, i_id, o_item);
            if (rc) {
                rc = xipHeaderFind(i_image, i_id, o_item);
            }
            break;
        }

        if (xipSorted(i_image)) {
            rc = xipBinarySearch(i_image, i_id, &toc);
        } else {
            rc = xipLinearSearch(i_image, i_id, &toc);
        }
        if (rc) break;

        if (o_item) {
            pitem = o_item;
        } else {
            pitem = &item;
        }
        rc = xipDecodeToc(i_image, toc, pitem);
        if (rc) break;

    } while (0);

    return rc;
}


int
sbe_xip_map_halt(void* io_image, 
                 int (*i_fn)(void* io_image, 
                             const uint64_t i_poreAddress,
                             const char* i_rcString,
                             void* io_arg),
                 void* io_arg)
{
    int rc;
    SbeXipSection haltSection;
    SbeXipHalt *halt;
    uint32_t size;
    uint32_t actualSize;

    do {
        rc = xipQuickCheck(io_image, 0);
        if (rc) break;

        rc = sbe_xip_get_section(io_image, SBE_XIP_SECTION_HALT, &haltSection);
        if (rc) break;

        halt = (SbeXipHalt*)((unsigned long)io_image + haltSection.iv_offset);
        size = haltSection.iv_size;
        
        while (size) {

            rc = i_fn(io_image, 
                      xipRevLe64(halt->iv_address),
                      halt->iv_string,
                      io_arg);
            if (rc) break;

            // The SbeXipHalt structure claims a 4-character string.  The
            // computation below computes the actual record size based on the
            // actual length of the string, including the 0-byte termination.

            actualSize = 8 + (((strlen(halt->iv_string) + 4) / 4) * 4);

            if (size < actualSize) {
                rc = TRACE_ERRORX(SBE_XIP_IMAGE_ERROR,
                                  "The .halt section is improperly formed\n");
                break;
            }

            size -= actualSize;
            halt = (SbeXipHalt*)((unsigned long)halt + actualSize);
        };

        if (rc) break;

    } while (0);

    return rc;
}

        
typedef struct {
    uint64_t iv_address;
    const char* iv_string;
} GetHaltStruct;


XIP_STATIC int
xipGetHaltMap(void* io_image, 
              const uint64_t i_poreAddress,
              const char* i_rcString,
              void* io_arg)
{
    int rc;

    GetHaltStruct* s = (GetHaltStruct*)io_arg;

    (void)io_image;

    if (i_poreAddress == s->iv_address) {
        s->iv_string = i_rcString;
        rc = -1;
    } else {
        rc = 0;
    }

    return rc;
}


int
sbe_xip_get_halt(void* io_image, 
                 const uint64_t i_poreAddress,
                 const char** o_rcString)
{
    int rc;
    GetHaltStruct s;

    s.iv_address = i_poreAddress;
    do {
        rc = xipQuickCheck(io_image, 0);
        if (rc) break;

        rc = sbe_xip_map_halt(io_image, xipGetHaltMap, &s);
        if (rc == 0) {
            rc = TRACE_ERRORX(SBE_XIP_ITEM_NOT_FOUND,
                              "sbe_xip_get_halt: No HALT code is associated "
                              "with address " F0x012llx "\n", i_poreAddress);
        } else if (rc < 0) {
            *o_rcString = s.iv_string;
            rc = 0;
        }
    } while (0);

    return rc;
}


int
sbe_xip_get_scalar(void *i_image, const char* i_id, uint64_t* o_data)
{
    int rc;
    SbeXipItem item;
    
    rc = sbe_xip_find(i_image, i_id, &item);
    if (!rc) {
        switch (item.iv_type) {
        case SBE_XIP_UINT8:
            *o_data = *((uint8_t*)(item.iv_imageData));
            break;
        case SBE_XIP_UINT32:
            *o_data = xipRevLe32(*((uint32_t*)(item.iv_imageData)));
            break;
        case SBE_XIP_UINT64:
            *o_data = xipRevLe64(*((uint64_t*)(item.iv_imageData)));
            break;
        case SBE_XIP_ADDRESS:
            *o_data = item.iv_address;
            break;
        default:
            rc = TRACE_ERROR(SBE_XIP_TYPE_ERROR);
            break;
        }
    }
    return rc;
}


int
sbe_xip_get_element(void *i_image, 
                    const char* i_id,
                    const uint32_t i_index,
                    uint64_t* o_data)
{
    int rc;
    SbeXipItem item;
    
    do {
        rc = sbe_xip_find(i_image, i_id, &item);
        if (rc) break;

        if ((item.iv_elements != 0) && (i_index >= item.iv_elements)) {
            rc = TRACE_ERROR(SBE_XIP_BOUNDS_ERROR);
            break;
        }

        switch (item.iv_type) {
        case SBE_XIP_UINT8:
            *o_data = ((uint8_t*)(item.iv_imageData))[i_index];
            break;
        case SBE_XIP_UINT32:
            *o_data = xipRevLe32(((uint32_t*)(item.iv_imageData))[i_index]);
            break;
        case SBE_XIP_UINT64:
            *o_data = xipRevLe64(((uint64_t*)(item.iv_imageData))[i_index]);
            break;
        default:
            rc = TRACE_ERROR(SBE_XIP_TYPE_ERROR);
            break;
        }
        if (rc) break;

    } while (0);
    return rc;
}


int
sbe_xip_get_string(void *i_image, const char* i_id, char** o_data)
{
    int rc;
    SbeXipItem item;
    
    rc = sbe_xip_find(i_image, i_id, &item);
    if (!rc) {
        switch (item.iv_type) {
        case SBE_XIP_STRING:
            *o_data = (char*)(item.iv_imageData);
            break;
        default:
            rc = TRACE_ERROR(SBE_XIP_TYPE_ERROR);
            break;
        }
    }
    return rc;
}


int
sbe_xip_read_uint64(const void *i_image, 
                    const uint64_t i_poreAddress,
                    uint64_t* o_data)
{
    int rc;

    do {
        rc = xipQuickCheck(i_image, 0);
        if (rc) break;

        rc = xipValidatePoreAddress(i_image, i_poreAddress, 8);
        if (rc) break;

        if (i_poreAddress % 8) {
            rc = TRACE_ERROR(SBE_XIP_ALIGNMENT_ERROR);
            break;
        }

        *o_data = 
            xipRevLe64(*((uint64_t*)xipPore2Host(i_image, i_poreAddress)));

    } while(0);

    return rc;
}


int
sbe_xip_set_scalar(void* io_image, const char* i_id, const uint64_t i_data)
{
    int rc;
    SbeXipItem item;

    rc = sbe_xip_find(io_image, i_id, &item);
    if (!rc) {
        switch(item.iv_type) {
        case SBE_XIP_UINT8:
            *((uint8_t*)(item.iv_imageData)) = (uint8_t)i_data;
            break;
        case SBE_XIP_UINT32:
            *((uint32_t*)(item.iv_imageData)) = xipRevLe32((uint32_t)i_data);
            break;
        case SBE_XIP_UINT64:
            *((uint64_t*)(item.iv_imageData)) = xipRevLe64((uint64_t)i_data);
            break;
        default:
            rc = TRACE_ERROR(SBE_XIP_TYPE_ERROR);
            break;
        }
    }
    return rc;
}


int
sbe_xip_set_element(void *i_image, 
                    const char* i_id,
                    const uint32_t i_index,
                    const uint64_t i_data)
{
    int rc;
    SbeXipItem item;
    
    do {
        rc = sbe_xip_find(i_image, i_id, &item);
        if (rc) break;

        if ((item.iv_elements != 0) && (i_index >= item.iv_elements)) {
            rc = TRACE_ERROR(SBE_XIP_BOUNDS_ERROR);
            break;
        }

        switch (item.iv_type) {
        case SBE_XIP_UINT8:
            ((uint8_t*)(item.iv_imageData))[i_index] = (uint8_t)i_data;
            break;
        case SBE_XIP_UINT32:
            ((uint32_t*)(item.iv_imageData))[i_index] = 
                xipRevLe32((uint32_t)i_data);
            break;
        case SBE_XIP_UINT64:
            ((uint64_t*)(item.iv_imageData))[i_index] = 
                xipRevLe64((uint64_t)i_data);
            break;
        default:
            rc = TRACE_ERROR(SBE_XIP_TYPE_ERROR);
            break;
        }
        if (rc) break;

    } while (0);

    return rc;
}


int
sbe_xip_set_string(void *i_image, const char* i_id, const char* i_data)
{
    int rc;
    SbeXipItem item;
    char* dest;
    
    rc = sbe_xip_find(i_image, i_id, &item);
    if (!rc) {
        switch (item.iv_type) {
        case SBE_XIP_STRING:
            dest = (char*)(item.iv_imageData);
            if (strlen(dest) < strlen(i_data)) {
                memcpy(dest, i_data, strlen(dest));
            } else {
                strcpy(dest, i_data);
            }
            break;
        default:
            rc = TRACE_ERROR(SBE_XIP_TYPE_ERROR);
            break;
        }
    }
    return rc;
}


int
sbe_xip_write_uint64(void *io_image, 
                     const uint64_t i_poreAddress,
                     const uint64_t i_data)
{
    int rc;

    do {
        rc = xipQuickCheck(io_image, 0);
        if (rc) break;

        rc = xipValidatePoreAddress(io_image, i_poreAddress, 8);
        if (rc) break;

        if (i_poreAddress % 8) {
            rc = TRACE_ERROR(SBE_XIP_ALIGNMENT_ERROR);
            break;
        }

        *((uint64_t*)xipPore2Host(io_image, i_poreAddress)) = 
            xipRevLe64(i_data);

    } while(0);

    return rc;
}


int
sbe_xip_delete_section(void* io_image, const int i_sectionId)
{
    int rc, final;
    SbeXipSection section;

    do {
        rc = xipQuickCheck(io_image, 1);
        if (rc) break;

        rc = sbe_xip_get_section(io_image, i_sectionId, &section);
        if (rc) break;


        // Deleting an empty section is a NOP.  Otherwise the section must be
        // the final section of the image. Update the sizes and re-establish
        // the final image alignment.

        if (section.iv_size == 0) break;

        rc = xipFinalSection(io_image, &final);
        if (rc) break;

        if (final != i_sectionId) {
            rc = TRACE_ERRORX(SBE_XIP_SECTION_ERROR,
                              "Attempt to delete non-final section %d\n",
                              i_sectionId);
            break;
        }

        xipSetSectionOffset(io_image, i_sectionId, 0);
        xipSetSectionSize(io_image, i_sectionId, 0);


        // For cleanliness we also remove any alignment padding that had been
        // appended between the now-last section and the deleted section, then
        // re-establish the final alignment. The assumption is that all images
        // always have the correct final alignment, so there is no way this
        // could overflow a designated buffer space since the image size is
        // the same or has been reduced.

        rc = xipFinalSection(io_image, &final);
        if (rc) break;

        rc = sbe_xip_get_section(io_image, final, &section);
        if (rc) break;

        xipSetImageSize(io_image, section.iv_offset + section.iv_size);
        xipFinalAlignment(io_image);

    } while (0);

    return rc;
}


#ifndef PPC_HYP

// This API is not needed by PHYP procedures, and is elided since PHYP does
// not support malloc().

int
sbe_xip_duplicate_section(const void* i_image, 
                          const int i_sectionId,
                          void** o_duplicate,
                          uint32_t* o_size)
{
    SbeXipSection section;
    int rc;

    *o_duplicate = 0;

    do {
        rc = xipQuickCheck(i_image, 0);
        if (rc) break;

        rc = sbe_xip_get_section(i_image, i_sectionId, &section);
        if (rc) break;

        if (section.iv_size == 0) {
            rc = TRACE_ERRORX(SBE_XIP_SECTION_ERROR,
                              "Attempt to duplicate empty section %d\n",
                              i_sectionId);
            break;
        }

        *o_duplicate = malloc(section.iv_size);
        *o_size = section.iv_size;

        if (*o_duplicate == 0) {
            rc = TRACE_ERROR(SBE_XIP_NO_MEMORY);
            break;
        }

        memcpy(*o_duplicate, 
               xipHostAddressFromOffset(i_image, section.iv_offset),
               section.iv_size);
        
        
    } while (0);

    if (rc) {
        free(*o_duplicate);
        *o_duplicate = 0;
        *o_size = 0;
    }

    return rc;
}

#endif // PPC_HYP


// The append must be done in such a way that if the append fails, the image
// is not modified. This behavior is required by applications that
// speculatively append until the allocation fails, but still require the
// final image to be valid. To accomplish this the initial image size and
// section statistics are captured at entry, and restored in the event of an
// error.

int
sbe_xip_append(void* io_image,
               const int i_sectionId,
               const void* i_data,
               const uint32_t i_size,
               const uint32_t i_allocation,
               uint32_t* o_sectionOffset)
{
    SbeXipSection section, initialSection;
    int rc, final, restoreOnError;
    void* hostAddress;
    uint32_t pad;
    uint32_t initialSize = 0;

    do {
        restoreOnError = 0;

        rc = xipQuickCheck(io_image, 1);
        if (rc) break;

        rc = sbe_xip_get_section(io_image, i_sectionId, &section);
        if (rc) break;

        if (i_size == 0) break;

        initialSection = section;
        initialSize = xipImageSize(io_image);
        restoreOnError = 1;

        if (section.iv_size == 0) {

            // The section is empty, and now becomes the final section. Pad
            // the image to the specified section alignment.  Note that the
            // size of the previously final section does not change.

            rc = xipPadImage(io_image, i_allocation, section.iv_alignment, 
                             &pad);
            if (rc) break;
            section.iv_offset = xipImageSize(io_image);

        } else {

            // Otherwise, the section must be the final section in order to
            // continue. Remove any padding from the image.

            rc = xipFinalSection(io_image, &final);
            if (rc) break;

            if (final != i_sectionId) {
                rc = TRACE_ERRORX(SBE_XIP_SECTION_ERROR,
                                  "Attempt to append to non-final section "
                                  "%d\n", i_sectionId);
                break;
            }
            xipSetImageSize(io_image, section.iv_offset + section.iv_size);
        }


        // Make sure the allocated space won't overflow. Set the return
        // parameter o_sectionOffset and copy the new data into the image (or
        // simply clear the space).

        if ((xipImageSize(io_image) + i_size) > i_allocation) {
            rc = TRACE_ERROR(SBE_XIP_WOULD_OVERFLOW);
            break;
        }            
        if (o_sectionOffset != 0) {
            *o_sectionOffset = section.iv_size;
        }

        hostAddress = 
            xipHostAddressFromOffset(io_image, xipImageSize(io_image));
        if (i_data == 0) {
            memset(hostAddress, 0, i_size);
        } else {
            memcpy(hostAddress, i_data, i_size);
        }


        // Update the image size and section table. Note that the final
        // alignment may push out of the allocation.

        xipSetImageSize(io_image, xipImageSize(io_image) + i_size);
        xipFinalAlignment(io_image);

        if (xipImageSize(io_image) > i_allocation) {
            rc = TRACE_ERROR(SBE_XIP_WOULD_OVERFLOW);
            break;
        }            

        section.iv_size += i_size;

        if (xipPutSection(io_image, i_sectionId, &section) != 0) {
            rc = TRACE_ERROR(SBE_XIP_BUG); /* Can't happen */
            break;
        }


        // Special case

        if (i_sectionId == SBE_XIP_SECTION_TOC) {
            ((SbeXipHeader*)io_image)->iv_tocSorted = 0;
        }

    } while (0);

    if (rc && restoreOnError) {
        if (xipPutSection(io_image, i_sectionId, &initialSection) != 0) {
            rc = TRACE_ERROR(SBE_XIP_BUG); /* Can't happen */
        }
        xipSetImageSize(io_image, initialSize);
    }
     
    return rc;
}


int
sbe_xip_section2pore(const void* i_image, 
                     const int i_sectionId,
                     const uint32_t i_offset,
                     uint64_t* o_poreAddress)
{
    int rc;
    SbeXipSection section;

    do {
        rc = xipQuickCheck(i_image, 0);
        if (rc) break;

        rc = sbe_xip_get_section(i_image, i_sectionId, &section);
        if (rc) break;

        if (section.iv_size == 0) {
            rc = TRACE_ERROR(SBE_XIP_SECTION_ERROR);
            break;
        }

        if (i_offset > (section.iv_offset + section.iv_size)) {
            rc = TRACE_ERROR(SBE_XIP_INVALID_ARGUMENT);
            break;
        }

        *o_poreAddress = xipLinkAddress(i_image) + section.iv_offset + i_offset;

        if (*o_poreAddress % 4) {
            rc = TRACE_ERROR(SBE_XIP_ALIGNMENT_ERROR);
            break;
        }

    } while(0);

    return rc;
}


int
sbe_xip_pore2section(const void* i_image, 
                     const uint64_t i_poreAddress,
                     int* i_section,
                     uint32_t* i_offset)
{
    int rc;

    do {
        rc = xipQuickCheck(i_image, 0);
        if (rc) break;

        rc = xipPore2Section(i_image, i_poreAddress, i_section, i_offset);

    } while(0);

    return rc;
}


int
sbe_xip_pore2host(const void* i_image, 
                  const uint64_t i_poreAddress,
                  void** o_hostAddress)
{
    int rc;

    do {
        rc = xipQuickCheck(i_image, 0);
        if (rc) break;

        if ((i_poreAddress < xipLinkAddress(i_image)) ||
            (i_poreAddress > 
             (xipLinkAddress(i_image) + xipImageSize(i_image)))) {
            rc = TRACE_ERROR(SBE_XIP_INVALID_ARGUMENT);
            break;
        }

        *o_hostAddress = 
            xipHostAddressFromOffset(i_image, 
                                     i_poreAddress - xipLinkAddress(i_image));
    } while(0);

    return rc;
}
    
    
int
sbe_xip_host2pore(const void* i_image, 
                  void* i_hostAddress,
                  uint64_t* o_poreAddress)
{
    int rc;

    do {
        rc = xipQuickCheck(i_image, 0);
        if (rc) break;

        if ((i_hostAddress < i_image) ||
            (i_hostAddress > 
             xipHostAddressFromOffset(i_image, xipImageSize(i_image)))) {
            rc = TRACE_ERROR(SBE_XIP_INVALID_ARGUMENT);
            break;
        }

        *o_poreAddress = xipLinkAddress(i_image) + 
            ((unsigned long)i_hostAddress - (unsigned long)i_image);
        if (*o_poreAddress % 4) {
            rc = TRACE_ERROR(SBE_XIP_ALIGNMENT_ERROR);
            break;
        }
    } while(0);

    return rc;
}
        

void
sbe_xip_translate_header(SbeXipHeader* o_dest, const SbeXipHeader* i_src)
{
#ifndef _BIG_ENDIAN
    int i;
    SbeXipSection* destSection;
    const SbeXipSection* srcSection;

#if SBE_XIP_HEADER_VERSION != 8
#error This code assumes the SBE-XIP header version 8 layout
#endif

    o_dest->iv_magic = xipRevLe64(i_src->iv_magic);
    o_dest->iv_entryOffset = xipRevLe64(i_src->iv_entryOffset);
    o_dest->iv_linkAddress = xipRevLe64(i_src->iv_linkAddress);
    o_dest->iv_ptsVersion = xipRevLe64(i_src->iv_ptsVersion);

    for (i = 0; i < 4; i++) {
        o_dest->iv_reserved64[i] = 0;
    }

    for (i = 0, destSection = o_dest->iv_section, 
             srcSection = i_src->iv_section;
         i < SBE_XIP_SECTIONS; 
         i++, destSection++, srcSection++) {
        xipTranslateSection(destSection, srcSection);
    }

    o_dest->iv_imageSize = xipRevLe32(i_src->iv_imageSize);
    o_dest->iv_buildDate = xipRevLe32(i_src->iv_buildDate);
    o_dest->iv_buildTime = xipRevLe32(i_src->iv_buildTime);

    for (i = 0; i < 5; i++) {
        o_dest->iv_reserved32[i] = 0;
    }

    o_dest->iv_headerVersion = i_src->iv_headerVersion;
    o_dest->iv_normalized = i_src->iv_normalized;
    o_dest->iv_tocSorted = i_src->iv_tocSorted;

    for (i = 0; i < 3; i++) {
        o_dest->iv_reserved8[i] = 0;
    }

    memcpy(o_dest->iv_buildUser, i_src->iv_buildUser, 
           sizeof(i_src->iv_buildUser));
    memcpy(o_dest->iv_buildHost, i_src->iv_buildHost, 
           sizeof(i_src->iv_buildHost));
    memcpy(o_dest->iv_reservedChar, i_src->iv_reservedChar, 
           sizeof(i_src->iv_reservedChar));

#else
    if (o_dest != i_src) {
        *o_dest = *i_src;
    }
#endif  /* _BIG_ENDIAN */
}
    

int
sbe_xip_map_toc(void* io_image, 
                int (*i_fn)(void* io_image,
                            const SbeXipItem* i_item, 
                            void* io_arg),
                void* io_arg)
{
    int rc;
    SbeXipToc *imageToc;
    SbeXipItem item;
    size_t entries;

    do {
        rc = xipQuickCheck(io_image, 0);
        if (rc) break;

        rc = xipGetToc(io_image, &imageToc, &entries, 0, 0);
        if (rc) break;

        for (; entries--; imageToc++) {
            rc = xipDecodeToc(io_image, imageToc, &item);
            if (rc) break;
            rc = i_fn(io_image, &item, io_arg);
            if (rc) break;
        }
    } while(0);

    return rc;
}
