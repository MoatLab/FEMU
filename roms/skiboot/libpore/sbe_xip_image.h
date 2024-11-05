/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/usr/hwpf/hwp/build_winkle_images/p8_slw_build/sbe_xip_image.h $ */
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
#ifndef __SBE_XIP_IMAGE_H
#define __SBE_XIP_IMAGE_H

// $Id: sbe_xip_image.h,v 1.26 2015/07/29 23:40:17 cmolsen Exp $
// $Source: /afs/awd/projects/eclipz/KnowledgeBase/.cvsroot/eclipz/chips/p8/working/procedures/ipl/sbe/sbe_xip_image.h,v $
//-----------------------------------------------------------------------------
// *! (C) Copyright International Business Machines Corp. 2011
// *! All Rights Reserved -- Property of IBM
// *! ***  ***
//-----------------------------------------------------------------------------
// *! OWNER NAME: Bishop Brock          Email: bcbrock@us.ibm.com
//------------------------------------------------------------------------------

/// \file sbe_xip_image.h
/// \brief Everything related to creating and manipulating SBE-XIP binary
/// images.

#include "fapi_sbe_common.H"

/// Current version (fields, layout, sections) of the SBE_XIP header
///
/// If any changes are made to this file or to sbe_xip_header.H, please update
/// the header version and follow-up on all of the error messages.

#define SBE_XIP_HEADER_VERSION 8

/// \defgroup sbe_xip_magic_numbers SBE-XIP magic numbers
///
/// An SBE-XIP magic number is a 64-bit constant.  The 4 high-order bytes
/// contain the ASCII characters "XIP " and identify the image as an SBE-XIP
/// image, while the 4 low-order bytes identify the type of the image.
///
/// @{

#define SBE_XIP_MAGIC     0x58495020               // "XIP "
#define SBE_BASE_MAGIC    ULL(0x5849502042415345)  // "XIP BASE"
#define SBE_SEEPROM_MAGIC ULL(0x584950205345504d)  // "XIP SEPM"
#define SBE_CENTAUR_MAGIC ULL(0x58495020434e5452)  // "XIP CNTR"

/// @}


/// \defgroup sbe_xip_sections SBE-XIP Image Section Indexes
///
/// These constants define the order that the SbeXipSection structures appear
/// in the header, which is not necessarily the order the sections appear in
/// the binary image.  Given that SBE-XIP image contents are tightly
/// controlled, we use this simple indexing scheme for the allowed sections
/// rather than a more general approach, e.g., allowing arbitrary sections
/// identified by their names.
///
/// @{

// -*- DO NOT REORDER OR EDIT THIS SET OF CONSTANTS WITHOUT ALSO EDITING -*-
// -*- THE ASSEMBLER LAYOUT IN sbe_xip_header.H.                         -*-

#define SBE_XIP_SECTION_HEADER      0
#define SBE_XIP_SECTION_FIXED       1
#define SBE_XIP_SECTION_FIXED_TOC   2
#define SBE_XIP_SECTION_IPL_TEXT    3
#define SBE_XIP_SECTION_IPL_DATA    4
#define SBE_XIP_SECTION_TEXT        5
#define SBE_XIP_SECTION_DATA        6
#define SBE_XIP_SECTION_TOC         7
#define SBE_XIP_SECTION_STRINGS     8
#define SBE_XIP_SECTION_HALT        9
#define SBE_XIP_SECTION_PIBMEM0    10
#define SBE_XIP_SECTION_DCRINGS    11
#define SBE_XIP_SECTION_RINGS      12
#define SBE_XIP_SECTION_SLW        13
#define SBE_XIP_SECTION_FIT        14
#define SBE_XIP_SECTION_FFDC       15

#define SBE_XIP_SECTIONS 16

/// @}


/// \defgroup sbe_xip_validate() ignore masks.
///
/// These defines, when matched in sbe_xip_validate(), cause the validation
/// to skip the check of the corresponding property. The purpose is to more
/// effectively debug images that may be damaged and which have excess info
/// before or after the image. The latter will be the case when dumping the
/// image as a memory block without knowing where the image starts and ends.
///
/// @{

#define SBE_XIP_IGNORE_FILE_SIZE (uint32_t)0x00000001
#define SBE_XIP_IGNORE_ALL       (uint32_t)0x80000000

/// @}


#ifndef __ASSEMBLER__

/// Applications can expand this macro to create an array of section names.
#define SBE_XIP_SECTION_NAMES(var)              \
    const char* var[] = {                       \
        ".header",                              \
        ".fixed",                               \
        ".fixed_toc",                           \
        ".ipl_text",                            \
        ".ipl_data",                            \
        ".text",                                \
        ".data",                                \
        ".toc",                                 \
        ".strings",                             \
        ".halt",                                \
        ".pibmem0",                             \
        ".dcrings",                             \
        ".rings",                               \
        ".slw",                                 \
        ".fit",                                 \
        ".ffdc",                                \
    }

/// Applications can use this macro to safely index the array of section
/// names. 
#define SBE_XIP_SECTION_NAME(var, n)                                   \
    ((((n) < 0) || ((n) > (int)(sizeof(var) / sizeof(char*)))) ?        \
     "Bug : Invalid SBE-XIP section name" : var[n])


#endif  /* __ASSEMBLER__ */


/// Maximum section alignment for SBE-XIP sections
#define SBE_XIP_MAX_SECTION_ALIGNMENT 128

/// \defgroup sbe_xip_toc_types SBE-XIP Table of Contents data types
///
/// These are the data types stored in the \a iv_type field of the SbeXipToc
/// objects.  These must be defined as manifest constants because they are
/// required to be recognized as manifest constants in C (as opposed to C++)
/// code.
///
/// NB: The 0x0 code is purposefully left undefined to catch bugs.
///
/// @{

/// Data is a single unsigned byte
#define SBE_XIP_UINT8 0x01

/// Data is a 32-bit unsigned integer
#define SBE_XIP_UINT32 0x02

/// Data is a 64-bit unsigned integer
#define SBE_XIP_UINT64 0x03

/// Data is a 0-byte terminated ASCII string
#define SBE_XIP_STRING 0x04

/// Data is an address
#define SBE_XIP_ADDRESS 0x05

/// The maximum type number
#define SBE_XIP_MAX_TYPE_INDEX 0x05

/// Applications can expand this macro to get access to string forms of the
/// SBE-XIP data types if desired.
#define SBE_XIP_TYPE_STRINGS(var)               \
    const char* var[] = {                       \
        "Illegal 0 Code",                       \
        "SBE_XIP_UINT8",                        \
        "SBE_XIP_UINT32",                       \
        "SBE_XIP_UINT64",                       \
        "SBE_XIP_STRING",                       \
        "SBE_XIP_ADDRESS",                      \
    }

/// Applications can expand this macro to get access to abbreviated string
/// forms of the SBE-XIP data types if desired.
#define SBE_XIP_TYPE_ABBREVS(var)               \
    const char* var[] = {                       \
        "Illegal 0 Code",                       \
        "u8 ",                                  \
        "u32",                                  \
        "u64",                                  \
        "str",                                  \
        "adr",                                  \
    }

/// Applications can use this macro to safely index either array of SBE-XIP
/// type strings.
#define SBE_XIP_TYPE_STRING(var, n)                     \
    (((n) > (sizeof(var) / sizeof(char*))) ?            \
     "Invalid SBE-XIP type specification" : var[n])

/// @}


/// Final alignment constraint for SBE-XIP images.
///
/// PORE images are required to be multiples of 8 bytes in length, to
/// guarantee that the PoreVe will be able to complete any 8-byte load/store.
#define SBE_XIP_FINAL_ALIGNMENT 8


////////////////////////////////////////////////////////////////////////////
// C Definitions
////////////////////////////////////////////////////////////////////////////

#ifndef __ASSEMBLER__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
#if 0
} /* So __cplusplus doesn't mess w/auto-indent */
#endif

/// SBE-XIP Section information
///
/// This structure defines the data layout of section table entries in the
/// SBE-XIP image header.

// -*- DO NOT REORDER OR EDIT THIS STRUCTURE DEFINITION WITHOUT ALSO    -*-
// -*- EDITING THE ASSEMBLER LAYOUT IN sbe_xip_header.H                 -*-

typedef struct {

    /// The offset (in bytes) of the section from the beginning of the image
    ///
    /// In normalized images the section offset will always be 0 if the
    /// section size is also 0.
    uint32_t iv_offset;

    /// The size of the section in bytes, exclusive of alignment padding
    ///
    /// This is the size of the program-significant data in the section,
    /// exclusive of any alignment padding or reserved or extra space.  The
    /// alignment padding (reserved space) is not represented explicitly, but
    /// is only implied by the offset of any subsequent non-empty section, or
    /// in the case of the final section in the image, the image size.
    ///
    /// Regardless of the \a iv_offset, if the \a iv_size of a section is 0 it
    /// should be considered "not present" in the image.  In normalized images
    /// the section offset will always be 0 if the section size is also 0.
    uint32_t iv_size;

    /// The required initial alignment for the section offset
    ///
    /// The PORE and the applications using SBE-XIP images have strict
    /// alignment/padding requirements.  The PORE does not handle any type of
    /// unaligned instruction or data fetches.  Some sections and subsections
    /// must also be POWER cache-line aligned. The \a iv_alignment applies to
    /// the first byte of the section. PORE images are also required to be
    /// multiples of 8 bytes in length, to guarantee that the PoreVe will be
    /// able to complete any 8-byte load/store.  These constraints are checked
    /// by sbe_xip_validate() and enforced by sbe_xip_append(). The alignment
    /// constraints may force a section to be padded, which may create "holes"
    /// in the image as explained in the comments for the \a iv_size field.
    ///
    /// Note that alignment constraints are always checked relative to the
    /// first byte of the image for in-memory images, not relative to the host
    /// address. Alignment specifications are required to be a power-of-2.
    uint8_t iv_alignment;

    /// Reserved structure alignment padding; Pad to 12 bytes
    uint8_t iv_reserved8[3];

} SbeXipSection;

/// The SbeXipSection structure is created by assembler code and is expected
/// to have the same size in C code.  This constraint is checked in
/// sbe_xip_validate(). 
#define SIZE_OF_SBE_XIP_SECTION 12


/// SBE-XIP binary image header
///
/// This header occupies the initial bytes of an SBE-XIP binary image.
/// The header contents are documented here, however the structure is actually
/// defined in the file sbe_xip_header.S, and these two definitions must be
/// kept consistent.
///
/// The header is a fixed-format representation of the most critical
/// information about the image.  The large majority of information about the
/// image and its contents are available through the searchable table of
/// contents. PORE code itself normally accesses the data directly through
/// global symbols. 
///
/// The header only contains information 1) required by OTPROM code (e.g., the
/// entry point); 2) required by search and updating APIs (e.g., the
/// locations and sizes of all of the sections.); a few pieces of critical
/// meta-data (e.g., information about the image build process).
///
/// Any entries that are accessed by PORE code are required to be 64 bits, and
/// will appear at the beginning of the header.
///
/// The header also contains bytewise offsets and sizes of all of the sections
/// that are assembled to complete the image.  The offsets are relative to the
/// start of the image (where the header is loaded).  The sizes include any
/// padding inserted by the link editor to guarantee section alignment.
///
/// Every field of the header is also accesssible through the searchable table
/// of contents as documented in sbe_xip_header.S.

// -*- DO NOT REORDER OR EDIT THIS STRUCTURE DEFINITION WITHOUT ALSO     -*-
// -*- EDITING THE ASSEMBLER LAYOUT IN sbe_xip_header.S, AND WITHOUT     -*-
// -*- UPDATING THE sbe_xip_translate_header() API IN sbe_xip_image.c.   -*-

typedef struct {

    //////////////////////////////////////////////////////////////////////
    // Identification - 8-byte aligned; 8 entries
    //////////////////////////////////////////////////////////////////////

    /// Contains SBE_XIP_MAGIC to identify an SBE-XIP image
    uint64_t iv_magic;

    /// The offset of the SBE-XIP entry point from the start of the image
    uint64_t iv_entryOffset;

    /// The base address used to link the image, as a full relocatable PORE
    /// address 
    uint64_t iv_linkAddress;

    /// PTS version
    uint64_t iv_ptsVersion;

    /// Reserved for future expansion
    uint64_t iv_reserved64[4];

    //////////////////////////////////////////////////////////////////////
    // Section Table - 4-byte aligned; 16 entries
    //////////////////////////////////////////////////////////////////////

    SbeXipSection iv_section[SBE_XIP_SECTIONS];

    //////////////////////////////////////////////////////////////////////
    // Other information - 4-byte aligned; 8 entries
    //////////////////////////////////////////////////////////////////////

    /// The size of the image (including padding) in bytes
    uint32_t iv_imageSize;

    /// Build date generated by `date +%Y%m%d`, e.g., 20110630	
    uint32_t iv_buildDate;

    /// Build time generated by `date +%H%M`, e.g., 0756
    uint32_t iv_buildTime;

    /// Reserved for future expansion
    uint32_t iv_reserved32[5];

    //////////////////////////////////////////////////////////////////////
    // Other Information - 1-byte aligned; 8 entries
    //////////////////////////////////////////////////////////////////////

    /// Header format version number
    uint8_t iv_headerVersion;

    /// Indicates whether the image has been normalized (0/1)
    uint8_t iv_normalized;

    /// Indicates whether the TOC has been sorted to speed searching (0/1)
    uint8_t iv_tocSorted;

    /// Reserved for future expansion
    uint8_t iv_reserved8[5];

    //////////////////////////////////////////////////////////////////////
    // Strings; 64 characters allocated
    //////////////////////////////////////////////////////////////////////

    /// Build user, generated by `id -un`
    char iv_buildUser[16];

    /// Build host, generated by `hostname`
    char iv_buildHost[24];

    /// Reserved for future expansion
    char iv_reservedChar[24];
    
} SbeXipHeader;


/// A C-structure form of the SBE-XIP Table of Contents (TOC) entries
///
/// The .toc section consists entirely of an array of these structures.
/// TOC entries are never accessed by PORE code. 
///
/// These structures store indexing information for global data required to be
/// manipulated by external tools.  The actual data is usually allocated in a
/// data section and manipulated by the SBE code using global or local symbol
/// names.  Each TOC entry contains a pointer to a keyword string naming the
/// data, the address of the data (or the data itself), the data type,
/// meta-information about the data, and for vectors the vector size.

// -*- DO NOT REORDER OR EDIT THIS STRUCTURE DEFINITION WITHOUT ALSO     -*-
// -*- EDITING THE ASSEMBLER MACROS (BELOW) THAT CREATE THE TABLE OF     -*-
// -*- CONTENTS ENTRIES.                                                 -*-

typedef struct {

    /// A pointer to a 0-byte terminated ASCII string identifying the data.
    ///
    /// When allocated by the .xip_toc macro this is a pointer to the string
    /// form of the symbol name for the global or local symbol associated with
    /// the data which is allocated in the .strings section. This pointer is
    /// not aligned.
    ///
    /// When the image is normalized this pointer is replaced by the offset of
    /// the string in the .strings section.
    uint32_t iv_id;

    /// A 32-bit pointer locating the data
    ///
    /// This field is initially populated by the link editor.  For scalar,
    /// vector and string types this is the final relocated address of the
    /// first byte of the data.  For address types, this is the relocated
    /// address.  When the image is normalized, these addresses are converted
    /// into the equivalent offsets from the beginning of the section holding
    /// the data.
    uint32_t iv_data;

    /// The type of the data; See \ref sbe_xip_toc_types.
    uint8_t iv_type;

    /// The section containing the data; See \ref sbe_xip_sections.
    uint8_t iv_section;

    /// The number of elements for vector types, otherwise 1 for scalar types
    /// and addresses.
    ///
    /// Vectors are naturally limited in size, e.g. to the number of cores,
    /// chips in a node, DD-levels etc.  If \a iv_elements is 0 then no bounds
    /// checking is done on get/set accesses of the data.
    uint8_t iv_elements;

    /// Structure alignment padding; Pad to 12 bytes
    uint8_t iv_pad;

} SbeXipToc;

/// The SbeXipToc structure is created by assembler code and is expected
/// to have the same size in C code.  This constraint is checked in
/// sbe_xip_validate(). 
#define SIZE_OF_SBE_XIP_TOC 12


/// A C-structure form of hashed SBE-XIP Table of Contents (TOC) entries
///
/// This structure was introduced in order to allow a small TOC for the .fixed
/// section to support minimum-sized SEEPROM images in which the global TOC
/// and all strings have been stripped out.  In this structure the index
/// string has been replaced by a 32-bit hash, and there is no longer a record
/// of the original data name other then the hash.  The section of the data is
/// assumed to be .fixed, with a maximum 16-bit offset.
///
/// These structures are created when entries are made in the .fixed section.
/// They are created empty, then filled in during image normalization.
///
/// This structure allows the sbe_xip_get*() and sbe_xip_set*() APIs to work
/// even on highly-stripped SEEPROM images.  

typedef struct {

    /// A 32-bit hash (FNV-1a) of the Id string.
    uint32_t iv_hash;

    /// The offset in bytes from the start of the (implied) section of the data
    uint16_t iv_offset;

    /// The type of the data; See \ref sbe_xip_toc_types.
    uint8_t iv_type;

    /// The number of elements for vector types, otherwise 1 for scalar types
    /// and addresses.
    ///
    /// Vectors are naturally limited in size, e.g. to the number of cores,
    /// chips in a node, DD-levels etc.  If \a iv_elements is 0 then no bounds
    /// checking is done on get/set accesses of the data.
    uint8_t iv_elements;

} SbeXipHashedToc;

/// The SbeXipHashedToc structure is created by assembler code and is expected
/// to have the same size in C code.  This constraint is checked in
/// sbe_xip_validate().
#define SIZE_OF_SBE_XIP_HASHED_TOC 8


/// A decoded TOC entry for use by applications
///
/// This structure is a decoded form of a normalized TOC entry, filled in by
/// the sbe_xip_decode_toc() and sbe_xip_find() APIs.  This structure is
/// always returned with data elements in host-endian format. 
///
/// In the event that the TOC has been removed from the image, this structure
/// will also be returned by sbe_xip_find() with information populated from
/// the .fixed_toc section if possible.  In this case the field \a iv_partial
/// will be set and only the fields \a iv_address, \a iv_imageData, \a iv_type
/// and \a iv_elements will be populated (all other fields will be set to 0).
///
/// \note Only special-purpose applications will ever need to use this
/// structure given that the higher-level APIs sbe_xip_get_*() and
/// sbe_xip_set_*() are provided and should be used if possible, especially
/// given that the information may be truncated as described above.

typedef struct {

    /// A pointer to the associated TOC entry as it exists in the image
    ///
    ///  If \a iv_partial is set this field is returned as 0.
    SbeXipToc* iv_toc;

    /// The full relocatable PORE address
    ///
    /// All relocatable addresses are computed from the \a iv_linkAddress
    /// stored in the header. For scalar and string data, this is the
    /// relocatable address of the data.  For address-only entries, this is
    /// the indexed address itself. 
    uint64_t iv_address;

    /// A host pointer to the first byte of text or data within the image
    ///
    /// For scalar or string types this is a host pointer to the first byte of
    /// the data.  For code pointers (addresses) this is host pointer to the
    /// first byte of code.  Note that any use of this field requires the
    /// caller to handle conversion of the data to host endian-ness if
    /// required.  Only 8-bit and string data can be used directly on all
    /// hosts.
    void* iv_imageData;

    /// The item name
    ///
    /// This is a pointer in host memory to a string that names the TOC entry
    /// requested.  This field is set to a pointer to the ID string of the TOC
    /// entry inside the image. If \a iv_partial is set this field is returned
    /// as 0.
    char* iv_id;

    /// The data type, one of the SBE_XIP_* constants
    uint8_t iv_type;

    /// The number of elements in a vector
    ///
    /// This field is set from the TOC entry when the TOC entry is
    /// decoded. This value is stored as 1 for scalar declarations, and may be
    /// set to 0 for vectors with large or undeclared sizes.  Otherwise it is
    /// used to bounds check indexed accesses.
    uint8_t iv_elements;

    /// Is this record only partially populated?
    ///
    /// This field is set to 0 normally, and only set to 1 if a lookup is made
    /// in an image that only has the fixed TOC and the requested Id hashes to
    /// the fixed TOC.
    uint8_t iv_partial;

} SbeXipItem;


/// Prototype entry in the .halt section
///
/// The .halt section is generated by the 'reqhalt' macro.  This structure
/// associates the address of each halt with the string form of the FAPI
/// return code associated with the halt.  The string form is used because the
/// FAPI error return code is not constant.  The .halt section is 4-byte
/// aligned, and each address/string entry is always padded to a multiple of 4
/// bytes. 
///
/// In the .halt section the \a iv_string may be any length, thus the size of
/// each actual record is variable (although guaranteed to always be a
/// multiple of 4 bytes). Although the C compiler might natuarlly align
/// instances of this structure on a 64-bit boundary, the APIs that allow
/// access to the .halt section assume that the underlying machine can do
/// non-aligned loads from a pointer to this structure.

typedef struct {

    /// The 64-bit relocatable address of the halt
    ///
    /// This is the address found in the PC (Status Register bits 16:63) when
    /// the PORE halts.  The full 64-bit form is used rather than the simple
    /// 32-bit offset to support merging SEEPROM and PIBMEM .halt sections in
    /// the SEEPROM IPL images.
    uint64_t iv_address;

    /// A C-prototype for a variable-length 0-terminated ASCII string
    ///
    /// This is a prototype only to simplify C programming.  The actual string
    /// may be any length.
    char iv_string[4];

} SbeXipHalt;


/// Validate an SBE-XIP image
///
/// \param[in] i_image A pointer to an SBE-XIP image in host memory. 
/// 
/// \param[in] i_size The putative size of the image
///
/// \param[in] i_maskIgnores Array of ignore bits representing which properties
/// should not be checked for in sbe_xip_validate2().
///
/// This API should be called first by all applications that manipulate
/// SBE-XIP images in host memory.  The magic number is validated, and 
/// the image is checked for consistency of the section table and table of
/// contents.  The \a iv_imageSize field of the header must also match the
/// provided \a i_size parameter.  Validation does not modify the image.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_validate(void* i_image, const uint32_t i_size);

int
sbe_xip_validate2(void* i_image, const uint32_t i_size, const uint32_t i_maskIgnores);


/// Normalize the SBE-XIP image
///
/// \param[in] io_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections. 
///
/// SBE-XIP images must be normalized before any other APIs are allowed to
/// operate on the image.  Since normalization modifies the image, an explicit
/// call to normalize the image is required.  Briefly, normalization modifies
/// the TOC entries created by the final link to simplify search, updates,
/// modification and relocation of the image.  Normalization is explained in
/// the written documentation of the SBE-XIP binary format. Normalization does
/// not modify the size of the image.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_normalize(void* io_image);


/// Return the size of an SBE-XIP image from the image header
///
/// \param[in] i_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections.
///
/// \param[out] o_size A pointer to a variable returned as the size of the
/// image in bytes, as recorded in the image header.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_image_size(void* i_image, uint32_t* o_size);


/// Locate a section table entry and translate into host format
///
/// \param[in] i_image A pointer to an SBE-XIP image in host memory.
///
/// \param[in] i_sectionId Identifies the section to be queried.  See \ref
/// sbe_xip_sections.
///
/// \param[out] o_hostSection Updated to contain the section table entry
/// translated to host byte order.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_get_section(const void* i_image,
                    const int i_sectionId,
                    SbeXipSection* o_hostSection);


/// Endian translation of an SbeXipHeader object
///
/// \param[out] o_hostHeader The destination object.
///
/// \param[in] i_imageHeader The source object.
///
/// Translation of a SbeXipHeader includes translation of all data members
/// including traslation of the embedded section table.  This translation
/// works even if \a o_src == \a o_dest, i.e., in the destructive case.
void
sbe_xip_translate_header(SbeXipHeader* o_hostHeader, 
                         const SbeXipHeader* i_imageHeader);


/// Get scalar data from an SBE-XIP image
///
/// \param[in] i_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections.  The image is
/// also required to have been normalized.
///
/// \param[in] i_id A pointer to a 0-terminated ASCII string naming the item
/// requested. 
///
/// \param[out] o_data A pointer to an 8-byte integer to receive the scalar
/// data. Assuming the item is located this variable is assigned by the call.
/// In the event of an error the final state of \a o_data is not specified.
///
/// This API searches the SBE-XIP Table of Contents (TOC) for the item named
/// \a i_id, assigning \a o_data from the image if the item is found and is a
/// scalar value.  Scalar values include 8- 32- and 64-bit integers and PORE
/// addresses.  Image data smaller than 64 bits are extracted as unsigned
/// types, and it is the caller's responsibility to cast or convert the
/// returned data as appropriate.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_get_scalar(void *i_image, const char* i_id, uint64_t* o_data);


/// Get an integral element from a vector held in an SBE-XIP image
///
/// \param[in] i_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections.  The image is
/// also required to have been normalized.
///
/// \param[in] i_id A pointer to a 0-terminated ASCII string naming the item
/// requested. 
///
/// \param[in] i_index  The index of the vector element to return.
///
/// \param[out] o_data A pointer to an 8-byte integer to receive the
/// data. Assuming the item is located this variable is assigned by the call.
/// In the event of an error the final state of \a o_data is not specified.
///
/// This API searches the SBE-XIP Table of Contents (TOC) for the \a i_index
/// element of the item named \a i_id, assigning \a o_data from the image if
/// the item is found, is a vector of an integral type, and the \a i_index is
/// in bounds.  Vector elements smaller than 64 bits are extracted as unsigned
/// types, and it is the caller's responsibility to cast or convert the
/// returned data as appropriate.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_get_element(void *i_image, 
                    const char* i_id, 
                    const uint32_t i_index,
                    uint64_t* o_data);


/// Get string data from an SBE-XIP image
///
/// \param[in] i_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections.  The image is
/// also required to have been normalized.
///
/// \param[in] i_id A pointer to a 0-terminated ASCII string naming the item
/// requested. 
///
/// \param[out] o_data A pointer to a character pointer.  Assuming the
/// item is located this variable is assigned by the call to point to the
/// string as it exists in the \a i_image.  In the event of an error the final
/// state of \a o_data is not specified.
///
/// This API searches the SBE-XIP Table of Contents (TOC) for the item named
/// \a i_id, assigning \a o_data if the item is found and is a string.  It is
/// the caller's responsibility to copy the string from the \a i_image memory
/// space if necessary.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_get_string(void *i_image, const char* i_id, char** o_data);


/// Directly read 64-bit data from the image based on a PORE address
///
/// \param[in] i_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections.
///
/// \param[in] i_poreAddress A relocatable PORE address contained in the
/// image, presumably of an 8-byte data area.  The \a i_poreAddress is
/// required to be 8-byte aligned, otherwise the SBE_XIP_ALIGNMENT_ERROR code
/// is returned.
///
/// \param[out] o_data The 64 bit data in host format that was found at \a
/// i_poreAddress.
///
/// This API is provided for applications that need to manipulate SBE-XIP
/// images in terms of their relocatable PORE addresses.  The API checks that
/// the \a i_poreAddress is properly aligned and contained in the image, then
/// reads the contents of \a i_poreAddress into \a o_data, performing
/// image-to-host endianness conversion if required.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_read_uint64(const void *i_image, 
                    const uint64_t i_poreAddress,
                    uint64_t* o_data);


/// Set scalar data in an SBE-XIP image
///
/// \param[in,out] io_image A pointer to an SBE-XIP image in host memory.
/// The image is assumed to be consistent with the information contained in
/// the header regarding the presence of and sizes of all sections.  The image
/// is also required to have been normalized.
///
/// \param[in] i_id A pointer to a 0-terminated ASCII string naming the item
/// to be modified. 
///
/// \param[in] i_data The new scalar data. 
///
/// This API searches the SBE-XIP Table of Contents (TOC) for the item named
/// by \a i_id, updating the image from \a i_data if the item is found, has
/// a scalar type and can be modified.  For this API the scalar types include
/// 8- 32- and 64-bit integers.  Although PORE addresses are considered a
/// scalar type for sbe_xip_get_scalar(), PORE addresses can not be modified
/// by this API.  The caller is responsible for ensuring that the \a i_data is
/// of the correct size for the underlying data element in the image.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_set_scalar(void* io_image, const char* i_id, const uint64_t i_data);


/// Set an integral element in a vector held in an SBE-XIP image
///
/// \param[in] i_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections.  The image is
/// also required to have been normalized.
///
/// \param[in] i_id A pointer to a 0-terminated ASCII string naming the item
/// to be updated.
///
/// \param[in] i_index  The index of the vector element to update.
///
/// \param[out] i_data The new vector element.
///
/// This API searches the SBE-XIP Table of Contents (TOC) for the \a i_index
/// element of the item named \a i_id, update the image from \a i_data if the
/// item is found, is a vector of an integral type, and the \a i_index is in
/// bounds.  The caller is responsible for ensuring that the \a i_data is of
/// the correct size for the underlying data element in the image.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_set_element(void *i_image, 
                    const char* i_id, 
                    const uint32_t i_index,
                    const uint64_t i_data);


/// Set string data in an SBE-XIP image
///
/// \param[in,out] io_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections.  The image is
/// also required to have been normalized.
///
/// \param[in] i_id A pointer to a 0-terminated ASCII string naming the item
/// to be modified.
///
/// \param[in] i_data A pointer to the new string data.
///
/// This API searches the SBE-XIP Table of Contents (TOC) for the item named
/// \a i_id, which must be a string variable.  If found, then the string data
/// in the image is overwritten with \a i_data.  Strings are held 0-terminated
/// in the image, and the SBE-XIP format does not maintain a record of the
/// amount of memory allocated for an individual string.  If a string is
/// overwritten by a shorter string then the 'excess' storage is effectively
/// lost.  If the length of \a i_data is longer that the current strlen() of
/// the string data then \a i_data is silently truncated to the first
/// strlen(old_string) characters.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_set_string(void *io_image, const char* i_id, const char* i_data);


/// Directly write 64-bit data into the image based on a PORE address
///
/// \param[in, out] io_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections.
///
/// \param[in] i_poreAddress A relocatable PORE address contained in the
/// image, presumably of an 8-byte data area.  The \a i_poreAddress is
/// required to be 8-byte aligned, otherwise the SBE_XIP_ALIGNMENT_ERROR code
/// is returned.
///
/// \param[in] i_data The 64 bit data in host format to be written to \a
/// i_poreAddress. 
///
/// This API is provided for applications that need to manipulate SBE-XIP
/// images in terms of their relocatable PORE addresses.  The API checks that
/// the \a i_poreAddress is properly aligned and contained in the image, then
/// updates the contents of \a i_poreAddress with \a i_data, performing
/// host-to-image endianness conversion if required.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_write_uint64(void *io_image, 
                     const uint64_t i_poreAddress,
                     const uint64_t i_data);


/// Map over an SBE-XIP image Table of Contents
///
/// \param[in,out] io_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections.  The image is
/// also required to have been normalized.
///
/// \param[in] i_fn A pointer to a function to call on each TOC entry.  The
/// function has the prototype:
///
/// \code
/// int (*i_fn)(void* io_image,
///             const SbeXipItem* i_item, 
///             void* io_arg)
/// \endcode
///
/// \param[in,out] io_arg The private argument of \a i_fn.
///
/// This API iterates over each entry of the TOC, calling \a i_fn with
/// pointers to the image, an SbeXipItem* pointer, and a private argument. The
/// iteration terminates either when all TOC entries have been mapped, or \a
/// i_fn returns a non-zero code.
///
/// \retval 0 Success; All TOC entries were mapped, including the case that
/// the .toc section is empty.
///
/// \retval non-0 May be either one of the SBE-XIP image error codes (see \ref
/// sbe_xip_image_errors), or a non-zero code from \a i_fn. Since the standard
/// SBE_XIP return codes are > 0, application-defined codes should be < 0.
int
sbe_xip_map_toc(void* io_image, 
                 int (*i_fn)(void* io_image, 
                             const SbeXipItem* i_item, 
                             void* io_arg),
                 void* io_arg);


/// Find an SBE-XIP TOC entry
///
/// \param[in] i_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections.  The image is
/// also required to have been normalized.
///
/// \param[in] i_id A 0-byte terminated ASCII string naming the item to be
/// searched for.
///
/// \param[out] o_item If the search is successful, then the object
/// pointed to by \a o_item is filled in with the decoded form of the
/// TOC entry for \a i_id.  If the API returns a non-0 error code then the
/// final state of the storage at \a o_item is undefined.  This parameter may
/// be suppied as 0, in which case sbe_xip_find() serves as a simple predicate
/// on whether an item is indexded in the TOC.
///
/// This API searches the TOC of a normalized SBE-XIP image for the item named
/// \a i_id, and if found, fills in the structure pointed to by \a
/// o_item with a decoded form of the TOC entry.  If the item is not found,
/// the following two return codes may be considered non-error codes:
///
/// - SBE_XIP_ITEM_NOT_FOUND : No TOC record for \a i_id was found.
///
/// - SBE_XIP_DATA_NOT_PRESENT : The item appears in the TOC, however the
/// section containing the data is no longer present in the image.
///
/// If the TOC section has been deleted from the image, then the search is
/// restricted to the abbreviated TOC that indexes data in the .fixed section.
/// In this case the \a o_item structure is marked with a 1 in the \a
/// iv_partial field since the abbreviated TOC can not populate the entire
/// SbeXipItem structure.
///
/// \note This API should typically only be used as a predicate, not as a way
/// to access the image via the returned SbeXipItem structure. To obtain data
/// from the image or update data in the image use the sbe_xip_get_*() and
/// sbe_xip_set_*() APIs respectively.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_find(void* i_image, 
             const char* i_id, 
             SbeXipItem* o_item);


/// Map over an SBE-XIP image .halt section
///
/// \param[in,out] io_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections.
///
/// \param[in] i_fn A pointer to a function to call on each entry in .halt.
/// The function has the prototype:
///
/// \code
/// int (*i_fn)(void* io_image,
///             const uint64_t i_poreAddress,
///             const char* i_rcString,
///             void* io_arg)
///
/// \endcode
///
/// \param[in,out] io_arg The private argument of \a i_fn.
///
/// This API iterates over each entry of the .halt section, calling \a i_fn
/// with each HALT address, the string form of the return code associated with
/// that HALT address, and a private argument. The iteration terminates either
/// when all .halt entries have been mapped, or \a i_fn returns a non-zero
/// code.  The \a i_poreAddddress passed to \a i_fn is the full 48-bit
/// relocatable PORE address.
///
/// \retval 0 Success, including the case that the image has no .halt section.
///
/// \retval non-0 May be either one of the SBE-XIP image error codes (see \ref
/// sbe_xip_image_errors), or any non-zero code from \a i_fn.  Since the
/// standard SBE_XIP return codes are \> 0, application-defined codes should
/// be \< 0.
int
sbe_xip_map_halt(void* io_image, 
                 int (*i_fn)(void* io_image, 
                             const uint64_t i_poreAddress,
                             const char* i_rcString,
                             void* io_arg),
                 void* io_arg);


/// Get the string from of a HALT code from an SBE-XIP image .halt section
///
/// \param[in,out] io_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections.
///
/// \param[in] i_poreAddress This is the 48-bit address found in the PC when
/// the PORE halts.  This address is actually 4 bytes beyond the actual HALT
/// instruction, however for simplicity this is the address used to index the
/// HALT. 
///
/// \param[out] o_rcString The caller provides the address of a string-pointer
/// variable which is updated with a pointer to the string form of the halt
/// code associated with \a i_poreAddress (assuming a successful completion).
///
/// \retval 0 Success
///
/// \revtal SBE_XIP_ITEM_NOT_FOUND The \a i_poreAddress is not associated
/// with a halt code in .halt.
///
/// \revtal Other See \ref sbe_xip_image_errors
int
sbe_xip_get_halt(void* io_image, 
                 const uint64_t i_poreAddress,
                 const char** o_rcString);


/// Delete a section from an SBE-XIP image in host memory
///
/// \param[in,out] io_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections. The image is
/// also required to have been normalized.
///
/// \param[in] i_sectionId Identifies the section to be deleted.  See \ref
/// sbe_xip_sections.
///
/// This API effectively deletes a section from an SBE-XIP image held in host
/// memory.  Unless the requested section \a i_section is already empty, only
/// the final (highest address offset) section of the image may be deleted.
/// Deleting the final section of the image means that the section size is set
/// to 0, and the size of the image recorded in the header is reduced by the
/// section size.  Any alignment padding of the now-last section is also
/// removed.
///
/// \note This API does not check for or warn if other sections in the image
/// reference the deleted section.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_delete_section(void* io_image, const int i_sectionId);


#ifndef PPC_HYP

/// Duplicate a section from an SBE-XIP image in host memory
///
/// \param[in,out] i_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections.
///
/// \param[in] i_sectionId Identifies the section to be duplicated.  See \ref
/// sbe_xip_sections.
///
/// \param[out] o_duplicate At exit, points to the newly allocated and
/// initialized duplicate of the given section. The caller is responsible for
/// free()-ing this memory when no longer required.
///
/// \param[out] o_size At exit, contains the size (in bytes) of the duplicated
/// section.  
///
/// This API creates a bytewise duplicate of a non-empty section into newly
/// malloc()-ed memory. At exit \a o_duplicate points to the duplicate, and \a
/// o_size is set the the size of the duplicated section. The caller is
/// responsible for free()-ing the memory when no longer required.  The
/// pointer at \a o_duplicate is set to NULL (0) and the \a o_size is set to 0
/// in the event of any failure.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_duplicate_section(const void* i_image, 
                          const int i_sectionId,
                          void** o_duplicate,
                          uint32_t* o_size);

#endif // PPC_HYP


/// Append binary data to an SBE-XIP image held in host memory
///
/// \param[in,out] io_image A pointer to an SBE-XIP image in host memory.  The
/// image is assumed to be consistent with the information contained in the
/// header regarding the presence of and sizes of all sections. The image is
/// also required to have been normalized.
///
/// \param[in] i_sectionId Identifies the section to contain the new data.
///
/// \param[in] i_data A pointer to the data to be appended to the image.  If
/// this pointer is NULL (0), then the effect is as if \a i_data were a
/// pointer to an \a i_size array of 0 bytes.
///
/// \param[in] i_size The size of the data to be appended in bytes.  If \a
/// i_data is 0, then this is the number of bytes to clear.
///
/// \param[in] i_allocation The size of the memory region containing the
/// image, measured from the first byte of the image.  The call will fail if
/// appending the new data plus any alignment padding would overflow the
/// allocated memory.
///
/// \param[out] o_sectionOffset If non-0 at entry, then the API updates the
/// location pointed to by \a o_sectionOffset with the offset of the first
/// byte of the appended data within the indicated section. This return value
/// is invalid in the event of a non-0 return code.
///
/// This API copies data from \a i_data to the end of the indicated \a
/// i_section.  The section \a i_section must either be empty, or must be the
/// final (highest address) section in the image.  If the section is initially
/// empty and \a i_size is non-0 then the section is created at the end of the
/// image.  The size of \a i_section and the size of the image are always
/// adjusted to reflect the newly added data.  This is a simple binary copy
/// without any interpretation (e.g., endian-translation) of the copied data.
/// The caller is responsible for insuring that the host memory area
/// containing the SBE-XIP image is large enough to hold the newly appended
/// data without causing addressing errors or buffer overrun errors.
///
/// The final parameter \a o_sectionOffset is optional, and may be passed as
/// NULL (0) if the application does not require the information.  This return
/// value is provided to simplify typical use cases of this API:
///
/// - A scan program is appended to the image, or a run-time data area is
/// allocated and cleared at the end of the image.
///
/// - Pointer variables in the image are updated with PORE addresses obtained
/// via sbe_xip_section2pore(), or
/// other procedure code initializes a newly allocated and cleared data area
/// via host addresses obtained from sbe_xip_section2host().
///
/// Regarding alignment, note that the SBE-XIP format requires that sections
/// maintain an initial alignment that varies by section, and the API will
/// enforce these alignment constraints for all sections created by the API.
/// All alignment is relative to the first byte of the image (\a io_image) -
/// \e not to the current in-memory address of the image. By specification
/// SBE-XIP images must be loaded at a 4K alignment in order for PORE hardware
/// relocation to work, however the APIs don't require this 4K alignment for
/// in-memory manipulation of images.  Images to be executed on PoreVe will
/// normally require at least 8-byte final aligment in order to guarantee that
/// the PoreVe can execute an 8-byte fetch or load/store of the final
/// doubleword.
///
/// \note If the TOC section is modified then the image is marked as having an
/// unsorted TOC.
///
/// \note If the call fails for any reason (other than a bug in the API
/// itself) then the \a io_image data is returned unmodified.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_append(void* io_image,
               const int i_sectionId,
               const void* i_data,
               const uint32_t i_size,
               const uint32_t i_allocation,
               uint32_t* o_sectionOffset);


/// Convert an SBE-XIP section offset to a relocatable PORE address
///
/// \param[in] i_image A pointer to an SBE-XIP image in host memory
///
/// \param[in] i_sectionId A valid SBE-XIP section identifier; The section
/// must be non-empty.
///
/// \param[in] i_offset An offset (in bytes) within the section.  At least one
/// byte at \a i_offset must be currently allocated in the section.
///
/// \param[in] o_poreAddress The equivalent relocatable PORE address is
/// returned via this pointer. Since valid PORE addresses are always either
/// 4-byte (code) or 8-byte (data) aligned, this API checks the aligment of
/// the translated address and returns SBE_XIP_ALIGNMENT_ERROR if the PORE
/// address is not at least 4-byte aligned.  Note that the translated address
/// is still returned even if incorrectly aligned.
///
/// This API is typically used to translate section offsets returned from
/// sbe_xip_append() into relocatable PORE addresses.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_section2pore(const void* i_image, 
                     const int i_sectionId,
                     const uint32_t i_offset,
                     uint64_t* o_poreAddress);


/// Convert an SBE-XIP relocatable PORE address to a host memory address
///
/// \param[in] i_image A pointer to an SBE-XIP image in host memory.
///
/// \param[in] i_poreAddress A relocatable PORE address putatively addressing
/// relocatable memory contained in the image.
///
/// \param[out] o_hostAddress The API updates the location pointed to by \a
/// o_hostAddress with the host address of the memory addressed by \a
/// i_poreAddress.  In the event of an error (non-0 return code) the final
/// content of \a o_hostAddress is undefined.
///
/// This API is typically used to translate relocatable PORE addresses stored
/// in the SBE-XIP image into the equivalent host address of the in-memory
/// image, allowing host-code to manipulate arbitrary data structures in the
/// image. If the \a i_poreAddress does not refer to memory within the image
/// (as determined by the link address and image size) then the
/// SBE_XIP_INVALID_ARGUMENT error code is returned.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_pore2host(const void* i_image, 
                  const uint64_t i_poreAddress,
                  void** o_hostAddress);


/// Convert an SBE-XIP relocatable PORE address to section Id and offset
///
/// \param[in] i_image A pointer to an SBE-XIP image in host memory.
///
/// \param[in] i_poreAddress A relocatable PORE address putatively addressing
/// relocatable memory contained in the image.
///
/// \param[out] o_section The API updates the location pointed to by \a
/// o_section with the section Id of the memory addressed by \a
/// i_poreAddress.  In the event of an error (non-0 return code) the final
/// content of \a o_section is undefined.
///
/// \param[out] o_offset The API updates the location pointed to by \a
/// o_offset with the byte offset of the memory addressed by \a i_poreAddress
/// within \a o_section.  In the event of an error (non-0 return code) the
/// final content of \a o_offset is undefined.
///
/// This API is typically used to translate relocatable PORE addresses stored
/// in the SBE-XIP image into the equivalent section + offset form, allowing
/// host-code to manipulate arbitrary data structures in the image. If the \a
/// i_poreAddress does not refer to memory within the image (as determined by
/// the link address and image size) then the SBE_XIP_INVALID_ARGUMENT error
/// code is returned.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_pore2section(const void* i_image, 
                     const uint64_t i_poreAddress,
                     int* o_section,
                     uint32_t* o_offset);


/// Convert an in-memory SBE-XIP host address to a relocatable PORE address
///
/// \param[in] i_image A pointer to an SBE-XIP image in host memory
///
/// \param[in] i_hostAddress A host address addressing data within the image.
///
/// \param[out] o_poreAddress The API updates the location pointed to by \a
/// o_poreAddress with the equivalent relocatable PORE address of the memory
/// addressed by i_hostAddress.  Since valid PORE addresses are always either
/// 4-byte (code) or 8-byte (data) aligned, this API checks the aligment of
/// the translated address and returns SBE_XIP_ALIGNMENT_ERROR if the PORE
/// address is not at least 4-byte aligned.  Note that the translated address
/// is still returned evn if incorrectly aligned.
///
/// This API is provided as a convenient way to convert host memory addresses
/// for an in-memory SBE-XIP image into PORE addresses correctly relocated for
/// the image, for example to update pointer variables in the image.  If the
/// \a i_hostAddress does not refer to memory within the image (as determined
/// by the image address and image size) then the SBE_XIP_INVALID_ARGUMENT
/// error code is returned.
///
/// \retval 0 Success
///
/// \retval non-0 See \ref sbe_xip_image_errors
int
sbe_xip_host2pore(const void* i_image, 
                  void* i_hostAddress,
                  uint64_t* o_poreAddress);


/// \defgroup sbe_xip_image_errors Error codes from SBE-XIP image APIs
///
/// @{

/// A putative SBE-XIP image does not have the correct magic number, or
/// contains some other major inconsistency.
#define SBE_XIP_IMAGE_ERROR 1

/// The TOC may be missing, partially present or may have an alignment problem.
#define SBE_XIP_TOC_ERROR 2

/// A named item was not found in the SBE-XIP TOC, or a putative HALT address
/// is not associated with a halt code in .halt.
#define SBE_XIP_ITEM_NOT_FOUND 3

/// A named item appears in the SBE-XIP TOC, but the data is not present in
/// the image.  This error can occur if sections have been deleted from the
/// image.
#define SBE_XIP_DATA_NOT_PRESENT 4

/// A named item appears in the SBE-XIP TOC, but the data can not be
/// modified. This error will occur if an attempt is made to modify an
/// address-only entry.
#define SBE_XIP_CANT_MODIFY 5

/// A direct or implied argument is invalid, e.g. an illegal data type or
/// section identifier, or an address not contained within the image.
#define SBE_XIP_INVALID_ARGUMENT 6

/// A data type mismatch or an illegal type was specified or implied for an
/// operation. 
#define SBE_XIP_TYPE_ERROR 7

/// A bug in an SBE-XIP image API
#define SBE_XIP_BUG 8

/// The image must first be normalized with sbe_xip_normalize().
#define SBE_XIP_NOT_NORMALIZED 9

/// Attempt to delete a non-empty section that is not the final section of the
/// image, or an attempt to append data to a non-empty section that is not the
/// final section of the image, or an attempt to operate on an empty section
/// for those APIs that prohibit this.
#define SBE_XIP_SECTION_ERROR 10

/// An address translation API returned a PORE address that was not at least
/// 4-byte aligned, or alignment violations were observed by
/// sbe_xip_validate() or sbe_xip_append().
#define SBE_XIP_ALIGNMENT_ERROR 11

/// An API that performs dynamic memory allocation was unable to allocate
/// memory. 
#define SBE_XIP_NO_MEMORY 12

/// Attempt to get or set a vector element with an index that is outside of
/// the declared bounds of the vector.
#define SBE_XIP_BOUNDS_ERROR 13

/// Attempt to grow the image past its defined memory allocation
#define SBE_XIP_WOULD_OVERFLOW 14

/// Error associated with the disassembler occurred.
#define SBE_XIP_DISASSEMBLER_ERROR 15

/// hash collision creating the .fixed_toc section
#define SBE_XIP_HASH_COLLISION 16

/// Applications can expand this macro to declare an array of string forms of
/// the error codes if desired.
#define SBE_XIP_ERROR_STRINGS(var)              \
    const char* var[] = {                       \
        "Success",                              \
        "SBE_XIP_IMAGE_ERROR",                  \
        "SBE_XIP_TOC_ERROR",                    \
        "SBE_XIP_ITEM_NOT_FOUND",               \
        "SBE_XIP_DATA_NOT_PRESENT",             \
        "SBE_XIP_CANT_MODIFY",                  \
        "SBE_XIP_INVALID_ARGUMENT",             \
        "SBE_XIP_TYPE_ERROR",                   \
        "SBE_XIP_BUG",                          \
        "SBE_XIP_NOT_NORMALIZED",               \
        "SBE_XIP_SECTION_ERROR",                \
        "SBE_XIP_ALIGNMENT_ERROR",              \
        "SBE_XIP_NO_MEMORY",                    \
        "SBE_XIP_BOUNDS_ERROR",                 \
        "SBE_XIP_WOULD_OVERFLOW",               \
        "SBE_XIP_DISASSEMBLER_ERROR",           \
        "SBE_XIP_HASH_COLLISION",               \
    }

/// Applications can use this macro to safely index the array of error
/// strings. 
#define SBE_XIP_ERROR_STRING(var, n)                                   \
    ((((n) < 0) || ((n) > (int)(sizeof(var) / sizeof(char*)))) ?        \
     "Bug : Invalid SBE-XIP error code" : var[n])

/// @}

/// Disassembler error codes.
#define DIS_IMAGE_ERROR                   1
#define DIS_MEMORY_ERROR                  2
#define DIS_DISASM_ERROR                  3
#define DIS_RING_NAME_ADDR_MATCH_SUCCESS  4
#define DIS_RING_NAME_ADDR_MATCH_FAILURE  5
#define DIS_TOO_MANY_DISASM_WARNINGS      6
#define DIS_DISASM_TROUBLES               7

#define DIS_ERROR_STRINGS(var)              \
    const char* var[] = {                   \
        "Success",                          \
        "DIS_IMAGE_ERROR",                  \
        "DIS_MEMORY_ERROR",                 \
        "DIS_DISASM_ERROR",                 \
        "DIS_RING_NAME_ADDR_MATCH_SUCCESS", \
        "DIS_RING_NAME_ADDR_MATCH_FAILURE", \
        "DIS_TOO_MANY_DISASM_WARNINGS",     \
        "DIS_DISASM_TROUBLES",              \
    }

#define DIS_ERROR_STRING(var, n)                                   \
    ((((n) < 0) || ((n) > (int)(sizeof(var) / sizeof(char*)))) ?        \
     "Bug : Invalid DIS error code" : var[n])

#if 0
{ /* So __cplusplus doesn't mess w/auto-indent */
#endif
#ifdef __cplusplus
}
#endif

#endif  // __ASSEMBLER__


////////////////////////////////////////////////////////////////////////////
// Assembler Definitions
////////////////////////////////////////////////////////////////////////////

#ifdef __ASSEMBLER__

/// Create an XIP TOC entry
///
/// \param[in] index The string form of the \a index symbol is created and
/// linked from the TOC entry to allow external search procedures to locate
/// the \a address.
///
/// \param[in] type One of the SBE_XIP_* type constants; See \ref
/// sbe_xip_toc_types.
///
/// \param[in] address The address of the idexed code or data; This wlll
/// typically be a symbol.
///
/// \param[in] elements <Optional> For vector types, number of elements in the
/// vector, which is limited to an 8-bit unsigned integer.  This parameter
/// defaults to 1 which indicates a scalar type. Declaring a vector with 0
/// elements disables bounds checking on vector accesses, and can be used if
/// very large or indeterminate sized vectors are required. The TOC format
/// does not support vectors of strings or addresses.
///
/// The \c .xip_toc macro creates a XIP Table of Contents (TOC) structure in
/// the \c .toc section, as specified by the parameters.  This macro is
/// typically not used directly in assembly code.  Instead programmers should
/// use .xip_quad, .xip_quada, .xip_quadia, .xip_address, .xip_string or
/// .xip_cvs_revision.

        .macro  .xip_toc, index:req, type:req, address:req, elements=1

	.if	(((\type) < 1) || ((\type) > SBE_XIP_MAX_TYPE_INDEX))
	.error	".xip_toc : Illegal type index"
	.endif

        // First push into the .strings section to lay down the
        // string form of the index name under a local label.

        .pushsection .strings
7667862:        
        .asciz  "\index"
        .popsection

        // Now the 12-byte TOC entry is created.  Push into the .toc section
	// and lay down the first 4 bytes which are always a pointer to the
	// string just declared.  The next 4 bytes are the address of the data
	// (or the address itself in the case of address types). The final 4
	// bytes are the type, section (always 0 prior to normalization),
	// number of elements, and a padding byte.

	.pushsection .toc
	
	.long	7667862b, (\address)
	.byte	(\type), 0, (\elements), 0

	.popsection

	.endm


/// Allocate and initialize 64-bit global scalar or vector data and create the
/// TOC entry.
///
/// \param[in] symbol The name of the scalar or vector; this name is also used
/// as the TOC index of the data.
///
/// \param[in] init The initial value of (each element of) the data.
/// This is a 64-bit integer; To allocate address pointers use .xip_quada.
///
/// \param[in] elements The number of 64-bit elements in the data structure,
/// defaulting to 1, with a maximum value of 255.
///
/// \param[in] section The section where the data will be allocated,
/// default depends on the memory space

	.macro	.xip_quad, symbol:req, init:req, elements=1, section

        ..xip_quad_helper .quad, \symbol, (\init), (\elements), \section

	.endm


/// Allocate and initialize 64-bit global scalar or vector data containing a
/// relocatable address in and create the TOC entry.
///
/// \param[in] symbol The name of the scalar or vector; this name is also used
/// as the TOC index of the data.
///
/// \param[in] init The initial value of (each element of) the data.  This
/// will typically be a symbolic address. If the intention is to define an
/// address that will always be filled in later by image manipulation tools,
/// then use the .xip_quad macro with a 0 initial value.
///
/// \param[in] elements The number of 64-bit elements in the data structure,
/// defaulting to 1, with a maximum value of 255.
///
/// \param[in] section The section where the data will be allocated,
/// default depends on the memory space

	.macro	.xip_quada, symbol:req, offset:req, elements=1, section

	..xip_quad_helper .quada, \symbol, (\offset), (\elements), \section

	.endm


/// Helper for .xip_quad and .xip_quada

        .macro	..xip_quad_helper, directive, symbol, init, elements, section
	
	.if	(((\elements) < 1) || ((\elements) > 255))
	.error	"The number of vector elements must be in the range 1..255"
	.endif

	..xip_pushsection \section
	.balign 8

	.global	\symbol
\symbol\():
	.rept	(\elements)
        \directive (\init)
	.endr

	.popsection

	.xip_toc \symbol, SBE_XIP_UINT64, \symbol, (\elements)

	.endm


/// Allocate and initialize 64-bit global scalar or vector data containing
/// full 64-bit addresses and create a TOC entry
///
/// \param[in] symbol The name of the scalar or vector; this name is also used
/// as the TOC index of the data.
///
/// \param[in] space A valid PORE memory space descriptor
///
/// \param[in] offset A 32-bit relocatable offset
///
/// \param[in] elements The number of 64-bit elements in the data structure,
/// defaulting to 1, with a maximum value of 255.
///
/// \param[in] section The section where the data will be allocated,
/// default depends on the memory space

         .macro	.xip_quadia, symbol:req, space:req, offset:req, \
		 elements=1, section

	.if	(((\elements) < 1) || ((\elements) > 255))
	.error	"The number of vector elements must be in the range 1..255"
	.endif

	..xip_pushsection \section
	.balign	8

	.global	\symbol
\symbol\():	
	.rept	(\elements)
	.quadia	(\space), (\offset)
	.endr
	
	.popsection

	.xip_toc \symbol, SBE_XIP_UINT64, \symbol, (\elements)

	.endm

/// Default push into .ipl_data unless in an OCI space, then .data

	.macro	..xip_pushsection, section

	.ifnb	\section
	.pushsection \section
	.else
	.if	(_PGAS_DEFAULT_SPACE == PORE_SPACE_OCI)
	.pushsection .data
	.else
	.pushsection .ipl_data
	.endif
	.endif
             
	.balign	8            

	.endm

/// Allocate and initialize a string in .strings
///
/// \param[in] index The string will be stored in the TOC using this index
/// symbol.
///
/// \param[in] string The string to be allocated in .strings. String space is
/// fixed once allocated.  Strings designed to be overwritten by external tools
/// should be allocated to be as long as eventually needed (e.g., by a string
/// of blanks.)

	.macro	.xip_string, index:req, string:req

	.pushsection .strings
7874647:                       
	.asciz	"\string"
	.popsection

	.xip_toc \index, SBE_XIP_STRING, 7874647b

	.endm


/// Allocate and initialize a CVS Revison string in .strings
///
/// \param[in] index The string will be stored in the TOC using this index
/// symbol.
///
/// \param[in] string A CVS revision string to be allocated in .strings.  CVS
/// revision strings are formatted by stripping out and only storing the
/// actual revision number :
///
/// \code
///     "$Revision <n>.<m> $" -> "<n>.<m>"
/// \endcode
	

	.macro	.xip_cvs_revision, index:req, string:req

	.pushsection .strings
7874647:        
	..cvs_revision_string "\string"
	.popsection

	.xip_toc \index, SBE_XIP_STRING, 7874647b

	.endm


/// Shorthand to create a TOC entry for an address
/// 
/// \param[in] index The symbol will be indexed as this name
///
/// \param[in] symbol <Optional> The symbol to index; by default the same as
/// the index.

	.macro	.xip_address, index:req, symbol
             
	.ifb	\symbol
	.xip_toc \index, SBE_XIP_ADDRESS, \index
	.else
	.xip_toc \index, SBE_XIP_ADDRESS, \symbol
	.endif

	.endm


/// Edit and allocate a CVS revision string
///
/// CVS revision strings are formatted by stripping out and only storing the
/// actual revision number :
/// \code
///     "$Revision <n>.<m> $" -> "<n>.<m>"
/// \endcode
	
	.macro	..cvs_revision_string, rev:req
	.irpc	c, \rev
	.ifnc	"\c", "$"
	.ifnc	"\c", "R"
	.ifnc	"\c", "e"
	.ifnc	"\c", "v"
	.ifnc	"\c", "i"
	.ifnc	"\c", "s"
	.ifnc	"\c", "i"
	.ifnc	"\c", "o"
	.ifnc	"\c", "n"
	.ifnc	"\c", ":"
	.ifnc	"\c", " "
	.ascii	"\c"
	.endif
	.endif
	.endif
	.endif
	.endif
	.endif
	.endif
	.endif
	.endif
	.endif
	.endif
	.endr
	.byte	0
	.endm

#endif // __ASSEMBLER__

#endif  // __SBE_XIP_TOC_H
