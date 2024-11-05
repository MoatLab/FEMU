/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/usr/hwpf/hwp/build_winkle_images/p8_slw_build/p8_delta_scan_rw.h $ */
/*                                                                        */
/* OpenPOWER HostBoot Project                                             */
/*                                                                        */
/* COPYRIGHT International Business Machines Corp. 2012,2014              */
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
// $Id: p8_delta_scan_rw.h,v 1.49 2014/05/13 13:31:51 jmcgill Exp $
#define OVERRIDE_OFFSET 8            // Byte offset of forward pointer's addr relative 
                                     //   to base forward pointer's addr.
#define SIZE_IMAGE_BUF_MAX      5000000 // Max ~5MB image buffer size.
#define SIZE_IMAGE_CENTAUR_MAX  5000000 // Max ~5MB image buffer size.
#define SIZE_REPR_RING_MAX        50000 // Max ~50kB repr ring buffer size.
#define SCOM_REG_MASK   0x00ffffff   // Scom register mask (within a chiplet)
#define CID_MASK        0xff000000   // Chiplet ID mask
#define CID_EX_LOW      0x10         // Lowest EX chiplet addr
#define CID_EX_HIGH     0x1f         // Highest EX chiplet addr

/*****  Xip customize support ****/
#define COMBINED_GOOD_VECTORS_TOC_NAME    "combined_good_vectors"
#define L2_SINGLE_MEMBER_ENABLE_TOC_NAME  "l2_single_member_enable_mask"
#define PROC_PIB_REPR_VECTOR_TOC_NAME     "proc_sbe_pibmem_repair_vector"
#define NEST_SKEWADJUST_VECTOR_TOC_NAME   "proc_sbe_nest_skewadjust_vector"
#define SECURITY_SETUP_VECTOR_TOC_NAME    "proc_sbe_security_setup_vector"
#define VALID_BOOT_CORES_MASK_TOC_NAME    "valid_boot_cores_mask"
#define MAX_PLL_RING_SIZE                  128 // Bytes
#define PERV_BNDY_PLL_RING_TOC_NAME       "perv_bndy_pll_ring"
#define PERV_BNDY_PLL_RING_ALT_TOC_NAME   "perv_bndy_pll_ring_alt"
#define MAX_FUNC_L3_RING_LIST_ENTRIES     64  
#define MAX_FUNC_L3_RING_SIZE             7000 // Bytes
#define FUNC_L3_RING_TOC_NAME             "ex_func_l3_ring"
#define MAX_CEN_PLL_RING_SIZE               80 // Bytes
#define TP_PLL_BNDY_RING_ALT_TOC_NAME     "tp_pll_bndy_ring_alt"
#define STANDALONE_MBOX0_VALUE_TOC_NAME   "standalone_mbox0_value"
#define STANDALONE_MBOX1_VALUE_TOC_NAME   "standalone_mbox1_value"
#define STANDALONE_MBOX2_VALUE_TOC_NAME   "standalone_mbox2_value"
#define STANDALONE_MBOX3_VALUE_TOC_NAME   "standalone_mbox3_value"
#define UNTRUSTED_BAR_TOC_NAME            "fabric_config"
#define UNTRUSTED_PBA_BAR_TOC_NAME        "fabric_config_pba"
#define REFCLOCK_TERM_TOC_NAME            "refclock_term"

/*****  Scan setting  *****/
#define OPCG_SCAN_RATIO                     4
#define P8_OPCG_SCAN_RATIO_BITS             (uint64_t(OPCG_SCAN_RATIO-1)<<(63-8))
#define P8_OPCG_GO_BITS                     (uint64_t(0x40000000)<<32)
#define P8_SCAN_POLL_MASK_BIT15             (uint64_t(0x00010000)<<32)

/*****  Scan Control Regs  *****/
#define P8_PORE_OPCG_CTRL_REG0_0x00030002   0x00030002 // OPCG control reg 0
#define P8_PORE_OPCG_CTRL_REG1_0x00030003   0x00030003 // OPCG control reg 1
#define P8_PORE_OPCG_CTRL_REG2_0x00030004   0x00030004 // OPCG control reg 2
#define P8_PORE_OPCG_START_REG3_0x00030005  0x00030005 // OPCG start reg 3
#define P8_PORE_CLOCK_REGION_0x00030006     0x00030006 // Clock region control
#define P8_PORE_CLOCK_CONTROLLER_REG        0x00030007 // Addr of clock ctrl scom reg
#define P8_PORE_CLOCK_STATUS_0x00030008     0x00030008 // Status of clocks running
#define P8_PORE_SHIFT_REG                   0x00038000 // Addr of scom reg that does scan ring shifting
#define P8_SCAN_CHECK_WORD                  0xA5A55A5A // Header check word

/*****  Ring state *****/
#define MAX_RING_SIZE 500000   // 500kbits is the max ring size in bits

/***** Return codes *****/
#define DSLWB_RING_SEARCH_MATCH               0
#define DSLWB_RING_SEARCH_EXHAUST_MATCH      30
#define DSLWB_RING_SEARCH_NO_MATCH           31
#define DSLWB_RING_SEARCH_MESS               32
#define DSLWB_SLWB_SUCCESS                    0
#define DSLWB_SLWB_NO_RING_MATCH             40
#define DSLWB_SLWB_DX_ERROR                  41
#define DSLWB_SLWB_WF_ERROR                  42
#define DSLWB_SLWB_WF_IMAGE_ERROR            43
#define DSLWB_SLWB_IMAGE_ERROR               44
#define DSLWB_SLWB_UNKNOWN_ERROR             45
#define IMGBUILD_SUCCESS                      0  // Successful img build.
#define IMGBUILD_ERR_GENERIC                  1  // Non-specific error code.
#define IMGBUILD_ERR_FILE_ACCESS              2  // Unable to access/open file.
#define IMGBUILD_ERR_CHIPLET_ID_MESS          4  // Chiplet ID mess(mostly for VPD rings).
#define IMGBUILD_NO_RINGS_FOUND               5  // Successful img build but no rings found.
#define IMGBUILD_BAD_ARGS                     6  // Bad function arguments.
#define IMGBUILD_ERR_MEMORY                   7  // Memory allocation error.
#define IMGBUILD_ERR_RING_TOO_LARGE           8  // Ring size exceeds HB/PHYP's buffer.
#define IMGBUILD_ERR_CHECK_CODE               9  // Coding or image data problem.
#define IMGBUILD_INVALID_IMAGE               10  // Invalid image.
#define IMGBUILD_IMAGE_SIZE_MISMATCH         11  // Mismatch between image sizes.
#define IMGBUILD_IMAGE_SIZE_MESS             12  // Messed up image or section sizes.
#define IMGBUILD_RINGTYPE_NOT_ALLOWED        13  // Ringtype not allowed.
#define IMGBUILD_BUFFER_TOO_SMALL            14  // Buffer too small.
#define IMGBUILD_ERR_PORE_INLINE             20  // Pore inline error.
#define IMGBUILD_ERR_PORE_INLINE_ASM         21  // Err assoc w/inline assembler.
#define IMGBUILD_RING_SEARCH_MATCH            0
#define IMGBUILD_RING_SEARCH_EXHAUST_MATCH   30
#define IMGBUILD_RING_SEARCH_NO_MATCH        31
#define IMGBUILD_RING_SEARCH_MESS            32
#define IMGBUILD_ERR_RING_SEARCH             33  // Err assoc w/ring retrieval.
#define IMGBUILD_ERR_DATACARE_RING_MESS      34  // Err assoc w/datacare & vpd ring sizes.
#define IMGBUILD_ERR_WF_CREATE               45  // Err assoc w/create_wiggle_flip_prg.
#define IMGBUILD_ERR_RING_WRITE_TO_IMAGE     46  // Err assoc w/wr_ring_block_to_img.
#define IMGBUILD_ERR_SECTION_SIZING          48  // Err assoc w/section sizing.
#define IMGBUILD_ERR_GET_SECTION             49  // Err assoc w/getting section ID.
#define IMGBUILD_ERR_SECTION_DELETE          50  // Err assoc w/deleting ELF section.
#define IMGBUILD_ERR_APPEND                  51  // Err assoc w/appending to ELF section.
#define IMGBUILD_ERR_INCOMPLETE_IMG_BUILD    52  // The image was built, but with errors.
#define IMGBUILD_ERR_FWD_BACK_PTR_MESS       53  // Forward or backward pointer mess.
#define IMGBUILD_ERR_KEYWORD_NOT_FOUND       54  // Image keyword not found.
#define IMGBUILD_ERR_MISALIGNED_RING_LAYOUT  55  // Ring layout is misaligned.
#define IMGBUILD_ERR_IMAGE_TOO_LARGE         56  // Image too large. Exceeded max size.
#define IMGBUILD_ERR_XIP_MISC                57  // Miscellaneous XIP image error.
#define IMGBUILD_ERR_XIP_UNKNOWN             58  // Unknown XIP image error.
#define IMGBUILD_ERR_RS4_DECOMPRESS          59  // Error during RS4 decompression.
#define IMGBUILD_ERR_RS4_COMPRESS            60  // Error during RS4 compression.
#define IMGBUILD_ERR_RAM_HDRS_NOT_SYNCED     61  // Ram headers not synchronized.
#define IMGBUILD_ERR_RAM_TABLE_FULL          63  // Ram table is full.       
#define IMGBUILD_ERR_RAM_CODE                64  // Code error in Ram API code.
#define IMGBUILD_ERR_RAM_INVALID_PARM        65  // Invalid Ramming parameter.
#define IMGBUILD_WARN_RAM_TABLE_CONTAMINATION 66 // Ram table contamination
#define IMGBUILD_ERR_RAM_TABLE_FAIL          67  // Unsuccessful RAM table build.
#define IMGBUILD_ERR_RAM_TABLE_END_NOT_FOUND 68  // Table entry end bit not found.
#define IMGBUILD_ERR_SCOM_INVALID_PARM       70  // Invalid Scomming parameter.
#define IMGBUILD_ERR_SCOM_HDRS_NOT_SYNCD     72  // Scom headers out of sync.
#define IMGBUILD_ERR_SCOM_ENTRY_NOT_FOUND    74  // Scom entry not found (OR/AND oper.)
#define IMGBUILD_ERR_SCOM_REPEAT_ENTRIES     76  // Repeat entries not allow.
#define IMGBUILD_ERR_SCOM_INVALID_SUBSECTION 77  // Invalid subsection value.
#define IMGBUILD_ERR_SCOM_TABLE_FAIL         79  // Unsuccessful SCOM table build.

#if defined SLW_COMMAND_LINE_RAM || defined XIPC_COMMAND_LINE
#define SLW_COMMAND_LINE
#endif

#if defined __FAPI && !(defined __P8_PORE_TABLE_GEN_API_C)
#define MY_INF(_fmt_, _args_...) FAPI_INF(_fmt_, ##_args_)
#ifndef SLW_COMMAND_LINE
#define MY_ERR(_fmt_, _args_...) FAPI_ERR(_fmt_, ##_args_)
#else
#define MY_ERR(_fmt_, _args_...) FAPI_INF(_fmt_, ##_args_)
#endif // End of SLW_COMMAND_LINE
#define MY_DBG(_fmt_, _args_...) FAPI_DBG(_fmt_, ##_args_)
#else  // End of __FAPI
#ifdef SLW_COMMAND_LINE
#define MY_INF(_fmt_, _args_...) printf(_fmt_, ##_args_)
#define MY_ERR(_fmt_, _args_...) printf(_fmt_, ##_args_)
#define MY_DBG(_fmt_, _args_...) printf(_fmt_, ##_args_)
#else  // End of SLW_COMMAND_LINE
#ifdef __SKIBOOT__
#define pr_fmt(fmt) "LIBPORE: " fmt
#include <skiboot.h>
//#define MY_INF(_fmt_, _args_...) prlog(PR_TRACE, _fmt_, ##_args_)
#define MY_INF(_fmt_, _args_...) do { } while(0)
#define MY_ERR(_fmt_, _args_...) prerror(_fmt_, ##_args_)
//#define MY_DBG(_fmt_, _args_...) prlog(PR_INSANE, _fmt_, ##_args_)
#define MY_DBG(_fmt_, _args_...) do { } while(0)
#else
#define MY_INF(_fmt_, _args_...) do { } while(0)
#define MY_ERR(_fmt_, _args_...) do { } while(0)
#define MY_DBG(_fmt_, _args_...) do { } while(0)
#endif
#endif  // End of not(__FAPI) & not(SLW_COMMAND_LINE)
#endif

#ifdef SLW_COMMAND_LINE
// Debug and development stuff
//#define IGNORE_FOR_NOW  // Causes code sections to be ignored.
#define DEBUG_SUPPORT   // Activates sbe-xip debug support.
#endif

/* XXX TEMPORARY */
#ifdef __SKIBOOT__
#define DEBUG_SUPPORT   // Activates sbe-xip debug support.
#endif

//#include <stdio.h>
//#include <stdint.h>
//#include <stdlib.h>
#include <p8_pore_api_custom.h>
#include <string.h>

#if defined SLW_COMMAND_LINE
#include <stdint.h> // May be in conflict with p8_pore_api_custom.h
#include <stdlib.h> // May be in conflict with p8_pore_api_custom.h
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#endif //End of SLW_COMMAND_LINE

// Not needed by:
// - Done: p8_pore_table_gen_api, p8_slw_build, p8_xip_customize, sbe_xip_tool,
//   p8_delta_scan, p8_ipl_build, p8_centaur_build.
// - So, what was this used for?
//#include <pore_bitmanip.H>

#include <p8_image_help_base.H>

#if !(defined __P8_PORE_TABLE_GEN_API_C) && !(defined __CEN_XIP_CUSTOMIZE_C) && !(defined SLW_COMMAND_LINE_RAM)
// We don't need this include for gen_cpureg/scom or slw ramming.
#include <p8_scan_compression.H>
#endif

#undef __PORE_INLINE_ASSEMBLER_C__
#include <pore_inline.h>

#if( defined(__cplusplus) && !defined(PLIC_MODULE) )
extern "C" {
#endif


#if !(defined __P8_PORE_TABLE_GEN_API_C) && !(defined SLW_COMMAND_LINE_RAM)

// Info:
// DeltaRingLayout describes the sequential order of the content in the compressed delta
//   ring blocks in the .initf section in the SBE-XIP images.
// When creating the .initf delta ring blocks, the following rules must be followed:
// - Everything must be stored in BE format.
// - {entryOffset; sizeOfThis; sizeOfMeta; metaData} must be word-aligned to ensure 
//   that the {rs4Launch} starts on a word boundary.
// - {rs4Launch} must start on a word boundary (see earlier rule how to do that).
// - {entryOffset; sizeOfThis; sizeOfMeta; metaData; rs4Launch} must be double-word-
//   aligned to ensure that {rs4Delta} starts on a double-word boundary.
// - {rs4Delta} must start on a double-word bournday (see earlier rule how to do that).
//
typedef struct {
  uint64_t entryOffset;
  uint64_t backItemPtr;
  uint32_t sizeOfThis;
  uint32_t sizeOfMeta; // Exact size of meta data. Arbitrary size. Not null terminated.
  uint32_t ddLevel;
  uint8_t  sysPhase;
  uint8_t  override;
  uint8_t  reserved1;
  uint8_t  reserved2;
  char     *metaData;  // Arbitrary size. Extra bytes to next alignment are random or 0s.
  uint32_t *rs4Launch; // Code. Must be 4-byte aligned. Actually should be 8-B align!
  uint32_t *rs4Delta;  // Data. Must be 8-byte aligned.
  uint32_t *wfInline;  // Code. Must be 4-byte aligned. Actually should be 8-B align!
} DeltaRingLayout;

typedef struct {
  uint32_t sizeOfData;
  char     data[];
} MetaData;

int calc_ring_delta_state(  
              const uint32_t  *i_init,
							const uint32_t  *i_alter,
							uint32_t        *o_delta,
							const uint32_t  i_ringLen);

int  create_wiggle_flip_prg(  
              uint32_t   *i_deltaRing,
              uint32_t   i_ringBitLen,
              uint32_t   i_scanSelectData,
              uint32_t   i_chipletID,
              uint32_t   **o_wfInline,
              uint32_t   *o_wfInlineLenInWords,
              uint8_t    i_flushOptimization,
							uint32_t   i_scanMaxRotate,
              uint32_t   i_waitsScanDelay,
              uint32_t   i_ddLevel);

uint64_t calc_ring_layout_entry_offset(
							uint8_t  i_typeRingLayout,
							uint32_t i_sizeMetaData);

int write_ring_block_to_image(  
							void             *io_image,
							const char       *i_ringName,    // NULL if no name.
              DeltaRingLayout  *i_ringBlock,
							const uint8_t    i_idxVector,   // [0-15] - Ignored if ringName==NULL
							const uint8_t    i_override,    // [0,1]  - Ignored if ringName==NULL
							const uint8_t    i_overridable, // [0,1]  - Ignored if ringName==NULL
              const uint32_t   i_sizeImageMax,
              const uint8_t    i_xipSectionId,
              void             *i_bufTmp,
              const uint32_t   i_sizeBufTmp);

#if !(defined __CEN_XIP_CUSTOMIZE_C)

int p8_centaur_build( 
							void      *i_imageIn,
              uint32_t  i_ddLevel,
              void      *i_imageOut,
              uint32_t  i_sizeImageOutMax);

int p8_ipl_build(     
							void      *i_imageIn,
              uint32_t  i_ddLevel,
              void      *i_imageOut,
              uint32_t  i_sizeImageOutMax);

int get_ring_layout_from_image2(  
							const void  *i_imageIn,
              uint32_t    i_ddLevel,
              uint8_t      i_sysPhase,
              DeltaRingLayout  **o_rs4RingLayout,
              void        **nextRing,
              uint8_t     i_xipSectionId);

int gen_ring_delta_state(  
              uint32_t   bitLen, 
              uint32_t   *i_init, 
              uint32_t   *i_alter,
              uint32_t   *o_delta,
              uint32_t   verbose);

int write_rs4_ring_to_ref_image(  
              char       *i_fnImage,
              CompressedScanData *i_RS4,
              uint32_t   i_ddLevel,
              uint8_t    i_sysPhase,
              uint8_t    i_override,
							uint8_t    i_ringType,
              char       *i_varName,
              char       *i_fnMetaData,
							void       *i_bufTmp,
							uint32_t   i_sizeBufTmp,
              uint32_t   verbose);

int write_vpd_ring_to_ipl_image(
              void       *io_image,
							uint32_t   &io_sizeImageOut,
							CompressedScanData *i_bufRs4Ring,
							uint32_t   i_ddLevel,
							uint8_t    i_sysPhase,
              char       *i_ringName,
							void       *i_bufTmp,
							uint32_t   i_sizeBufTmp,
              uint8_t    i_xipSection);

int write_vpd_ring_to_slw_image(
              void       *io_image,
							uint32_t   &io_sizeImageOut,
							CompressedScanData *i_bufRs4Ring,
							uint32_t   i_ddLevel,
							uint8_t    i_sysPhase,
              char       *i_ringName,
							void       *i_bufTmp,
							uint32_t   i_sizeBufTmp,
              uint8_t    i_bWcSpace);

int check_and_perform_ring_datacare( 
						  void      *i_imageRef,
							void      *io_buf1,
							uint8_t   i_ddLevel,
						  uint8_t   i_sysPhase,
							char      *i_ringName,
							void      *i_buf2,
							uint32_t  i_sizeBuf2);
							
int get_delta_ring_from_image(
              char       *i_fnImage,
              char       *i_varName,
              uint32_t   i_ddLevel,
              uint8_t    i_sysPhase,
              uint8_t    i_override,
              MetaData  **o_metaData,
              CompressedScanData  **o_deltaRingRS4,
              uint32_t   verbose);

int write_wiggle_flip_to_image(
              void       *io_imageOut,
              uint32_t   *i_sizeImageMaxNew,
              DeltaRingLayout *i_ringLayout,
              uint32_t   *i_wfInline,
              uint32_t   i_wfInlineLenInWords);

int get_ring_layout_from_image(  
              const void *i_imageIn,
              uint32_t   i_ddLevel,
              uint8_t    i_sysPhase,
              DeltaRingLayout  *o_rs4RingLayout,
              void       **nextRing);

int append_empty_section(
              void      *io_image,
              int       *i_sizeImageMaxNew,
              uint32_t  i_sectionId,
              int       *i_sizeSection,
							uint8_t   i_bFixed);

int initialize_slw_section(
              void      *io_image,
              uint32_t  *i_sizeImageMaxNew);

int create_and_initialize_fixed_image(
              void      *io_image);

int update_runtime_scom_pointer(
							void			*io_image);

void cleanup(
              void *buf1=NULL,
              void *buf2=NULL,
              void *buf3=NULL,
              void *buf4=NULL,
              void *buf5=NULL);
              
#endif  // End of !(defined __CEN_XIP_CUSTOMIZE_C)

#endif  // End of !(defined __P8_PORE_TABLE_GEN_API_C) && !(defined SLW_COMMAND_LINE_RAM)

// Byte-reverse a 32-bit integer if on an LE machine
static inline uint32_t myRev32(const uint32_t i_x)
{
    uint32_t rx;

#ifdef _BIG_ENDIAN
    rx = i_x;
#else
    uint8_t *pix = (uint8_t*)(&i_x);
    uint8_t *prx = (uint8_t*)(&rx);

    prx[0] = pix[3];
    prx[1] = pix[2];
    prx[2] = pix[1];
    prx[3] = pix[0];
#endif

    return rx;
}

// Byte-reverse a 64-bit integer if on a little-endian machine
static inline uint64_t myRev64(const uint64_t i_x)
{
    uint64_t rx;

#ifdef _BIG_ENDIAN
    rx = i_x;
#else
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
#endif

    return rx;
}

// N-byte align an address, offset or size (aos)
static inline uint64_t myByteAlign( const uint8_t nBytes, const uint64_t aos)
{
  return ((aos+nBytes-1)/nBytes)*nBytes;
}

#if( defined(__cplusplus) && !defined(PLIC_MODULE) )
}
#endif
