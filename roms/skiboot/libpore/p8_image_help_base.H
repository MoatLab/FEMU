/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/usr/hwpf/hwp/build_winkle_images/p8_slw_build/p8_image_help_base.H $ */
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
// $Id: p8_image_help_base.H,v 1.18 2013/06/10 22:08:20 jeshua Exp $
//------------------------------------------------------------------------------
//  Title:  p8_image_help_base.H
//  Description:  Contains the most basic structures and defines needed for 
//                image building and interpretation.
//------------------------------------------------------------------------------
#ifndef _P8_IMAGE_HELP_BASE_H_
#define _P8_IMAGE_HELP_BASE_H_

#include <sbe_xip_image.h>

//
// Various image/ring buffer sizes. Must be used by all users (VBU, FSP, HB, HBI, Cronus)
//
const uint32_t  MAX_REF_IMAGE_SIZE      =   5000000; // Max reference image size.
const uint32_t  FIXED_SEEPROM_WORK_SPACE=  128*1024; // Max work space for Seeprom img.
const uint32_t  MAX_SEEPROM_IMAGE_SIZE  =   56*1024; // Max Seeprom image size.
// Fixed SLW image size (Ensure 128-byte alignment.)
const uint32_t  FIXED_SLW_IMAGE_SIZE    = 1024*1024; // Fixed SLW image size for _fixed.
const uint32_t  FIXED_RING_BUF_SIZE     =     60000; // Fixed ring buf size for _fixed.

const uint8_t   MAX_VPD_TYPES           =   2;   // #G and #R, so far.
#define         CHIPLET_ID_MIN            0x00 
#define         CHIPLET_ID_MAX            0x1F 
#define         CHIPLET_ID_EX_MIN         0x10 
#define         CHIPLET_ID_EX_MAX         0x1F 
const uint8_t   MAX_CHIPLETS            = CHIPLET_ID_MAX-CHIPLET_ID_MIN+1;
const uint32_t  ASM_RS4_LAUNCH_BUF_SIZE =  24; // Byte size of RS4 launch buffer. 
const uint32_t  WF_ENCAP_SIZE           = 400; // Byte size of WF encapsulation.
                                               // (Actually, only 304B but may change.)
const uint32_t  WF_WORST_CASE_SIZE_FAC  =   4; // WC WF size = 3x ring length.
                                               // (Assumes 12B per write.)
                                               // (4x w/waits instructions.)
const uint32_t  LISTING_STRING_SIZE     = 256;
const uint64_t  MAX_UINT64_T            = (uint64_t)0xFFFFFFFF<<32 | (uint64_t)0xFFFFFFFF;

const uint8_t RING_SECTION_ID[] = {
  SBE_XIP_SECTION_RINGS,
  SBE_XIP_SECTION_DCRINGS,
};
const uint8_t RING_SECTION_ID_SIZE = sizeof(RING_SECTION_ID) / sizeof(RING_SECTION_ID[0]);

#ifdef __cplusplus
extern "C" {
#endif

// Base (shared) ring layout for both RS4 and Wiggle-flip layouts.
typedef struct {
  uint64_t entryOffset;
  uint64_t backItemPtr;
  uint32_t sizeOfThis;
  uint32_t sizeOfMeta; // Exact size of meta data. Arbitrary size. Not null terminated.
} BaseRingLayout;

// RS4 specific layout.
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
} Rs4RingLayout;

// PairingInfo is used for pairing, or matching, a back pointer address of a
// ring block with its corresponding TOC name.
typedef struct {
    uint64_t address;     // (in) Holds PORE backPtr addr of the ring
    uint8_t  vectorpos;   // (in) Vector position of fwdPtr [0;31]
                          //      max=0  for most VPD rings 
                          //      max=1  for all non-VPD rings
                          //      max=1  for perv_ VPD rings
                          //      max=15 for most VPD ex_ rings
                          //      max=31 for 16 ex_ chiplets with override
    char     *name;       // (out) TOC name
    uint8_t  isvpd;       // (out) 0: Non-VPD ring  1: VPD ring
    uint8_t  overridable; // (out) 0: No (most VPD rings)  1: Yes (all non-VPD rings)
    uint8_t  override;    // (out) 0: base  1: override
} PairingInfo;


///
/// ****************************************************************************
/// Function declares.
/// ****************************************************************************
///
int over_write_ring_data_in_image(  void            *io_image,
                                    const char      *i_ringName,
                                    const void      *i_ringData,    // WF or RS4
                                    const uint32_t  i_sizeRingData, // Byte size
                                    const uint8_t   i_idxVector,
                                    const uint8_t   i_override,
                                    const uint8_t   i_overridable );


#ifdef __cplusplus
}
#endif

#endif //_P8_IMAGE_HELP_BASE_H_
