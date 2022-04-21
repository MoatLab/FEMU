/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/import/chips/p9/procedures/hwp/lib/p9_hcd_header_defs.H $ */
/*                                                                        */
/* OpenPOWER HostBoot Project                                             */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2016,2017                        */
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
///
/// @file  p9_hcd_header_defs.H
/// @brief defines header constants based on file types
///
/// This header contains those cpp manifest constants required for processing
/// the linker scripts used to generate OCC code images.  As these are used
/// by linker scripts as well as by C++ code, these cannot be solely be put
/// into a namespace. Prefixing these with the region name is the attempt
/// to make these globally unique when this header is included in C++ code.
///
//  *HWP HWP Owner:        David Du   <daviddu@us.ibm.com>
//  *HWP Backup HWP Owner: Greg Still <stillgs@us.ibm.com>
//  *HWP FW Owner:         Prem Jha <premjha2@in.ibm.com>
//  *HWP Team:             PM
//  *HWP Level:            2
//  *HWP Consumed by:      PM
//

#ifndef __HCD_HEADER_DEFS_H__
#define __HCD_HEADER_DEFS_H__

/// Macros for generating an Hcode header section
///
/// The CPP macros HCD_HDR_UINTxx generate equivalent code depending on
/// whether they are being called from assembler (where they actually
/// create the header section data) or from C (where they specifiy a
/// C-structure form of the contents of the header section.
///
/// In assembler each invocation also creates space in the header section

#ifdef __ASSEMBLER__

// *INDENT-OFF*
    .macro  hcd_header_uint64, symbol:req, value = 0
    .global \symbol
\symbol\():
    .quad (\value)
    .endm

    .macro  hcd_header_uint32, symbol:req, value = 0
    .global \symbol
    \symbol\():
    .long (\value)
    .endm

    .macro  hcd_header_uint16, symbol:req, value = 0
    .global \symbol
\symbol\():
    .short (\value)
    .endm

    .macro  hcd_header_uint8, symbol:req, value = 0
    .global \symbol
\symbol\():
    .byte (\value)
    .endm

    .macro  hcd_header_uint8_vec, symbol:req, number:req, value = 0
    .global \symbol
\symbol\():
    .rept (\number)
    .byte (\value)
    .endr
    .endm

    .macro  hcd_header_attn, symbol:req, number = 1
    .global \symbol
\symbol\():
    .rept (\number)
    .long 0x00000200
    .endr
    .endm

    .macro  hcd_header_attn_pad, align:req
    .balignl (\align), 0x00000200
    .endm

     .macro  hcd_header_pad, align:req
     .balignl (\align), 0
     .endm
// *INDENT-ON*

#define ULL(x) x
#define HCD_CONST(name, expr)   .set name, expr;
#define HCD_CONST64(name, expr) .set name, expr;

#define HCD_HDR_UINT64(symbol, value) hcd_header_uint64 symbol value
#define HCD_HDR_UINT32(symbol, value) hcd_header_uint32 symbol value
#define HCD_HDR_UINT16(symbol, value) hcd_header_uint16 symbol value
#define HCD_HDR_UINT8(symbol, value)  hcd_header_uint8  symbol value
#define HCD_HDR_UINT8_VEC(symbol, number, value)  hcd_header_uint8_vec  symbol number value
#define HCD_HDR_ATTN(symbol, number)  hcd_header_attn symbol number
#define HCD_HDR_ATTN_PAD(align)       hcd_header_attn_pad align
#define HCD_HDR_PAD(align)            hcd_header_pad      align

#else // NOT __ASSEMBLER__

#ifdef __LINKERSCRIPT__

    #define ULL(x) x
    #define POUND_DEFINE #define
    #define HCD_CONST(name, expr)   POUND_DEFINE name expr
    #define HCD_CONST64(name, expr) POUND_DEFINE name expr

#else

    #define ULL(x) x##ull
    #define HCD_CONST(name, expr)   enum { name = expr };
    #define HCD_CONST64(name, expr) enum { name = expr };

    #define HCD_HDR_UINT64(symbol, value) uint64_t symbol
    #define HCD_HDR_UINT32(symbol, value) uint32_t symbol
    #define HCD_HDR_UINT16(symbol, value) uint16_t symbol
    #define HCD_HDR_UINT8(symbol, value)  uint8_t  symbol
    #define HCD_HDR_UINT8_VEC(symbol, number, value) uint8_t  symbol[number]
    #define HCD_HDR_ATTN(symbol, number)  uint32_t symbol[number]
    #define HCD_HDR_ATTN_PAD(align)
    #define HCD_HDR_PAD(align)

#endif // __LINKERSCRIPT__
#endif // __ASSEMBLER__

// Stringification

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#endif // __HCD_HEADER_DEFS_H__
