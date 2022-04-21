/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/usr/hwpf/hwp/include/fapi_sbe_common.H $                  */
/*                                                                        */
/* OpenPOWER HostBoot Project                                             */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2012,2014                        */
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
#ifndef __FAPI_SBE_COMMON_H
#define __FAPI_SBE_COMMON_H

// $Id: fapi_sbe_common.H,v 1.1 2012/04/16 23:55:37 bcbrock Exp $
// $Source: /afs/awd/projects/eclipz/KnowledgeBase/.cvsroot/eclipz/chips/p8/working/procedures/fapi_sbe_common.H,v $
//------------------------------------------------------------------------------
// *! (C) Copyright International Business Machines Corp. 2011
// *! All Rights Reserved -- Property of IBM
// *! ***  ***
//------------------------------------------------------------------------------
// *! OWNER NAME  :               Email:

/// \file fapi_sbe_common.H
/// \brief Definitions common to FAPI and SBE procedures
///
/// Several preprocessor macros are required to have different definitions in
/// C, C++ and SBE assembly procedures.  These common forms are collected here.

#if defined __ASSEMBLER__

#define CONST_UINT8_T(name, expr) .set name, (expr)
#define CONST_UINT32_T(name, expr) .set name, (expr)
#define CONST_UINT64_T(name, expr) .set name, (expr)

#define ULL(x) x

#elif defined __cplusplus

#include <stdint.h>

#define CONST_UINT8_T(name, expr) const uint8_t name = (expr);
#define CONST_UINT32_T(name, expr) const uint32_t name = (expr);
#define CONST_UINT64_T(name, expr) const uint64_t name = (expr);

#define ULL(x) x##ull

#else // C code

// CONST_UINT[8,3,64]_T() can't be used in C code/headers; Use 
//
//     #define <symbol> <value> [ or ULL(<value>) for 64-bit constants

#define ULL(x) x##ull

#endif  // __ASSEMBLER__

#endif  // __FAPI_SBE_COMMON_H
