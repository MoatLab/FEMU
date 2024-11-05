/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/usr/hwpf/hwp/build_winkle_images/p8_slw_build/p8_pore_table_static_data.c $ */
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

// $Id: p8_pore_table_static_data.c,v 1.7 2013-05-23 21:10:38 dcrowell Exp $
/*------------------------------------------------------------------------------*/
/* *! (C) Copyright International Business Machines Corp. 2012                  */
/* *! All Rights Reserved -- Property of IBM                                    */
/* *! ***  ***                                                  */
/*------------------------------------------------------------------------------*/
/* *! TITLE :       p8_pore_table_static_data                                   */
/* *! DESCRIPTION : Global static data declaration file.                        */
/* *! OWNER NAME :  Michael Olsen            Email: cmolsen@us.ibm.com          */
//
/* *! COMMENTS :    This file is exclusively for PHYP environment.              */
//
/*------------------------------------------------------------------------------*/
#include <p8_pore_table_gen_api.H>

const SlwSprRegs SLW_SPR_REGS[] = {  
  /*    name               value                    swizzled     */
  // ...core regs
  { "P8_SPR_HRMOR",    P8_SPR_HRMOR, ( P8_SPR_HRMOR >>5 | ( P8_SPR_HRMOR &0x1f)<<5 ) },
  { "P8_SPR_HMEER",    P8_SPR_HMEER, ( P8_SPR_HMEER >>5 | ( P8_SPR_HMEER &0x1f)<<5 ) },
  { "P8_SPR_PMICR",    P8_SPR_PMICR, ( P8_SPR_PMICR >>5 | ( P8_SPR_PMICR &0x1f)<<5 ) },
  { "P8_SPR_PMCR",     P8_SPR_PMCR,  ( P8_SPR_PMCR  >>5 | ( P8_SPR_PMCR  &0x1f)<<5 ) },
  { "P8_SPR_HID0",     P8_SPR_HID0,  ( P8_SPR_HID0  >>5 | ( P8_SPR_HID0  &0x1f)<<5 ) },
  { "P8_SPR_HID1",     P8_SPR_HID1,  ( P8_SPR_HID1  >>5 | ( P8_SPR_HID1  &0x1f)<<5 ) },
  { "P8_SPR_HID4",     P8_SPR_HID4,  ( P8_SPR_HID4  >>5 | ( P8_SPR_HID4  &0x1f)<<5 ) },
  { "P8_SPR_HID5",     P8_SPR_HID5,  ( P8_SPR_HID5  >>5 | ( P8_SPR_HID5  &0x1f)<<5 ) },
  { "P8_CORE_XTRA8",   P8_CORE_XTRA8,(            P8_CORE_XTRA8                    ) },
  { "P8_CORE_XTRA9",   P8_CORE_XTRA9,(            P8_CORE_XTRA9                    ) },
  // ...thread regs
  { "P8_SPR_HSPRG0",   P8_SPR_HSPRG0,( P8_SPR_HSPRG0>>5 | ( P8_SPR_HSPRG0&0x1f)<<5 ) },
  { "P8_SPR_LPCR",     P8_SPR_LPCR,  ( P8_SPR_LPCR  >>5 | ( P8_SPR_LPCR  &0x1f)<<5 ) },
  { "P8_MSR_MSR",      P8_MSR_MSR,   (            P8_MSR_MSR                       ) },
  { "P8_THRD_XTRA3",   P8_THRD_XTRA3,(            P8_THRD_XTRA3                    ) },
  { "P8_THRD_XTRA4",   P8_THRD_XTRA4,(            P8_THRD_XTRA4                    ) },
};

const int SLW_SPR_REGS_SIZE = sizeof(SLW_SPR_REGS)/sizeof(SLW_SPR_REGS[0]);
