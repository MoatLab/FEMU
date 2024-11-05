/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/usr/hwpf/hwp/build_winkle_images/p8_slw_build/p8_pore_api_custom.h $ */
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
/* $Id: p8_pore_api_custom.h,v 1.5 2012/05/22 21:25:21 cmolsen Exp $ */
/* $Source: /afs/awd/projects/eclipz/KnowledgeBase/.cvsroot/eclipz/chips/p8/working/procedures/utils/p8_pore_api_custom.h,v $ */

#include <stdint.h> /* for uint32_t */
#include <stdio.h> /* for printf */
#if !defined(__HOSTBOOT_MODULE) && !defined(__SKIBOOT__)
#include <netinet/in.h> /* for htonl */
#endif

/**
  * This file should be modified by users to appropriately handle some
  * environment-specific operations.
  */


/*********************************/
/*****  Logging and Tracing  *****/
/*********************************/
/**
 * All tracing functions assume printf-style formatting
 */

#ifndef __FAPI
/* Trace an informational message */
#define P8_PORE_ITRACE0(msg) printf("PORE> INFO: " msg "\n");
#define P8_PORE_ITRACE1(msg, arg0) printf("PORE> INFO: " msg "\n", arg0);

/* Trace an error message */
#define P8_PORE_ETRACE0(msg) printf("PORE> ERROR: " msg "\n");
#define P8_PORE_ETRACE1(msg, arg0) printf("PORE> ERROR: " msg "\n", arg0);
#define P8_PORE_ETRACE2(msg, arg0, arg1) printf("PORE> ERROR: " msg "\n", arg0, arg1);
#define P8_PORE_ETRACE3(msg, arg0, arg1, arg2) printf("PORE> ERROR: " msg "\n", arg0, arg1, arg2);
#define P8_PORE_ETRACE4(msg, arg0, arg1, arg2, arg3) printf("PORE> ERROR: " msg "\n", arg0, arg1, arg2, arg3);
#define P8_PORE_ETRACE5(msg, arg0, arg1, arg2, arg3, arg4) printf("PORE> ERROR: " msg "\n", arg0, arg1, arg2, arg3, arg4);
#endif
/* Used for debug, Cronus/FW should leave these empty */
#define P8_PORE_DTRACE0(msg)
#define P8_PORE_DTRACE1(msg, arg0) 
#define P8_PORE_DTRACE2(msg, arg0, arg1) 
#define P8_PORE_DTRACE3(msg, arg0, arg1, arg2) 
#define P8_PORE_DTRACE4(msg, arg0, arg1, arg2, arg3) 

/****** Following is only used for debug purposes ******/
/* FW/Cronus should NOT include this section */
/* DTRACE - Print debug statements to command line */
/* FTRACE - Print text PORE instructions of cpureg setup to DEBUG_FILE */
/*
#define P8_PORE_DTRACE0(msg) printf("PORE> DEBUG: " msg "\n");
#define P8_PORE_DTRACE1(msg, arg0) printf("PORE> DEBUG: " msg "\n", arg0);
#define P8_PORE_DTRACE2(msg, arg0, arg1) printf("PORE> DEBUG: " msg "\n", arg0, arg1);
#define P8_PORE_DTRACE3(msg, arg0, arg1, arg2) printf("PORE> DEBUG: " msg "\n", arg0, arg1, arg2);
#define P8_PORE_DTRACE4(msg, arg0, arg1, arg2, arg3) printf("PORE> DEBUG: " msg "\n", arg0, arg1, arg2, arg3);
*/

/**********************************/
/*****  Endian-ness Handling  *****/
/**********************************/
/**
 * Handle byte-swapping if necessary
 */

/* Default to big-endian format on both sides */
#define P8_PORE_HOST_TO_BIG32( bit32_int )  htonl(bit32_int)
#define P8_PORE_BIG32_TO_HOST( bit32_int )  ntohl(bit32_int)
#define P8_PORE_HOST_TO_BIG16( bit16_int )  htonl(bit16_int)
#define P8_PORE_BIG16_TO_HOST( bit16_int )  ntohl(bit16_int)

/*
*************** Do not edit this area ***************
This section is automatically updated by CVS when you check in this file.
Be sure to create CVS comments when you commit so that they can be included here.

$Log: p8_pore_api_custom.h,v $
Revision 1.5  2012/05/22 21:25:21  cmolsen
Updated to remove FAPI tracing, which is not allowed in plain C files.

Revision 1.4  2012/05/21 14:45:41  cmolsen
Updated to address Gerrit review II comments about printf() usage.

Revision 1.3  2012/05/15 19:53:38  cmolsen
Updated to address Gerrit review comments:
- Hostboot doesn't support printf().

Revision 1.2  2012/04/13 16:45:32  cmolsen
Includes __HOSTBOOT_MODULE exclude of <netinit/in.h>

Revision 1.1  2011/08/25 12:28:38  yjkim
initial check in

Revision 1.10  2010/08/30 23:27:17  schwartz
Added TRACE statements to include specified number of arguments
Defined branch type constants
Added constant for last scom op used to check if operation input to gen_scan is valid
Added mult spr error constant
Added p7p_pore_gen_wait API
Changed additional C++ style comments to C style
Initialized all variables to 0
Removed FTRACE statements
Added additional information to trace statements
Updated gen_scom to use the defined operation constants
Updated branch gen_relbranch to use defined branch type constants
Added rc check for calls to p7p_pore_gen_cpureg_status and p7p_pore_span_128byte_boundary subroutines

Revision 1.9  2010/08/30 14:57:54  schwartz
Removed FTRACE and associated #define statements
Changed TRACE macros to multiple macros with specified number of args

Revision 1.6  2010/08/26 15:13:34  schwartz
Fixed more C++ style comments to C style comments

Revision 1.5  2010/06/23 23:06:37  schwartz
Defined additional trace functions to be used for debugging, not in FW or Cronus

Revision 1.4  2010/05/24 02:34:07  schwartz
Fixed errors that appear when using -Werrors flag
Added in cvs logging (hopefully)


*/
