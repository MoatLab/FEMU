/********************************************************************************/
/*										*/
/*	     	TPM2 Novoton Proprietary Command Utilities			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: ntc2lib.h 1257 2018-06-27 20:52:08Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015, 2017					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#ifndef NTC2LIB_H
#define NTC2LIB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/TPM_Types.h>
#include <ibmtss/Unmarshal_fp.h>

/* default values for System P8 I2C */

#define P8_REQUIRED_i2cLoc1_2  	0xff
#define P8_REQUIRED_i2cLoc3_4  	0xff
#define P8_REQUIRED_AltCfg	0x03
#define P8_REQUIRED_Direction  	0x00
#define P8_REQUIRED_PullUp    	0xff
#define P8_REQUIRED_PushPull   	0xff
#define P8_REQUIRED_CFG_A    	0xfe
#define P8_REQUIRED_CFG_B    	0xff
#define P8_REQUIRED_CFG_C    	0xff
#define P8_REQUIRED_CFG_D    	0xff
#define P8_REQUIRED_CFG_E    	0xff
#define P8_REQUIRED_CFG_F    	0xff
#define P8_REQUIRED_CFG_G    	0xff
#define P8_REQUIRED_CFG_H    	0xff
#define P8_REQUIRED_CFG_I    	0xff
#define P8_REQUIRED_CFG_J    	0xff
#define P8_REQUIRED_IsValid    	0xaa
#define P8_REQUIRED_IsLocked	0x00;

/* default values for System P8 I2C */

#define P9_REQUIRED_i2cLoc1_2  	0xa9		/* changed */
#define P9_REQUIRED_i2cLoc3_4  	0xa5		/* changed */
#define P9_REQUIRED_AltCfg	0x03
#define P9_REQUIRED_Direction  	0x00
#define P9_REQUIRED_PullUp    	0xff
#define P9_REQUIRED_PushPull   	0xff
#define P9_REQUIRED_CFG_A    	0xfe
#define P9_REQUIRED_CFG_B    	0xff
#define P9_REQUIRED_CFG_C    	0xff
#define P9_REQUIRED_CFG_D    	0xff
#define P9_REQUIRED_CFG_E    	0xff
#define P9_REQUIRED_CFG_F    	0xff
#define P9_REQUIRED_CFG_G    	0xff
#define P9_REQUIRED_CFG_H    	0xf0		/* changed */
#define P9_REQUIRED_CFG_I    	0xff
#define P9_REQUIRED_CFG_J    	0xff
#define P9_REQUIRED_IsValid    	0xaa
#define P9_REQUIRED_IsLocked	0x00;

/* required values, others not supported */

#define FIXED_Direction   	0x00
#define FIXED_PullUp    	0xff
#define FIXED_PushPull    	0xff
#define FIXED_CFG_F    		0xff
#define FIXED_CFG_I    		0xff
#define FIXED_CFG_J    		0xff
#define FIXED_IsValid    	0xaa

#ifdef __cplusplus
extern "C" {
#endif

    TPM_RC
    verifyConfig(NTC2_CFG_STRUCT *expected, NTC2_CFG_STRUCT *actual, int verifyLocked);
    void
    requiredConfig(NTC2_CFG_STRUCT *preConfig, int p9);
    
#ifdef __cplusplus
}
#endif

#endif
