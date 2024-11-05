/********************************************************************************/
/*										*/
/*	     	TPM2 Nuvoton Proprietary Command Utilities			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: ntc2lib.c 1290 2018-08-01 14:45:24Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2018					*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ntc2lib.h"

/* verifyConfig() compares the expected and actual values for the entire NTC2_CFG_STRUCT structure.

   If verifyLocked is TRUE, checks that the configuration is locked.  If FALSE, checks that the
   configuration is not locked
*/

TPM_RC verifyConfig(NTC2_CFG_STRUCT *expected, NTC2_CFG_STRUCT *actual, int verifyLocked)
{
    TPM_RC			rc = 0;
    int b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16;
    b0 = (actual->i2cLoc1_2 	== expected->i2cLoc1_2);
    if (!b0) {
	printf("ERROR: i2cLoc1_2 expect %02x actual %02x\n", expected->i2cLoc1_2, actual->i2cLoc1_2);
	rc = TPM_RC_VALUE;
    }
    b1 = (actual->i2cLoc3_4 	== expected->i2cLoc3_4);
    if (!b1) {
	printf("ERROR: i2cLoc3_4 expect %02x actual %02x\n", expected->i2cLoc3_4, actual->i2cLoc3_4);
	rc = TPM_RC_VALUE;
    }
    b2 = (actual->AltCfg 		== expected->AltCfg);
    if (!b2) {
	printf("ERROR: AltCfg expect %02x actual %02x\n", expected->AltCfg, actual->AltCfg);
	rc = TPM_RC_VALUE;
    }
    b3 = (actual->Direction 	== expected->Direction);
    if (!b3) {
	printf("ERROR: Direction expect %02x actual %02x\n", expected->Direction, actual->Direction);
	rc = TPM_RC_VALUE;
    }
    b4 = (actual->PullUp 		== expected->PullUp);
    if (!b4) {
	printf("ERROR: PullUp expect %02x actual %02x\n", expected->PullUp, actual->PullUp);
	rc = TPM_RC_VALUE;
    }
    b5 = (actual->PushPull 		== expected->PushPull);
    if (!b5) {
	printf("ERROR: PushPull expect %02x actual %02x\n", expected->PushPull, actual->PushPull);
	rc = TPM_RC_VALUE;
    }
    b6 = (actual->CFG_A 		== expected->CFG_A);
    if (!b6) {
	printf("ERROR: CFG_A expect %02x actual %02x\n", expected->CFG_A, actual->CFG_A);
	rc = TPM_RC_VALUE;
    }
    b7 = (actual->CFG_B 		== expected->CFG_B);
    if (!b7) {
	printf("ERROR: CFG_B expect %02x actual %02x\n", expected->CFG_B, actual->CFG_B);
	rc = TPM_RC_VALUE;
    }
    b8 = (actual->CFG_C 		== expected->CFG_C);
    if (!b8) {
	printf("ERROR: CFG_C expect %02x actual %02x\n", expected->CFG_C, actual->CFG_C);
	rc = TPM_RC_VALUE;
    }
    b9 = (actual->CFG_D 		== expected->CFG_D);
    if (!b9) {
	printf("ERROR: CFG_D expect %02x actual %02x\n", expected->CFG_D, actual->CFG_D);
	rc = TPM_RC_VALUE;
    }
    b10 = (actual->CFG_E 		== expected->CFG_E);
    if (!b10) {
	printf("CFG_E expect %02x actual %02x\n", expected->CFG_E, actual->CFG_E);
	rc = TPM_RC_VALUE;
    }
    b11 = (actual->CFG_F 		== expected->CFG_F);
    if (!b11) {
	printf("CFG_F expect %02x actual %02x\n", expected->CFG_F, actual->CFG_F);
	rc = TPM_RC_VALUE;
    }
    b12 = (actual->CFG_G 		== expected->CFG_G);
    if (!b12) {
	printf("ERROR: CFG_G expect %02x actual %02x\n", expected->CFG_G, actual->CFG_G);
	rc = TPM_RC_VALUE;
    }
    b13 = (actual->CFG_H 		== expected->CFG_H);
    if (!b13) {
	printf("ERROR: CFG_H expect %02x actual %02x\n", expected->CFG_H, actual->CFG_H);
	rc = TPM_RC_VALUE;
    }
    b14 = (actual->CFG_I 		== expected->CFG_I);
    if (!b14) {
	printf("ERROR: CFG_I expect %02x actual %02x\n", expected->CFG_I, actual->CFG_I);
	rc = TPM_RC_VALUE;
    }
    b15 = (actual->CFG_J 		== expected->CFG_J);
    if (!b15) {
	printf("ERROR: CFG_J expect %02x actual %02x\n", expected->CFG_J, actual->CFG_J);
	rc = TPM_RC_VALUE;
    }
    b16 = (actual->IsValid 		== expected->IsValid);
    if (!b16) {
	printf("ERROR: IsValid expect %02x actual %02x\n", expected->IsValid, actual->IsValid);
	rc = TPM_RC_VALUE;
    }
    if (verifyLocked) {
	if (actual->IsLocked != 0xaa) {
	    printf("ERROR: IsLocked is %02x not %02x\n",
		   actual->IsLocked, 0xaa);
	    rc = TPM_RC_VALUE;
	}
    }
    else {
	if (actual->IsLocked != 0xff) {
	    printf("ERROR: IsLocked %02x not %02x\n",
		   actual->IsLocked, 0xff);
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* requiredConfig() fills in the structure with the required values

   p9 FALSE uses P8 values.  p9 TRUE uses P9 values
*/

void requiredConfig(NTC2_CFG_STRUCT *preConfig, int p9)
{
    /* p8 preConfig */
    if (!p9) {
	preConfig->i2cLoc1_2 	= P8_REQUIRED_i2cLoc1_2;
	preConfig->i2cLoc3_4 	= P8_REQUIRED_i2cLoc3_4;
	preConfig->AltCfg 	= P8_REQUIRED_AltCfg;
	preConfig->Direction 	= P8_REQUIRED_Direction;
	preConfig->PullUp 	= P8_REQUIRED_PullUp;
	preConfig->PushPull 	= P8_REQUIRED_PushPull;
	preConfig->CFG_A 	= P8_REQUIRED_CFG_A;
	preConfig->CFG_B 	= P8_REQUIRED_CFG_B;
	preConfig->CFG_C 	= P8_REQUIRED_CFG_C;
	preConfig->CFG_D 	= P8_REQUIRED_CFG_D;
	preConfig->CFG_E 	= P8_REQUIRED_CFG_E;
	preConfig->CFG_F 	= P8_REQUIRED_CFG_F;
	preConfig->CFG_G 	= P8_REQUIRED_CFG_G;
	preConfig->CFG_H 	= P8_REQUIRED_CFG_H;
	preConfig->CFG_I 	= P8_REQUIRED_CFG_I;
	preConfig->CFG_J 	= P8_REQUIRED_CFG_J;
	preConfig->IsValid 	= P8_REQUIRED_IsValid;
	preConfig->IsLocked 	= P8_REQUIRED_IsLocked;
    }
    /* p9 preConfig */
    else {
	preConfig->i2cLoc1_2 	= P9_REQUIRED_i2cLoc1_2;
	preConfig->i2cLoc3_4 	= P9_REQUIRED_i2cLoc3_4;
	preConfig->AltCfg 	= P9_REQUIRED_AltCfg;
	preConfig->Direction 	= P9_REQUIRED_Direction;
	preConfig->PullUp 	= P9_REQUIRED_PullUp;
	preConfig->PushPull 	= P9_REQUIRED_PushPull;
	preConfig->CFG_A 	= P9_REQUIRED_CFG_A;
	preConfig->CFG_B 	= P9_REQUIRED_CFG_B;
	preConfig->CFG_C 	= P9_REQUIRED_CFG_C;
	preConfig->CFG_D 	= P9_REQUIRED_CFG_D;
	preConfig->CFG_E 	= P9_REQUIRED_CFG_E;
	preConfig->CFG_F 	= P9_REQUIRED_CFG_F;
	preConfig->CFG_G 	= P9_REQUIRED_CFG_G;
	preConfig->CFG_H 	= P9_REQUIRED_CFG_H;
	preConfig->CFG_I 	= P9_REQUIRED_CFG_I;
	preConfig->CFG_J 	= P9_REQUIRED_CFG_J;
	preConfig->IsValid 	= P9_REQUIRED_IsValid;
	preConfig->IsLocked 	= P9_REQUIRED_IsLocked;
    }
    return;
}


