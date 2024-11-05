/********************************************************************************/
/*										*/
/*			     TSS Library Independent Crypto Support		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2019.					*/
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

/* This is a semi-public header. The API should be stable, but is less guaranteed.

   It is useful for applications that need some basic crypto functions.
*/

#ifndef TSSCRYPTOH_H
#define TSSCRYPTOH_H

#ifdef __cplusplus
extern "C" {
#endif

    LIB_EXPORT
    uint16_t TSS_GetDigestBlockSize(TPM_ALG_ID hashAlg)
#ifdef __ULTRAVISOR__
	__attribute__ ((const))
#endif
	;

    LIB_EXPORT
    TPM_RC TSS_Hash_Generate(TPMT_HA *digest,
			     ...);

    LIB_EXPORT
    TPM_RC TSS_HMAC_Generate(TPMT_HA *digest,
			     const TPM2B_KEY *hmacKey,
			     ...);
    LIB_EXPORT
    TPM_RC TSS_HMAC_Verify(TPMT_HA *expect,
			   const TPM2B_KEY *hmacKey,
			   UINT32 sizeInBytes,
			   ...);
    LIB_EXPORT
    TPM_RC TSS_KDFA(uint8_t          *keyStream,
		    TPM_ALG_ID       hashAlg,
		    const TPM2B     *key,
		    const char      *label,
		    const TPM2B     *contextU,
		    const TPM2B     *contextV,
		    uint32_t         sizeInBits);

    LIB_EXPORT
    TPM_RC TSS_KDFE(uint8_t          *keyStream,
		    TPM_ALG_ID       hashAlg,
		    const TPM2B     *key,
		    const char      *label,
		    const TPM2B     *contextU,
		    const TPM2B     *contextV,
		    uint32_t         sizeInBits);

    uint16_t TSS_Sym_GetBlockSize(TPM_ALG_ID	symmetricAlg, 
				  uint16_t	keySizeInBits)
#ifdef __ULTRAVISOR__
	__attribute__ ((const))
#endif
	;

#ifdef __cplusplus
}
#endif

#endif
