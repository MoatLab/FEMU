/********************************************************************************/
/*										*/
/*			Sample Crypto Utilities					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2017 - 2019.					*/
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

#ifndef CRYPTUTILS_H
#define CRYPTUTILS_H

/* Windows 10 crypto API clashes with openssl */
#ifdef TPM_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#endif

/* TPM_TSS_NO_OPENSSL is a legacy macro.  cryptoutils was exposing several OpenSSL specific
   functions.  They are not available for other crypto libraries.  For OpenSSL, they are available
   but deprecated.  */

#ifndef TPM_TSS_NO_OPENSSL
#include <openssl/rand.h>
#include <openssl/pem.h>
#endif	/* TPM_TSS_NO_OPENSSL */

#ifdef TPM_TSS_MBEDTLS
#include <mbedtls/pk.h>
#endif	/* TPM_TSS_MBEDTLS */

#include <ibmtss/tss.h>

#ifdef __cplusplus
extern "C" {
#endif

    /*
      crypto library independent functions
    */

    void getCryptoLibrary(const char **name);
    
    TPM_RC convertPemToRsaPrivKey(void **rsaKey,
				  const char *pemKeyFilename,
				  const char *password);
    TPM_RC convertRsaKeyToPublicKeyBin(int 	*modulusBytes,
				       uint8_t 	**modulusBin,
				       void	*rsaKey);
    TPM_RC convertRsaKeyToPublic(TPM2B_PUBLIC 		*objectPublic,
				 int			keyType,
				 TPMI_ALG_SIG_SCHEME 	scheme,
				 TPMI_ALG_HASH 		nalg,
				 TPMI_ALG_HASH		halg,
				 void			*rsaKey);
    TPM_RC convertRsaPemToKeyPair(TPM2B_PUBLIC 		*objectPublic,
				  TPM2B_PRIVATE 	*objectPrivate,
				  int			keyType,
				  TPMI_ALG_SIG_SCHEME 	scheme,
				  TPMI_ALG_HASH 	nalg,
				  TPMI_ALG_HASH		halg,
				  const char 		*pemKeyFilename,
				  const char 		*password);
    TPM_RC convertRsaDerToKeyPair(TPM2B_PUBLIC 		*objectPublic,
				  TPM2B_SENSITIVE 	*objectSensitive,
				  int			keyType,
				  TPMI_ALG_SIG_SCHEME 	scheme,
				  TPMI_ALG_HASH 	nalg,
				  TPMI_ALG_HASH		halg,
				  const char		*derKeyFilename,
				  const char 		*password);
    TPM_RC convertRsaDerToPublic(TPM2B_PUBLIC 		*objectPublic,
				 int			keyType,
				 TPMI_ALG_SIG_SCHEME 	scheme,
				 TPMI_ALG_HASH 		nalg,
				 TPMI_ALG_HASH		halg,
				 const char		*derKeyFilename);
    TPM_RC convertRsaPemToPublic(TPM2B_PUBLIC 		*objectPublic,
				 int			keyType,
				 TPMI_ALG_SIG_SCHEME 	scheme,
				 TPMI_ALG_HASH 		nalg,
				 TPMI_ALG_HASH		halg,
				 const char 		*pemKeyFilename);
    TPM_RC convertRsaPrivateKeyBinToPrivate(TPM2B_PRIVATE 	*objectPrivate,
					    TPM2B_SENSITIVE 	*objectSensitive,
					    int 		privateKeyBytes,
					    uint8_t 		*privateKeyBin,
					    const char 		*password);
    TPM_RC convertRsaPublicKeyBinToPublic(TPM2B_PUBLIC 		*objectPublic,
					  int			keyType,
					  TPMI_ALG_SIG_SCHEME 	scheme,
					  TPMI_ALG_HASH 	nalg,
					  TPMI_ALG_HASH		halg,
					  int 			modulusBytes,
					  uint8_t 		*modulusBin);
    TPM_RC convertPublicToPEM(const TPM2B_PUBLIC *public,
			      const char *pemFilename);

    TPM_RC signRSAFromRSA(uint8_t *signature, size_t *signatureLength,
			  size_t signatureSize,
			  const uint8_t *digest, size_t digestLength,
			  TPMI_ALG_HASH hashAlg,
			  void *rsaKey);
    TPM_RC verifySignatureFromPem(unsigned char *message,
				  unsigned int messageSize,
				  TPMT_SIGNATURE *tSignature,
				  TPMI_ALG_HASH halg,
				  const char *pemFilename);
    TPM_RC verifyRSASignatureFromRSA(unsigned char *message,
				     unsigned int messageSize,
				     TPMT_SIGNATURE *tSignature,
				     TPMI_ALG_HASH halg,
				     void *rsaPubKey);
    TPM_RC verifySignatureFromHmacKey(unsigned char *message,
				      unsigned int messageSize,
				      TPMT_SIGNATURE *tSignature,
				      TPMI_ALG_HASH halg,
				      const char *hmacKeyFilename);

    TPM_RC convertRsaBinToTSignature(TPMT_SIGNATURE *tSignature,
				     TPMI_ALG_HASH halg,
				     uint8_t *signatureBin,
				     size_t signatureBinLen);

    /* Some OpenSSL builds do not include ECC */

#ifndef TPM_TSS_NOECC

    TPM_RC convertEcPemToKeyPair(TPM2B_PUBLIC 		*objectPublic,
				 TPM2B_PRIVATE 		*objectPrivate,
				 int			keyType,
				 TPMI_ALG_SIG_SCHEME 	scheme,
				 TPMI_ALG_HASH 		nalg,
				 TPMI_ALG_HASH		halg,
				 const char 		*pemKeyFilename,
				 const char 		*password);
    TPM_RC convertEcPemToPublic(TPM2B_PUBLIC 		*objectPublic,
				int			keyType,
				TPMI_ALG_SIG_SCHEME 	scheme,
				TPMI_ALG_HASH 		nalg,
				TPMI_ALG_HASH		halg,
				const char		*pemKeyFilename);
    TPM_RC convertEcDerToKeyPair(TPM2B_PUBLIC 		*objectPublic,
				 TPM2B_SENSITIVE 	*objectSensitive,
				 int			keyType,
				 TPMI_ALG_SIG_SCHEME 	scheme,
				 TPMI_ALG_HASH 		nalg,
				 TPMI_ALG_HASH		halg,
				 const char		*derKeyFilename,
				 const char 		*password);
    TPM_RC convertEcDerToPublic(TPM2B_PUBLIC 		*objectPublic,
				int			keyType,
				TPMI_ALG_SIG_SCHEME 	scheme,
				TPMI_ALG_HASH 		nalg,
				TPMI_ALG_HASH		halg,
				const char		*derKeyFilename);
    TPM_RC convertEcPrivateKeyBinToPrivate(TPM2B_PRIVATE 	*objectPrivate,
					   TPM2B_SENSITIVE 	*objectSensitive,
					   int 			privateKeyBytes,
					   uint8_t 		*privateKeyBin,
					   const char 		*password);
    TPM_RC convertEcBinToTSignature(TPMT_SIGNATURE 	*tSignature,
				    TPMI_ALG_HASH 	halg,
				    const uint8_t 	*signatureBin,
				    size_t 		signatureBinLen);
    
#endif	/* TPM_TSS_NOECC */
    
    /*
      OpenSSL specific functions

      These are not intended for general use.
    */
   
#ifndef TPM_TSS_NO_OPENSSL

/* Some functions add const to parameters as of openssl 1.1.0 */

#if OPENSSL_VERSION_NUMBER < 0x10100000
#define OSSLCONST
#else
#define OSSLCONST const
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000
    int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
    void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
    const X509_ALGOR *X509_get0_tbs_sigalg(const X509 *x);
    void RSA_get0_key(const RSA *rsaKey,
		      const BIGNUM **n,
		      const BIGNUM **e,
		      const BIGNUM **d);
    void RSA_get0_factors(const RSA *rsaKey,
			  const BIGNUM **p,
			  const BIGNUM **q);
#endif	/* pre openssl 1.1 */

#if OPENSSL_VERSION_NUMBER < 0x10002000
    void X509_get0_signature(OSSLCONST ASN1_BIT_STRING **psig,
			     OSSLCONST X509_ALGOR **palg, const X509 *x);
#endif	/* pre openssl 1.0.2 */

    TPM_RC convertPemToEvpPrivKey(EVP_PKEY **evpPkey,
				  const char *pemKeyFilename,
				  const char *password);
    TPM_RC convertPemToEvpPubKey(EVP_PKEY **evpPkey,
				 const char *pemKeyFilename);
    TPM_RC convertEvpPubkeyToPem(EVP_PKEY *evpPubkey,
				 const char *pemFilename);
    TPM_RC convertBin2Bn(BIGNUM **bn,
			 const unsigned char *bin,
			 unsigned int bytes);
    
    TPM_RC convertEvpPkeyToRsakey(RSA **rsaKey,
				  EVP_PKEY *evpPkey);
    TPM_RC convertRsaKeyToPrivateKeyBin(int 	*privateKeyBytes,
					uint8_t 	**privateKeyBin,
					const RSA	 *rsaKey);
    TPM_RC convertRsaKeyToPrivate(TPM2B_PRIVATE 	*objectPrivate,
				  TPM2B_SENSITIVE 	*objectSensitive,
				  RSA 			*rsaKey,
				  const char 		*password);
    TPM_RC getRsaKeyParts(const BIGNUM **n,
			  const BIGNUM **e,
			  const BIGNUM **d,
			  const BIGNUM **p,
			  const BIGNUM **q,
			  const RSA *rsaKey);
    int getRsaPubkeyAlgorithm(EVP_PKEY *pkey);
    TPM_RC convertRsaPublicToEvpPubKey(EVP_PKEY **evpPubkey,
				       const TPM2B_PUBLIC_KEY_RSA *tpm2bRsa);
    TPM_RC verifyRSASignatureFromEvpPubKey(unsigned char *message,
					   unsigned int messageSize,
					   TPMT_SIGNATURE *tSignature,
					   TPMI_ALG_HASH halg,
					   EVP_PKEY *evpPkey);

#ifndef TPM_TSS_NOECC
    TPM_RC convertEvpPkeyToEckey(EC_KEY **ecKey,
				 EVP_PKEY *evpPkey);
    TPM_RC convertEcKeyToPrivateKeyBin(int 		*privateKeyBytes,
				       uint8_t 		**privateKeyBin,
				       const EC_KEY 	*ecKey);
    TPM_RC convertEcKeyToPublicKeyBin(int 		*modulusBytes,
				      uint8_t 		**modulusBin,
				      const EC_KEY 	*ecKey);
    TPM_RC convertEcPublicKeyBinToPublic(TPM2B_PUBLIC 		*objectPublic,
					 int			keyType,
					 TPMI_ALG_SIG_SCHEME 	scheme,
					 TPMI_ALG_HASH 		nalg,
					 TPMI_ALG_HASH		halg,
					 TPMI_ECC_CURVE 	curveID,
					 int 			modulusBytes,
					 uint8_t 		*modulusBin);
    TPM_RC convertEcKeyToPrivate(TPM2B_PRIVATE 		*objectPrivate,
				 TPM2B_SENSITIVE 	*objectSensitive,
				 EC_KEY 		*ecKey,
				 const char 		*password);
    TPM_RC convertEcKeyToPublic(TPM2B_PUBLIC 		*objectPublic,
				int			keyType,
				TPMI_ALG_SIG_SCHEME 	scheme,
				TPMI_ALG_HASH 		nalg,
				TPMI_ALG_HASH		halg,
				EC_KEY 			*ecKey);
    TPM_RC convertEcPublicToEvpPubKey(EVP_PKEY **evpPubkey,	
				      const TPMS_ECC_POINT *tpmsEccPoint);
    TPM_RC verifyEcSignatureFromEvpPubKey(unsigned char *message,
					  unsigned int messageSize,
					  TPMT_SIGNATURE *tSignature,
					  EVP_PKEY *evpPkey);
    TPM_RC getEcCurve(TPMI_ECC_CURVE *curveID,
		      const EC_KEY *ecKey);
    
#endif /* TPM_TSS_NOECC */
#endif /* TPM_TSS_NO_OPENSSL */

    /*
      mbedtls specific functions

      These are not intended for general use, but are used by ekutils.c
    */

#ifdef TPM_TSS_MBEDTLS
    
    TPM_RC convertPkToRsaKey(mbedtls_rsa_context **rsaCtx,
			     mbedtls_pk_context *pkCtx);
    TPM_RC convertPkToEckey(mbedtls_ecp_keypair **ecCtx,
			    mbedtls_pk_context	*pkCtx);
    TPM_RC convertEcKeyToPublicKeyXYBin(size_t			*xBytes,
					uint8_t 		**xBin,
					size_t			*yBytes,
					uint8_t 		**yBin,
					mbedtls_ecp_keypair 	*ecKp);

#endif	/* TPM_TSS_MBEDTLS */
    
#ifdef __cplusplus
}
#endif

#endif
