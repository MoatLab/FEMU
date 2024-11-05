/********************************************************************************/
/*										*/
/*			IWG EK Index Parsing Utilities				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2019.					*/
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

#ifndef EKUTILS_H
#define EKUTILS_H

/* Windows 10 crypto API clashes with openssl */
#ifdef TPM_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#ifndef TPM_TSS_NO_OPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#endif	/* TPM_TSS_NO_OPENSSL */

#include <ibmtss/tss.h>

/* legacy TCG IWG NV indexes */

#define EK_CERT_RSA_INDEX 	0x01c00002
#define EK_NONCE_RSA_INDEX 	0x01c00003 
#define EK_TEMPLATE_RSA_INDEX 	0x01c00004

#define EK_CERT_EC_INDEX 	0x01c0000a
#define EK_NONCE_EC_INDEX 	0x01c0000b
#define EK_TEMPLATE_EC_INDEX 	0x01c0000c

#define MAX_ROOTS		100	/* 100 should be more than enough */

#ifdef __cplusplus
extern "C" {
#endif

    /*
      crypto library independent functions
    */
    
    TPM_RC readNvBufferMax(TSS_CONTEXT *tssContext,
			   uint32_t *nvBufferMax);
    TPM_RC getIndexSize(TSS_CONTEXT *tssContext,
			uint16_t *dataSize,
			TPMI_RH_NV_INDEX nvIndex);
    TPM_RC getIndexData(TSS_CONTEXT *tssContext,
			unsigned char **buffer,
			TPMI_RH_NV_INDEX nvIndex,
			uint16_t dataSize);
    TPM_RC getIndexContents(TSS_CONTEXT *tssContext,
			    unsigned char **buffer,
			    uint16_t *bufferSize,
			    TPMI_RH_NV_INDEX nvIndex);
    void getRsaTemplate(TPMT_PUBLIC *tpmtPublic);
    void getEccTemplate(TPMT_PUBLIC *tpmtPublic);
    TPM_RC getRootCertificateFilenames(char *rootFilename[],
				       unsigned int *rootFileCount,
				       const char *listFilename,
				       int print);
    TPM_RC processEKNonce(TSS_CONTEXT *tssContext,
			  unsigned char **nonce,
			  uint16_t *nonceSize,
			  TPMI_RH_NV_INDEX ekNonceIndex,
			  int print);
    TPM_RC processEKTemplate(TSS_CONTEXT *tssContext,
			     TPMT_PUBLIC *tpmtPublic,
			     TPMI_RH_NV_INDEX ekTemplateIndex,
			     int print);
    TPM_RC convertDerToX509(void **x509Certificate,
			    uint16_t readLength,
			    const unsigned char *readBuffer);
    TPM_RC convertX509PemToDer(uint32_t *certLength,
				unsigned char **certificate,
				const char *pemCertificateFilename);
    TPM_RC convertX509ToPem(const char *pemFilename,
			    void *x509);
    void x509FreeStructure(void *x509);
    void x509PrintStructure(void *x509);
    TPM_RC processEKCertificate(TSS_CONTEXT *tssContext,
				void **ekCertificate,
				uint8_t **modulusBin,
				int *modulusBytes,
				TPMI_RH_NV_INDEX ekCertIndex,
				int print);
    TPM_RC getIndexX509Certificate(TSS_CONTEXT *tssContext,
				   void **certificate,
				   TPMI_RH_NV_INDEX nvIndex);
    TPM_RC convertCertificatePubKey(uint8_t **modulusBin,
				    int *modulusBytes,
				    void *ekCertificate,
				    TPMI_RH_NV_INDEX ekCertIndex,
				    int print);
    TPM_RC createCertificate(char **x509CertString,
			     char **pemCertString,
			     uint32_t *certLength,
			     unsigned char **certificate,
			     TPMT_PUBLIC *tpmtPublic,	
			     const char *caKeyFileName,
			     size_t issuerEntriesSize,
			     char **issuerEntries,
			     size_t subjectEntriesSize,
			     char **subjectEntries,
			     const char *caKeyPassword);
    TPM_RC processRoot(TSS_CONTEXT *tssContext,
		       TPMI_RH_NV_INDEX ekCertIndex,
		       const char *rootFilename[],
		       unsigned int rootFileCount,
		       int print);
    TPM_RC verifyCertificate(void *x509Certificate,
			     const char *rootFilename[],
			     unsigned int rootFileCount,
			     int print);
    TPM_RC processCreatePrimary(TSS_CONTEXT *tssContext,
				TPM_HANDLE *keyHandle,
				TPMI_RH_NV_INDEX ekCertIndex,
				unsigned char *nonce,
				uint16_t nonceSize,
				TPMT_PUBLIC *tpmtPublicIn,
				TPMT_PUBLIC *tpmtPublicOut,
				unsigned int noFlush,
				int print);
    TPM_RC processValidatePrimary(uint8_t *publicKeyBin,
				  int publicKeyBytes,
				  TPMT_PUBLIC *tpmtPublic,
				  TPMI_RH_NV_INDEX ekCertIndex,
				  int print);
    TPM_RC processPrimary(TSS_CONTEXT *tssContext,
			  TPM_HANDLE *keyHandle,
			  TPMI_RH_NV_INDEX ekCertIndex,
			  TPMI_RH_NV_INDEX ekNonceIndex, 
			  TPMI_RH_NV_INDEX ekTemplateIndex,
			  unsigned int noFlush,
			  int print);

    /*
      deprecated OpenSSL specific functions
    */
   
#ifndef TPM_TSS_NO_OPENSSL


    uint32_t getPubkeyFromDerCertFile(RSA  **rsaPkey,
				      X509 **x509,
				      const char *derCertificateFileName);
    uint32_t getPubKeyFromX509Cert(RSA  **rsaPkey,
				   X509 *x509);
    TPM_RC getCaStore(X509_STORE **caStore,
		      X509 *caCert[],
		      const char *rootFilename[],
		      unsigned int rootFileCount);
    TPM_RC verifyKeyUsage(X509 *ekX509Certificate,
			  int pkeyType,
			  int print);
    TPM_RC convertX509ToDer(uint32_t *certLength,
			    unsigned char **certificate,
			    X509 *x509Certificate);
#ifndef TPM_TSS_NOECC
    TPM_RC convertX509ToEc(EC_KEY **ecKey,
			   X509 *x509);
#endif	/* TPM_TSS_NOECC */
    TPM_RC convertX509ToDer(uint32_t *certLength,
			    unsigned char **certificate,
			    X509 *x509Certificate);
    TPM_RC convertPemToX509(X509 **x509,
			    const char *pemCertificateFilename);
    TPM_RC convertPemMemToX509(X509 **x509,
			       const char *pemCertificate);
    TPM_RC convertX509ToPemMem(char **pemString,
			       X509 *x509);
    TPM_RC convertX509ToString(char **x509String,
			       X509 *x509);
    TPM_RC convertCertificatePubKey12(uint8_t **modulusBin,
				      int *modulusBytes,
				      X509 *ekCertificate);

    /* certificate key to nid mapping array */

    TPM_RC startCertificate(X509 *x509Certificate,
			    uint16_t keyLength,
			    const unsigned char *keyBuffer,
			    size_t issuerEntriesSize,
			    char **issuerEntries,
			    size_t subjectEntriesSize,
			    char **subjectEntries);

    typedef struct tdCertificateName
    {
	const char *key;
	int nid;
    } CertificateName;

    TPM_RC calculateNid(void);
    TPM_RC createX509Name(X509_NAME **x509Name,
			  size_t entriesSize,
			  char **entries);
    TPM_RC addCertExtension(X509 *x509Certificate, int nid, const char *value);
    TPM_RC addCertKeyRsa(X509 *x509Certificate,
			 const TPM2B_PUBLIC_KEY_RSA *tpm2bRsa);
#ifndef TPM_TSS_NOECC
    TPM_RC addCertKeyEcc(X509 *x509Certificate,
			 const TPMS_ECC_POINT *tpmsEccPoint);
#endif	/* TPM_TSS_NOECC */
    TPM_RC addCertSignatureRoot(X509 *x509Certificate,
				const char *caKeyFileName,
				const char *caKeyPassword);
    TPM_RC TSS_RSAGetKey(const BIGNUM **n,
			 const BIGNUM **e,
			 const BIGNUM **d,
			 const BIGNUM **p,
			 const BIGNUM **q,
			 const RSA *rsaKey);

    int TSS_Pubkey_GetAlgorithm(EVP_PKEY *pkey);


#endif /* TPM_TSS_NO_OPENSSL */

#ifdef __cplusplus
}
#endif

#endif
