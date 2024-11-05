/** @file
  RSA Asymmetric Cipher Wrapper Implementation over MbedTLS.

  This file implements following APIs which provide basic capabilities for RSA:
  1) RsaPssVerify

Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <mbedtls/rsa.h>

/**
  Verifies the RSA signature with RSASSA-PSS signature scheme defined in RFC 8017.
  Implementation determines salt length automatically from the signature encoding.
  Mask generation function is the same as the message digest algorithm.
  Salt length should be equal to digest length.

  @param[in]  RsaContext      Pointer to RSA context for signature verification.
  @param[in]  Message         Pointer to octet message to be verified.
  @param[in]  MsgSize         Size of the message in bytes.
  @param[in]  Signature       Pointer to RSASSA-PSS signature to be verified.
  @param[in]  SigSize         Size of signature in bytes.
  @param[in]  DigestLen       Length of digest for RSA operation.
  @param[in]  SaltLen         Salt length for PSS encoding.

  @retval  TRUE   Valid signature encoded in RSASSA-PSS.
  @retval  FALSE  Invalid signature or invalid RSA context.

**/
BOOLEAN
EFIAPI
RsaPssVerify (
  IN  VOID         *RsaContext,
  IN  CONST UINT8  *Message,
  IN  UINTN        MsgSize,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize,
  IN  UINT16       DigestLen,
  IN  UINT16       SaltLen
  )
{
  INT32                Ret;
  mbedtls_md_type_t    md_alg;
  UINT8                HashValue[SHA512_DIGEST_SIZE];
  BOOLEAN              Status;
  UINTN                ShaCtxSize;
  VOID                 *ShaCtx;
  mbedtls_rsa_context  *RsaKey;

  if (RsaContext == NULL) {
    return FALSE;
  }

  if ((Message == NULL) || (MsgSize == 0) || (MsgSize > INT_MAX)) {
    return FALSE;
  }

  if (SaltLen != DigestLen) {
    return FALSE;
  }

  if ((Signature == NULL) || (SigSize == 0) || (SigSize > INT_MAX)) {
    return FALSE;
  }

  RsaKey = (mbedtls_rsa_context *)RsaContext;
  if (mbedtls_rsa_complete (RsaKey) != 0) {
    return FALSE;
  }

  ZeroMem (HashValue, DigestLen);

  switch (DigestLen) {
    case SHA256_DIGEST_SIZE:
      md_alg     = MBEDTLS_MD_SHA256;
      ShaCtxSize = Sha256GetContextSize ();
      ShaCtx     = AllocateZeroPool (ShaCtxSize);

      Status = Sha256Init (ShaCtx);
      if (!Status) {
        return FALSE;
      }

      Status = Sha256Update (ShaCtx, Message, MsgSize);
      if (!Status) {
        FreePool (ShaCtx);
        return FALSE;
      }

      Status = Sha256Final (ShaCtx, HashValue);
      if (!Status) {
        FreePool (ShaCtx);
        return FALSE;
      }

      FreePool (ShaCtx);
      break;

    case SHA384_DIGEST_SIZE:
      md_alg     = MBEDTLS_MD_SHA384;
      ShaCtxSize = Sha384GetContextSize ();
      ShaCtx     = AllocateZeroPool (ShaCtxSize);

      Status = Sha384Init (ShaCtx);
      if (!Status) {
        return FALSE;
      }

      Status = Sha384Update (ShaCtx, Message, MsgSize);
      if (!Status) {
        FreePool (ShaCtx);
        return FALSE;
      }

      Status = Sha384Final (ShaCtx, HashValue);
      if (!Status) {
        FreePool (ShaCtx);
        return FALSE;
      }

      FreePool (ShaCtx);
      break;

    case SHA512_DIGEST_SIZE:
      md_alg     = MBEDTLS_MD_SHA512;
      ShaCtxSize = Sha512GetContextSize ();
      ShaCtx     = AllocateZeroPool (ShaCtxSize);

      Status = Sha512Init (ShaCtx);
      if (!Status) {
        return FALSE;
      }

      Status = Sha512Update (ShaCtx, Message, MsgSize);
      if (!Status) {
        FreePool (ShaCtx);
        return FALSE;
      }

      Status = Sha512Final (ShaCtx, HashValue);
      if (!Status) {
        FreePool (ShaCtx);
        return FALSE;
      }

      FreePool (ShaCtx);
      break;

    default:
      return FALSE;
  }

  if (mbedtls_rsa_get_len (RsaContext) != SigSize) {
    return FALSE;
  }

  mbedtls_rsa_set_padding (RsaContext, MBEDTLS_RSA_PKCS_V21, md_alg);

  Ret = mbedtls_rsa_rsassa_pss_verify (
          RsaContext,
          md_alg,
          (UINT32)DigestLen,
          HashValue,
          Signature
          );
  if (Ret != 0) {
    return FALSE;
  }

  return TRUE;
}
