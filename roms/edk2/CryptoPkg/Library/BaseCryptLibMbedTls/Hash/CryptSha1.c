/** @file
  SHA-1 Digest Wrapper Implementation over MbedTLS.

Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <mbedtls/sha1.h>
#include <mbedtls/compat-2.x.h>

#ifndef DISABLE_SHA1_DEPRECATED_INTERFACES

/**
  Retrieves the size, in bytes, of the context buffer required for SHA-1 hash operations.

  @return  The size, in bytes, of the context buffer required for SHA-1 hash operations.

**/
UINTN
EFIAPI
Sha1GetContextSize (
  VOID
  )
{
  //
  // Retrieves MbedTLS SHA Context Size
  //
  return (UINTN)(sizeof (mbedtls_sha1_context));
}

/**
  Initializes user-supplied memory pointed by Sha1Context as SHA-1 hash context for
  subsequent use.

  If Sha1Context is NULL, then return FALSE.

  @param[out]  Sha1Context  Pointer to SHA-1 context being initialized.

  @retval TRUE   SHA-1 context initialization succeeded.
  @retval FALSE  SHA-1 context initialization failed.

**/
BOOLEAN
EFIAPI
Sha1Init (
  OUT  VOID  *Sha1Context
  )
{
  INT32  Ret;

  if (Sha1Context == NULL) {
    return FALSE;
  }

  mbedtls_sha1_init (Sha1Context);

  Ret = mbedtls_sha1_starts_ret (Sha1Context);
  if (Ret != 0) {
    return FALSE;
  }

  return TRUE;
}

/**
  Makes a copy of an existing SHA-1 context.

  If Sha1Context is NULL, then return FALSE.
  If NewSha1Context is NULL, then return FALSE.

  @param[in]  Sha1Context     Pointer to SHA-1 context being copied.
  @param[out] NewSha1Context  Pointer to new SHA-1 context.

  @retval TRUE   SHA-1 context copy succeeded.
  @retval FALSE  SHA-1 context copy failed.

**/
BOOLEAN
EFIAPI
Sha1Duplicate (
  IN   CONST VOID  *Sha1Context,
  OUT  VOID        *NewSha1Context
  )
{
  if ((Sha1Context == NULL) || (NewSha1Context == NULL)) {
    return FALSE;
  }

  mbedtls_sha1_clone (NewSha1Context, Sha1Context);

  return TRUE;
}

/**
  Digests the input data and updates SHA-1 context.

  This function performs SHA-1 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA-1 context should be already correctly initialized by Sha1Init(), and should not be finalized
  by Sha1Final(). Behavior with invalid context is undefined.

  If Sha1Context is NULL, then return FALSE.

  @param[in, out]  Sha1Context  Pointer to the SHA-1 context.
  @param[in]       Data         Pointer to the buffer containing the data to be hashed.
  @param[in]       DataSize     Size of Data buffer in bytes.

  @retval TRUE   SHA-1 data digest succeeded.
  @retval FALSE  SHA-1 data digest failed.

**/
BOOLEAN
EFIAPI
Sha1Update (
  IN OUT  VOID        *Sha1Context,
  IN      CONST VOID  *Data,
  IN      UINTN       DataSize
  )
{
  INT32  Ret;

  if (Sha1Context == NULL) {
    return FALSE;
  }

  if ((Data == NULL) && (DataSize != 0)) {
    return FALSE;
  }

  Ret = mbedtls_sha1_update_ret (Sha1Context, Data, DataSize);
  if (Ret != 0) {
    return FALSE;
  }

  return TRUE;
}

/**
  Completes computation of the SHA-1 digest value.

  This function completes SHA-1 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA-1 context cannot
  be used again.
  SHA-1 context should be already correctly initialized by Sha1Init(), and should not be
  finalized by Sha1Final(). Behavior with invalid SHA-1 context is undefined.

  If Sha1Context is NULL, then return FALSE.
  If HashValue is NULL, then return FALSE.

  @param[in, out]  Sha1Context  Pointer to the SHA-1 context.
  @param[out]      HashValue    Pointer to a buffer that receives the SHA-1 digest
                                value (20 bytes).

  @retval TRUE   SHA-1 digest computation succeeded.
  @retval FALSE  SHA-1 digest computation failed.

**/
BOOLEAN
EFIAPI
Sha1Final (
  IN OUT  VOID   *Sha1Context,
  OUT     UINT8  *HashValue
  )
{
  INT32  Ret;

  if ((Sha1Context == NULL) || (HashValue == NULL)) {
    return FALSE;
  }

  Ret = mbedtls_sha1_finish_ret (Sha1Context, HashValue);
  mbedtls_sha1_free (Sha1Context);
  if (Ret != 0) {
    return FALSE;
  }

  return TRUE;
}

/**
  Computes the SHA-1 message digest of a input data buffer.

  This function performs the SHA-1 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   Data        Pointer to the buffer containing the data to be hashed.
  @param[in]   DataSize    Size of Data buffer in bytes.
  @param[out]  HashValue   Pointer to a buffer that receives the SHA-1 digest
                           value (20 bytes).

  @retval TRUE   SHA-1 digest computation succeeded.
  @retval FALSE  SHA-1 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
BOOLEAN
EFIAPI
Sha1HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  INT32  Ret;

  if (HashValue == NULL) {
    return FALSE;
  }

  if ((Data == NULL) && (DataSize != 0)) {
    return FALSE;
  }

  Ret = mbedtls_sha1_ret (Data, DataSize, HashValue);
  if (Ret != 0) {
    return FALSE;
  }

  return TRUE;
}

#endif
