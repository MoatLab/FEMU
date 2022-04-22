/** @file
  Declaration of internal functions for Base Memory Library.

  Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __MEM_LIB_INTERNALS__
#define __MEM_LIB_INTERNALS__

#include <PiPei.h>

#include <Library/BaseMemoryLib.h>
#include <Library/PeiServicesTablePointerLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>

/**
  Copies a source buffer to a destination buffer, and returns the destination buffer.

  This function wraps the (*PeiServices)->CopyMem ().

  @param  DestinationBuffer   The pointer to the destination buffer of the memory copy.
  @param  SourceBuffer        The pointer to the source buffer of the memory copy.
  @param  Length              The number of bytes to copy from SourceBuffer to DestinationBuffer.

  @return DestinationBuffer.

**/
VOID *
EFIAPI
InternalMemCopyMem (
  OUT     VOID        *Destination,
  IN      CONST VOID  *Source,
  IN      UINTN       Length
  );

/**
  Fills a target buffer with a byte value, and returns the target buffer.

  This function wraps the (*PeiServices)->SetMem ().

  @param  Buffer    The memory to set.
  @param  Size      The number of bytes to set.
  @param  Value     Value of the set operation.

  @return Buffer.

**/
VOID *
EFIAPI
InternalMemSetMem (
  OUT     VOID   *Buffer,
  IN      UINTN  Size,
  IN      UINT8  Value
  );

/**
  Fills a target buffer with a 16-bit value, and returns the target buffer.

  @param  Buffer  The pointer to the target buffer to fill.
  @param  Length  The count of 16-bit value to fill.
  @param  Value   The value with which to fill Length bytes of Buffer.

  @return Buffer

**/
VOID *
EFIAPI
InternalMemSetMem16 (
  OUT     VOID    *Buffer,
  IN      UINTN   Length,
  IN      UINT16  Value
  );

/**
  Fills a target buffer with a 32-bit value, and returns the target buffer.

  @param  Buffer  The pointer to the target buffer to fill.
  @param  Length  The count of 32-bit value to fill.
  @param  Value   The value with which to fill Length bytes of Buffer.

  @return Buffer

**/
VOID *
EFIAPI
InternalMemSetMem32 (
  OUT     VOID    *Buffer,
  IN      UINTN   Length,
  IN      UINT32  Value
  );

/**
  Fills a target buffer with a 64-bit value, and returns the target buffer.

  @param  Buffer  The pointer to the target buffer to fill.
  @param  Length  The count of 64-bit value to fill.
  @param  Value   The value with which to fill Length bytes of Buffer.

  @return Buffer

**/
VOID *
EFIAPI
InternalMemSetMem64 (
  OUT     VOID    *Buffer,
  IN      UINTN   Length,
  IN      UINT64  Value
  );

/**
  Set Buffer to 0 for Size bytes.

  @param  Buffer The memory to set.
  @param  Length The number of bytes to set

  @return Buffer

**/
VOID *
EFIAPI
InternalMemZeroMem (
  OUT     VOID   *Buffer,
  IN      UINTN  Length
  );

/**
  Compares two memory buffers of a given length.

  @param  DestinationBuffer The first memory buffer
  @param  SourceBuffer      The second memory buffer
  @param  Length            The length of DestinationBuffer and SourceBuffer memory
                            regions to compare. Must be non-zero.

  @return 0                 All Length bytes of the two buffers are identical.
  @retval Non-zero          The first mismatched byte in SourceBuffer subtracted from the first
                            mismatched byte in DestinationBuffer.

**/
INTN
EFIAPI
InternalMemCompareMem (
  IN      CONST VOID  *DestinationBuffer,
  IN      CONST VOID  *SourceBuffer,
  IN      UINTN       Length
  );

/**
  Scans a target buffer for an 8-bit value, and returns a pointer to the
  matching 8-bit value in the target buffer.

  @param  Buffer  The pointer to the target buffer to scan.
  @param  Length  The count of 8-bit value to scan. Must be non-zero.
  @param  Value   The value to search for in the target buffer.

  @return The pointer to the first occurrence, or NULL if not found.

**/
CONST VOID *
EFIAPI
InternalMemScanMem8 (
  IN      CONST VOID  *Buffer,
  IN      UINTN       Length,
  IN      UINT8       Value
  );

/**
  Scans a target buffer for a 16-bit value, and returns a pointer to the
  matching 16-bit value in the target buffer.

  @param  Buffer  The pointer to the target buffer to scan.
  @param  Length  The count of 16-bit value to scan. Must be non-zero.
  @param  Value   The value to search for in the target buffer.

  @return The pointer to the first occurrence, or NULL if not found.

**/
CONST VOID *
EFIAPI
InternalMemScanMem16 (
  IN      CONST VOID  *Buffer,
  IN      UINTN       Length,
  IN      UINT16      Value
  );

/**
  Scans a target buffer for a 32-bit value, and returns a pointer to the
  matching 32-bit value in the target buffer.

  @param  Buffer  The pointer to the target buffer to scan.
  @param  Length  The count of 32-bit value to scan. Must be non-zero.
  @param  Value   The value to search for in the target buffer.

  @return The pointer to the first occurrence, or NULL if not found.

**/
CONST VOID *
EFIAPI
InternalMemScanMem32 (
  IN      CONST VOID  *Buffer,
  IN      UINTN       Length,
  IN      UINT32      Value
  );

/**
  Scans a target buffer for a 64-bit value, and returns a pointer to the
  matching 64-bit value in the target buffer.

  @param  Buffer  The pointer to the target buffer to scan.
  @param  Length  The count of 64-bit value to scan. Must be non-zero.
  @param  Value   The value to search for in the target buffer.

  @return The pointer to the first occurrence, or NULL if not found.

**/
CONST VOID *
EFIAPI
InternalMemScanMem64 (
  IN      CONST VOID  *Buffer,
  IN      UINTN       Length,
  IN      UINT64      Value
  );

/**
  Checks whether the contents of a buffer are all zeros.

  @param  Buffer  The pointer to the buffer to be checked.
  @param  Length  The size of the buffer (in bytes) to be checked.

  @retval TRUE    Contents of the buffer are all zeros.
  @retval FALSE   Contents of the buffer are not all zeros.

**/
BOOLEAN
EFIAPI
InternalMemIsZeroBuffer (
  IN CONST VOID  *Buffer,
  IN UINTN       Length
  );

#endif
