/** @file
  Declaration of the boot file download function.

Copyright (c) 2015 - 2021, Intel Corporation. All rights reserved.<BR>
(C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __EFI_HTTP_BOOT_HTTP_H__
#define __EFI_HTTP_BOOT_HTTP_H__

#define HTTP_BOOT_BLOCK_SIZE                   1500
#define HTTP_USER_AGENT_EFI_HTTP_BOOT          "UefiHttpBoot/1.0"
#define HTTP_BOOT_AUTHENTICATION_INFO_MAX_LEN  255

//
// Record the data length and start address of a data block.
//
typedef struct {
  LIST_ENTRY    Link;                     // Link to the EntityDataList in HTTP_BOOT_CACHE_CONTENT
  UINT8         *Block;                   // If NULL, the data is in previous data block.
  UINT8         *DataStart;               // Point to somewhere in the Block
  UINTN         DataLength;
} HTTP_BOOT_ENTITY_DATA;

//
// Structure for a cache item
//
typedef struct {
  LIST_ENTRY               Link;              // Link to the CacheList in driver's private data.
  EFI_HTTP_REQUEST_DATA    *RequestData;
  HTTP_IO_RESPONSE_DATA    *ResponseData;     // Not include any message-body data.
  HTTP_BOOT_IMAGE_TYPE     ImageType;
  UINTN                    EntityLength;
  LIST_ENTRY               EntityDataList;    // Entity data (message-body)
} HTTP_BOOT_CACHE_CONTENT;

//
// Callback data for HTTP_BODY_PARSER_CALLBACK()
//
typedef struct {
  EFI_STATUS                 Status;
  //
  // Cache info.
  //
  HTTP_BOOT_CACHE_CONTENT    *Cache;
  BOOLEAN                    NewBlock;
  UINT8                      *Block;

  //
  // Caller provided buffer to load the file in.
  //
  UINTN                      CopyedSize;
  UINTN                      BufferSize;
  UINT8                      *Buffer;

  HTTP_BOOT_PRIVATE_DATA     *Private;
} HTTP_BOOT_CALLBACK_DATA;

/**
  Discover all the boot information for boot file.

  @param[in, out]    Private        The pointer to the driver's private data.

  @retval EFI_SUCCESS          Successfully obtained all the boot information .
  @retval Others               Failed to retrieve the boot information.

**/
EFI_STATUS
HttpBootDiscoverBootInfo (
  IN OUT HTTP_BOOT_PRIVATE_DATA  *Private
  );

/**
  Create a HttpIo instance for the file download.

  @param[in]    Private        The pointer to the driver's private data.

  @retval EFI_SUCCESS          Successfully created.
  @retval Others               Failed to create HttpIo.

**/
EFI_STATUS
HttpBootCreateHttpIo (
  IN     HTTP_BOOT_PRIVATE_DATA  *Private
  );

/**
  This function download the boot file by using UEFI HTTP protocol.

  @param[in]       Private         The pointer to the driver's private data.
  @param[in]       HeaderOnly      Only request the response header, it could save a lot of time if
                                   the caller only want to know the size of the requested file.
  @param[in, out]  BufferSize      On input the size of Buffer in bytes. On output with a return
                                   code of EFI_SUCCESS, the amount of data transferred to
                                   Buffer. On output with a return code of EFI_BUFFER_TOO_SMALL,
                                   the size of Buffer required to retrieve the requested file.
  @param[out]      Buffer          The memory buffer to transfer the file to. IF Buffer is NULL,
                                   then the size of the requested file is returned in
                                   BufferSize.
  @param[out]      ImageType       The image type of the downloaded file.

  @retval EFI_SUCCESS              The file was loaded.
  @retval EFI_INVALID_PARAMETER    BufferSize is NULL or Buffer Size is not NULL but Buffer is NULL.
  @retval EFI_OUT_OF_RESOURCES     Could not allocate needed resources
  @retval EFI_BUFFER_TOO_SMALL     The BufferSize is too small to read the current directory entry.
                                   BufferSize has been updated with the size needed to complete
                                   the request.
  @retval EFI_ACCESS_DENIED        The server needs to authenticate the client.
  @retval Others                   Unexpected error happened.

**/
EFI_STATUS
HttpBootGetBootFile (
  IN     HTTP_BOOT_PRIVATE_DATA  *Private,
  IN     BOOLEAN                 HeaderOnly,
  IN OUT UINTN                   *BufferSize,
  OUT UINT8                      *Buffer,
  OUT HTTP_BOOT_IMAGE_TYPE       *ImageType
  );

/**
  Clean up all cached data.

  @param[in]          Private         The pointer to the driver's private data.

**/
VOID
HttpBootFreeCacheList (
  IN     HTTP_BOOT_PRIVATE_DATA  *Private
  );

#endif
