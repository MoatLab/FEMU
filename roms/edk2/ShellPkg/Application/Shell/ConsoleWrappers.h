/** @file
  Function definitions for shell simple text in and out on top of file handles.

  (C) Copyright 2013 Hewlett-Packard Development Company, L.P.<BR>
  Copyright (c) 2010 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _SHELL_CONSOLE_WRAPPERS_HEADER_
#define _SHELL_CONSOLE_WRAPPERS_HEADER_

/**
  Function to create a EFI_SIMPLE_TEXT_INPUT_PROTOCOL on top of a
  SHELL_FILE_HANDLE to support redirecting input from a file.

  @param[in]  FileHandleToUse The pointer to the SHELL_FILE_HANDLE to use.
  @param[in]  HandleLocation  The pointer of a location to copy handle with protocol to.

  @retval NULL                There was insufficient memory available.
  @return                     A pointer to the allocated protocol structure;
**/
EFI_SIMPLE_TEXT_INPUT_PROTOCOL *
CreateSimpleTextInOnFile (
  IN SHELL_FILE_HANDLE  FileHandleToUse,
  IN EFI_HANDLE         *HandleLocation
  );

/**
  Function to close a EFI_SIMPLE_TEXT_INPUT_PROTOCOL on top of a
  SHELL_FILE_HANDLE to support redirecting input from a file.

  @param[in]  SimpleTextIn    The pointer to the SimpleTextIn to close.

  @retval EFI_SUCCESS         The object was closed.
**/
EFI_STATUS
CloseSimpleTextInOnFile (
  IN EFI_SIMPLE_TEXT_INPUT_PROTOCOL  *SimpleTextIn
  );

/**
  Function to create a EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL on top of a
  SHELL_FILE_HANDLE to support redirecting output from a file.

  @param[in]  FileHandleToUse  The pointer to the SHELL_FILE_HANDLE to use.
  @param[in]  HandleLocation   The pointer of a location to copy handle with protocol to.
  @param[in]  OriginalProtocol The pointer to the original output protocol for pass thru of functions.

  @retval NULL                There was insufficient memory available.
  @return                     A pointer to the allocated protocol structure;
**/
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *
CreateSimpleTextOutOnFile (
  IN SHELL_FILE_HANDLE                FileHandleToUse,
  IN EFI_HANDLE                       *HandleLocation,
  IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *OriginalProtocol
  );

/**
  Function to close a EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL on top of a
  SHELL_FILE_HANDLE to support redirecting output from a file.

  @param[in] SimpleTextOut    The pointer to the SimpleTextOUT to close.

  @retval EFI_SUCCESS         The object was closed.
**/
EFI_STATUS
CloseSimpleTextOutOnFile (
  IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *SimpleTextOut
  );

#endif //_SHELL_CONSOLE_WRAPPERS_HEADER_
