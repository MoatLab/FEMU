/** @file
  This file defines the EDKII Redfish Platform Config Protocol private structure.

  (C) Copyright 2021-2022 Hewlett Packard Enterprise Development LP<BR>
  Copyright (c) 2022-2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef EDKII_REDFISH_PLATFORM_CONFIG_IMPL_H_
#define EDKII_REDFISH_PLATFORM_CONFIG_IMPL_H_

#include <Uefi.h>

//
// Libraries
//
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/HiiUtilityLib.h>
#include <Library/HiiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#define IS_EMPTY_STRING(a)  (a == NULL || a[0] == L'\0')
#define ENGLISH_LANGUAGE_CODE  "en-US"
#define X_UEFI_SCHEMA_PREFIX   "x-uefi-redfish-"

//
// Definition of REDFISH_PLATFORM_CONFIG_PRIVATE.
//
typedef struct {
  LIST_ENTRY        Link;
  EFI_HII_HANDLE    HiiHandle;
  BOOLEAN           IsDeleted;
} REDFISH_PLATFORM_CONFIG_PENDING_LIST;

#define REDFISH_PLATFORM_CONFIG_PENDING_LIST_FROM_LINK(a)  BASE_CR (a, REDFISH_PLATFORM_CONFIG_PENDING_LIST, Link)

typedef struct {
  UINTN    Count;                               // Number of schema in list
  CHAR8    **SchemaList;                        // Schema list
} REDFISH_PLATFORM_CONFIG_SCHEMA;

//
// Definition of REDFISH_PLATFORM_CONFIG_FORM_SET_PRIVATE
//
typedef struct {
  LIST_ENTRY                        Link;
  HII_FORMSET                       *HiiFormSet;     // Pointer to HII formset data.
  EFI_GUID                          Guid;            // Formset GUID.
  EFI_HII_HANDLE                    HiiHandle;       // Hii Handle of this formset.
  LIST_ENTRY                        HiiFormList;     // Form list that keep form data under this formset.
  CHAR16                            *DevicePathStr;  // Device path of this formset.
  REDFISH_PLATFORM_CONFIG_SCHEMA    SupportedSchema; // Schema that is supported in this formset.
} REDFISH_PLATFORM_CONFIG_FORM_SET_PRIVATE;

#define REDFISH_PLATFORM_CONFIG_FORMSET_FROM_LINK(a)  BASE_CR (a, REDFISH_PLATFORM_CONFIG_FORM_SET_PRIVATE, Link)

//
// Definition of REDFISH_PLATFORM_CONFIG_FORM_PRIVATE
//
typedef struct {
  LIST_ENTRY                                  Link;
  UINT16                                      Id;           // Form ID.
  EFI_STRING_ID                               Title;        // String token of form title.
  REDFISH_PLATFORM_CONFIG_FORM_SET_PRIVATE    *ParentFormset;
  HII_FORM                                    *HiiForm;      // Pointer to HII form data.
  LIST_ENTRY                                  StatementList; // Statement list that keep statement under this form.
  BOOLEAN                                     Suppressed;    // Form is suppressed
} REDFISH_PLATFORM_CONFIG_FORM_PRIVATE;

#define REDFISH_PLATFORM_CONFIG_FORM_FROM_LINK(a)  BASE_CR (a, REDFISH_PLATFORM_CONFIG_FORM_PRIVATE, Link)

//
// Definition of REDFISH_PLATFORM_CONFIG_STATEMENT_DATA
//
typedef struct {
  UINT64    NumMinimum;
  UINT64    NumMaximum;
  UINT64    NumStep;
  UINT8     StrMinSize;
  UINT8     StrMaxSize;
} REDFISH_PLATFORM_CONFIG_STATEMENT_DATA;

//
// Definition of REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE
//
typedef struct {
  LIST_ENTRY                                Link;
  REDFISH_PLATFORM_CONFIG_FORM_PRIVATE      *ParentForm;
  HII_STATEMENT                             *HiiStatement;  // Pointer to HII statement data.
  EFI_QUESTION_ID                           QuestionId;     // Question ID of this statement.
  EFI_STRING_ID                             Description;    // String token of this question.
  EFI_STRING_ID                             Help;           // String token of help message.
  EFI_STRING                                DesStringCache; // The string cache for search function.
  UINT8                                     Flags;          // The statement flag.
  REDFISH_PLATFORM_CONFIG_STATEMENT_DATA    StatementData;  // The max/min for statement value.
  BOOLEAN                                   Suppressed;     // Statement is suppressed.
  BOOLEAN                                   GrayedOut;      // Statement is GrayedOut.
} REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE;

#define REDFISH_PLATFORM_CONFIG_STATEMENT_FROM_LINK(a)  BASE_CR (a, REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE, Link)

//
// Definition of REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE_REF
//
typedef struct {
  LIST_ENTRY                                   Link;
  REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE    *Statement;
} REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE_REF;

#define REDFISH_PLATFORM_CONFIG_STATEMENT_REF_FROM_LINK(a)  BASE_CR (a, REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE_REF, Link)

//
// Definition of REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE_LIST
//
typedef struct {
  LIST_ENTRY    StatementList;      // List of REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE_REF
  UINTN         Count;
} REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE_LIST;

/**
  Release formset list and all the forms that belong to this formset.

  @param[in]      FormsetList   Pointer to formset list that needs to be
                                released.

  @retval         EFI_STATUS

**/
EFI_STATUS
ReleaseFormsetList (
  IN  LIST_ENTRY  *FormsetList
  );

/**
  Release formset list and all the forms that belong to this formset.

  @param[in]      FormsetList   Pointer to formset list that needs to be
                                released.

  @retval         EFI_STATUS

**/
EFI_STATUS
LoadFormsetList (
  IN   EFI_HII_HANDLE  *HiiHandle,
  OUT  LIST_ENTRY      *FormsetList
  );

/**
  When HII database is updated. Keep updated HII handle into pending list so
  we can process them later.

  @param[in]  HiiHandle   HII handle instance.
  @param[in]  PendingList Pending list to keep HII handle which is recently updated.

  @retval EFI_SUCCESS             HII handle is saved in pending list.
  @retval EFI_INVALID_PARAMETER   HiiHandle is NULL or PendingList is NULL.
  @retval EFI_OUT_OF_RESOURCES    System is out of memory.

**/
EFI_STATUS
NotifyFormsetUpdate (
  IN  EFI_HII_HANDLE  *HiiHandle,
  IN  LIST_ENTRY      *PendingList
  );

/**
  When HII database is updated and form-set is deleted. Keep deleted HII handle into pending list so
  we can process them later.

  @param[in]  HiiHandle   HII handle instance.
  @param[in]  PendingList Pending list to keep HII handle which is recently updated.

  @retval EFI_SUCCESS             HII handle is saved in pending list.
  @retval EFI_INVALID_PARAMETER   HiiHandle is NULL or PendingList is NULL.
  @retval EFI_OUT_OF_RESOURCES    System is out of memory.

**/
EFI_STATUS
NotifyFormsetDeleted (
  IN  EFI_HII_HANDLE  *HiiHandle,
  IN  LIST_ENTRY      *PendingList
  );

/**
  Get statement private instance by the given configure language.

  @param[in]  FormsetList                 Form-set list to search.
  @param[in]  Schema                      Schema to be matched.
  @param[in]  ConfigureLang               Configure language.

  @retval REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE *   Pointer to statement private instance.

**/
REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE *
GetStatementPrivateByConfigureLang (
  IN  LIST_ENTRY  *FormsetList,
  IN  CHAR8       *Schema,
  IN  EFI_STRING  ConfigureLang
  );

/**
  Search and find statement private instance by given regular expression pattern
  which describes the Configure Language.

  @param[in]  RegularExpressionProtocol   Regular express protocol.
  @param[in]  FormsetList                 Form-set list to search.
  @param[in]  Schema                      Schema to be matched.
  @param[in]  Pattern                     Regular expression pattern.
  @param[out] StatementList               Statement list that match above pattern.

  @retval EFI_SUCCESS             Statement list is returned.
  @retval EFI_INVALID_PARAMETER   Input parameter is NULL.
  @retval EFI_NOT_READY           Regular express protocol is NULL.
  @retval EFI_NOT_FOUND           No statement is found.
  @retval EFI_OUT_OF_RESOURCES    System is out of memory.

**/
EFI_STATUS
GetStatementPrivateByConfigureLangRegex (
  IN  EFI_REGULAR_EXPRESSION_PROTOCOL                 *RegularExpressionProtocol,
  IN  LIST_ENTRY                                      *FormsetList,
  IN  CHAR8                                           *Schema,
  IN  EFI_STRING                                      Pattern,
  OUT REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE_LIST  *StatementList
  );

/**
  There are HII database update and we need to process them accordingly so that we
  won't use stale data. This function will parse updated HII handle again in order
  to get updated data-set.

  @param[in]  FormsetList   List to keep HII form-set.
  @param[in]  PendingList   List to keep HII handle that is updated.

  @retval EFI_SUCCESS             HII handle is saved in pending list.
  @retval EFI_INVALID_PARAMETER   FormsetList is NULL or PendingList is NULL.

**/
EFI_STATUS
ProcessPendingList (
  IN  LIST_ENTRY  *FormsetList,
  IN  LIST_ENTRY  *PendingList
  );

/**
  Delete a string from HII Package List by given HiiHandle.

  @param[in]  StringId           Id of the string in HII database.
  @param[in]  HiiHandle          The HII package list handle.

  @retval EFI_SUCCESS            The string was deleted successfully.
  @retval EFI_INVALID_PARAMETER  StringId is zero.

**/
EFI_STATUS
HiiDeleteString (
  IN  EFI_STRING_ID   StringId,
  IN  EFI_HII_HANDLE  HiiHandle
  );

/**
  Retrieves a unicode string from a string package in a given language. The
  returned string is allocated using AllocatePool().  The caller is responsible
  for freeing the allocated buffer using FreePool().

  If HiiHandle is NULL, then ASSERT().
  If StringId is 0, then ASSET.

  @param[in]  HiiHandle         A handle that was previously registered in the HII Database.
  @param[in]  Language          The specified configure language to get string.
  @param[in]  StringId          The identifier of the string to retrieved from the string
                                package associated with HiiHandle.

  @retval NULL   The string specified by StringId is not present in the string package.
  @retval Other  The string was returned.

**/
EFI_STRING
HiiGetRedfishString (
  IN EFI_HII_HANDLE  HiiHandle,
  IN CHAR8           *Language,
  IN EFI_STRING_ID   StringId
  );

/**
  Retrieves a ASCII string from a string package in a given language. The
  returned string is allocated using AllocatePool().  The caller is responsible
  for freeing the allocated buffer using FreePool().

  If HiiHandle is NULL, then ASSERT().
  If StringId is 0, then ASSET.

  @param[in]  HiiHandle         A handle that was previously registered in the HII Database.
  @param[in]  Language          The specified configure language to get string.
  @param[in]  StringId          The identifier of the string to retrieved from the string
                                package associated with HiiHandle.

  @retval NULL   The string specified by StringId is not present in the string package.
  @retval Other  The string was returned.

**/
CHAR8 *
HiiGetRedfishAsciiString (
  IN EFI_HII_HANDLE  HiiHandle,
  IN CHAR8           *Language,
  IN EFI_STRING_ID   StringId
  );

/**
  Get ASCII string from HII database in English language. The returned string is allocated
  using AllocatePool(). The caller is responsible for freeing the allocated buffer using
  FreePool().

  @param[in]  HiiHandle         A handle that was previously registered in the HII Database.
  @param[in]  StringId          The identifier of the string to retrieved from the string
                                package associated with HiiHandle.

  @retval NULL   The string specified by StringId is not present in the string package.
  @retval Other  The string was returned.

**/
CHAR8 *
HiiGetEnglishAsciiString (
  IN EFI_HII_HANDLE  HiiHandle,
  IN EFI_STRING_ID   StringId
  );

/**
  Release all resource in statement list.

  @param[in]  StatementList   Statement list to be released.

  @retval EFI_SUCCESS             All resource are released.
  @retval EFI_INVALID_PARAMETER   StatementList is NULL.

**/
EFI_STATUS
ReleaseStatementList (
  IN  REDFISH_PLATFORM_CONFIG_STATEMENT_PRIVATE_LIST  *StatementList
  );

#endif
