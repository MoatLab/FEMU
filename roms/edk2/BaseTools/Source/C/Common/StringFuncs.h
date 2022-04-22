/** @file
String routines implementation

Copyright (c) 2007 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _EFI_STRING_FUNCS_H
#define _EFI_STRING_FUNCS_H

#include <stdio.h>
#include <stdlib.h>
#include <Common/UefiBaseTypes.h>

//
// Common data structures
//
typedef struct {
  UINTN      Count;
  //
  // Actually this array can be 0 or more items (based on Count)
  //
  CHAR8*     Strings[1];
} STRING_LIST;


//
// Functions declarations
//

CHAR8*
CloneString (
  IN CHAR8       *String
  )
;
/**

Routine Description:

  Allocates a new string and copies 'String' to clone it

Arguments:

  String          The string to clone

Returns:

  CHAR8* - NULL if there are not enough resources

**/


EFI_STATUS
StripInfDscStringInPlace (
  IN CHAR8       *String
  )
;
/**

Routine Description:

  Remove all comments, leading and trailing whitespace from the string.

Arguments:

  String          The string to 'strip'

Returns:

  EFI_STATUS

**/


STRING_LIST*
SplitStringByWhitespace (
  IN CHAR8       *String
  )
;
/**

Routine Description:

  Creates and returns a 'split' STRING_LIST by splitting the string
  on whitespace boundaries.

Arguments:

  String          The string to 'split'

Returns:

  EFI_STATUS

**/


STRING_LIST*
NewStringList (
  )
;
/**

Routine Description:

  Creates a new STRING_LIST with 0 strings.

Returns:

  STRING_LIST* - Null if there is not enough resources to create the object.

**/


EFI_STATUS
AppendCopyOfStringToList (
  IN OUT STRING_LIST **StringList,
  IN CHAR8       *String
  )
;
/**

Routine Description:

  Adds String to StringList.  A new copy of String is made before it is
  added to StringList.

Returns:

  EFI_STATUS

**/


EFI_STATUS
RemoveLastStringFromList (
  IN STRING_LIST       *StringList
  )
;
/**

Routine Description:

  Removes the last string from StringList and frees the memory associated
  with it.

Arguments:

  StringList        The string list to remove the string from

Returns:

  EFI_STATUS

**/


STRING_LIST*
AllocateStringListStruct (
  IN UINTN StringCount
  )
;
/**

Routine Description:

  Allocates a STRING_LIST structure that can store StringCount strings.

Arguments:

  StringCount        The number of strings that need to be stored

Returns:

  EFI_STATUS

**/


VOID
FreeStringList (
  IN STRING_LIST       *StringList
  )
;
/**

Routine Description:

  Frees all memory associated with StringList.

Arguments:

  StringList        The string list to free

Returns:

  EFI_STATUS

**/


CHAR8*
StringListToString (
  IN STRING_LIST       *StringList
  )
;
/**

Routine Description:

  Generates a string that represents the STRING_LIST

Arguments:

  StringList        The string list to convert to a string

Returns:

  CHAR8* - The string list represented with a single string.  The returned
           string must be freed by the caller.

**/


VOID
PrintStringList (
  IN STRING_LIST       *StringList
  )
;
/**

Routine Description:

  Prints out the string list

Arguments:

  StringList        The string list to print

**/


#endif
