/*++ @file

Copyright (c) 2006 - 2012, Intel Corporation. All rights reserved.<BR>
Portions copyright (c) 2008 - 2011, Apple Inc. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PiPei.h"
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/PeiServicesLib.h>
#include <IndustryStandard/PeImage.h>
#include <Library/DebugLib.h>

#include <Ppi/EmuThunk.h>
#include <Protocol/EmuThunk.h>

/**
  Retrieves and returns a pointer to the entry point to a PE/COFF image that has been loaded
  into system memory with the PE/COFF Loader Library functions.

  Retrieves the entry point to the PE/COFF image specified by Pe32Data and returns this entry
  point in EntryPoint.  If the entry point could not be retrieved from the PE/COFF image, then
  return RETURN_INVALID_PARAMETER.  Otherwise return RETURN_SUCCESS.
  If Pe32Data is NULL, then ASSERT().
  If EntryPoint is NULL, then ASSERT().

  @param  Pe32Data                  The pointer to the PE/COFF image that is loaded in system memory.
  @param  EntryPoint                The pointer to entry point to the PE/COFF image to return.

  @retval RETURN_SUCCESS            EntryPoint was returned.
  @retval RETURN_INVALID_PARAMETER  The entry point could not be found in the PE/COFF image.

**/
RETURN_STATUS
EFIAPI
PeCoffLoaderGetEntryPoint (
  IN     VOID  *Pe32Data,
  IN OUT VOID  **EntryPoint
  )
{
  EMU_THUNK_PPI       *ThunkPpi;
  EFI_STATUS          Status;
  EMU_THUNK_PROTOCOL  *Thunk;

  //
  // Locate EmuThunkPpi for retrieving standard output handle
  //
  Status = PeiServicesLocatePpi (
             &gEmuThunkPpiGuid,
             0,
             NULL,
             (VOID **)&ThunkPpi
             );
  ASSERT_EFI_ERROR (Status);

  Thunk = (EMU_THUNK_PROTOCOL *)ThunkPpi->Thunk ();

  return Thunk->PeCoffGetEntryPoint (Pe32Data, EntryPoint);
}

/**
  Returns the machine type of PE/COFF image.
  This is copied from MDE BasePeCoffGetEntryPointLib, the code should be sync with it.
  The reason is Emu package needs to load the image to memory to support source
  level debug.


  @param  Pe32Data   Pointer to a PE/COFF header

  @return            Machine type or zero if not a valid iamge

**/
UINT16
EFIAPI
PeCoffLoaderGetMachineType (
  IN  VOID  *Pe32Data
  )
{
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  EFI_IMAGE_DOS_HEADER                 *DosHdr;

  ASSERT (Pe32Data   != NULL);

  DosHdr = (EFI_IMAGE_DOS_HEADER  *)Pe32Data;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINTN)Pe32Data + (UINTN)((DosHdr->e_lfanew) & 0x0ffff));
  } else {
    Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)(Pe32Data);
  }

  if (Hdr.Te->Signature == EFI_TE_IMAGE_HEADER_SIGNATURE) {
    return Hdr.Te->Machine;
  } else if (Hdr.Pe32->Signature == EFI_IMAGE_NT_SIGNATURE) {
    return Hdr.Pe32->FileHeader.Machine;
  }

  return 0x0000;
}

/**
  Returns a pointer to the PDB file name for a PE/COFF image that has been
  loaded into system memory with the PE/COFF Loader Library functions.

  Returns the PDB file name for the PE/COFF image specified by Pe32Data.  If
  the PE/COFF image specified by Pe32Data is not a valid, then NULL is
  returned.  If the PE/COFF image specified by Pe32Data does not contain a
  debug directory entry, then NULL is returned.  If the debug directory entry
  in the PE/COFF image specified by Pe32Data does not contain a PDB file name,
  then NULL is returned.
  If Pe32Data is NULL, then ASSERT().

  @param  Pe32Data   Pointer to the PE/COFF image that is loaded in system
                     memory.

  @return The PDB file name for the PE/COFF image specified by Pe32Data or NULL
          if it cannot be retrieved.

**/
VOID *
EFIAPI
PeCoffLoaderGetPdbPointer (
  IN VOID  *Pe32Data
  )
{
  EFI_IMAGE_DOS_HEADER                 *DosHdr;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  EFI_IMAGE_DATA_DIRECTORY             *DirectoryEntry;
  EFI_IMAGE_DEBUG_DIRECTORY_ENTRY      *DebugEntry;
  UINTN                                DirCount;
  VOID                                 *CodeViewEntryPointer;
  INTN                                 TEImageAdjust;
  UINT32                               NumberOfRvaAndSizes;
  UINT16                               Magic;

  ASSERT (Pe32Data   != NULL);

  TEImageAdjust       = 0;
  DirectoryEntry      = NULL;
  DebugEntry          = NULL;
  NumberOfRvaAndSizes = 0;

  DosHdr = (EFI_IMAGE_DOS_HEADER *)Pe32Data;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    //
    // DOS image header is present, so read the PE header after the DOS image header.
    //
    Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINTN)Pe32Data + (UINTN)((DosHdr->e_lfanew) & 0x0ffff));
  } else {
    //
    // DOS image header is not present, so PE header is at the image base.
    //
    Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)Pe32Data;
  }

  if (Hdr.Te->Signature == EFI_TE_IMAGE_HEADER_SIGNATURE) {
    if (Hdr.Te->DataDirectory[EFI_TE_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress != 0) {
      DirectoryEntry = &Hdr.Te->DataDirectory[EFI_TE_IMAGE_DIRECTORY_ENTRY_DEBUG];
      TEImageAdjust  = sizeof (EFI_TE_IMAGE_HEADER) - Hdr.Te->StrippedSize;
      DebugEntry     = (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY *)((UINTN)Hdr.Te +
                                                           Hdr.Te->DataDirectory[EFI_TE_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress +
                                                           TEImageAdjust);
    }
  } else if (Hdr.Pe32->Signature == EFI_IMAGE_NT_SIGNATURE) {
    //
    // NOTE: We use Machine field to identify PE32/PE32+, instead of Magic.
    //       It is due to backward-compatibility, for some system might
    //       generate PE32+ image with PE32 Magic.
    //
    switch (Hdr.Pe32->FileHeader.Machine) {
      case EFI_IMAGE_MACHINE_IA32:
        //
        // Assume PE32 image with IA32 Machine field.
        //
        Magic = EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        break;
      case EFI_IMAGE_MACHINE_X64:
      case EFI_IMAGE_MACHINE_IA64:
        //
        // Assume PE32+ image with X64 or IA64 Machine field
        //
        Magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        break;
      default:
        //
        // For unknow Machine field, use Magic in optional Header
        //
        Magic = Hdr.Pe32->OptionalHeader.Magic;
    }

    if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset get Debug Directory Entry
      //
      NumberOfRvaAndSizes = Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes;
      DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&(Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG]);
      DebugEntry          = (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY *)((UINTN)Pe32Data + DirectoryEntry->VirtualAddress);
    } else if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      //
      // Use PE32+ offset get Debug Directory Entry
      //
      NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
      DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&(Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG]);
      DebugEntry          = (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY *)((UINTN)Pe32Data + DirectoryEntry->VirtualAddress);
    }

    if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_DEBUG) {
      DirectoryEntry = NULL;
      DebugEntry     = NULL;
    }
  } else {
    return NULL;
  }

  if ((DebugEntry == NULL) || (DirectoryEntry == NULL)) {
    return NULL;
  }

  for (DirCount = 0; DirCount < DirectoryEntry->Size; DirCount += sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY), DebugEntry++) {
    if (DebugEntry->Type == EFI_IMAGE_DEBUG_TYPE_CODEVIEW) {
      if (DebugEntry->SizeOfData > 0) {
        CodeViewEntryPointer = (VOID *)((UINTN)DebugEntry->RVA + ((UINTN)Pe32Data) + (UINTN)TEImageAdjust);
        switch (*(UINT32 *)CodeViewEntryPointer) {
          case CODEVIEW_SIGNATURE_NB10:
            return (VOID *)((CHAR8 *)CodeViewEntryPointer + sizeof (EFI_IMAGE_DEBUG_CODEVIEW_NB10_ENTRY));
          case CODEVIEW_SIGNATURE_RSDS:
            return (VOID *)((CHAR8 *)CodeViewEntryPointer + sizeof (EFI_IMAGE_DEBUG_CODEVIEW_RSDS_ENTRY));
          case CODEVIEW_SIGNATURE_MTOC:
            return (VOID *)((CHAR8 *)CodeViewEntryPointer + sizeof (EFI_IMAGE_DEBUG_CODEVIEW_MTOC_ENTRY));
          default:
            break;
        }
      }
    }
  }

  return NULL;
}

/**
  Returns the size of the PE/COFF headers

  Returns the size of the PE/COFF header specified by Pe32Data.
  If Pe32Data is NULL, then ASSERT().

  @param  Pe32Data   Pointer to the PE/COFF image that is loaded in system
                     memory.

  @return Size of PE/COFF header in bytes or zero if not a valid image.

**/
UINT32
EFIAPI
PeCoffGetSizeOfHeaders (
  IN VOID  *Pe32Data
  )
{
  EFI_IMAGE_DOS_HEADER                 *DosHdr;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  UINTN                                SizeOfHeaders;

  ASSERT (Pe32Data   != NULL);

  DosHdr = (EFI_IMAGE_DOS_HEADER *)Pe32Data;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    //
    // DOS image header is present, so read the PE header after the DOS image header.
    //
    Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINTN)Pe32Data + (UINTN)((DosHdr->e_lfanew) & 0x0ffff));
  } else {
    //
    // DOS image header is not present, so PE header is at the image base.
    //
    Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)Pe32Data;
  }

  if (Hdr.Te->Signature == EFI_TE_IMAGE_HEADER_SIGNATURE) {
    SizeOfHeaders = sizeof (EFI_TE_IMAGE_HEADER) + (UINTN)Hdr.Te->BaseOfCode - (UINTN)Hdr.Te->StrippedSize;
  } else if (Hdr.Pe32->Signature == EFI_IMAGE_NT_SIGNATURE) {
    SizeOfHeaders = Hdr.Pe32->OptionalHeader.SizeOfHeaders;
  } else {
    SizeOfHeaders = 0;
  }

  return (UINT32)SizeOfHeaders;
}
